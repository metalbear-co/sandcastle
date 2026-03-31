mod config;
mod github_auth_routes;
mod handler;
mod rook_ws;
mod secret_routes;

use std::sync::Arc;

use anyhow::Result;
use axum::{
    Extension, Router,
    http::StatusCode,
    middleware,
    routing::{get, post},
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

use sandcastle_auth::handlers::{
    auth_callback, authorize_approve, authorize_page, oauth_authorization_server,
    oauth_protected_resource, register_client, token_endpoint,
};
use sandcastle_auth::middleware::require_auth;
use sandcastle_auth::{AuthState, SharedAuthState};

use sandcastle_github_token_provider::GitHubDeviceFlowProvider;

use github_auth_routes::GitHubAuthPendingStore;
use handler::SandcastleHandler;
use secret_routes::BaseUrl;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("sandcastle=info")),
        )
        .init();

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);

    let base_url = std::env::var("BASE_URL").unwrap_or_else(|_| format!("http://localhost:{port}"));

    let auth_configured = std::env::var("AUTH_PROVIDER").is_ok()
        || std::env::var("MCP_TOKEN").is_ok()
        || std::env::var("SANDCASTLE_PASSWORD").is_ok();
    let no_auth = std::env::var("SANDCASTLE_NO_AUTH").is_ok() || !auth_configured;

    let store = sandcastle_store::load().await?;
    let secret_backend = sandcastle_secrets::load(store.clone()).await?;
    let auth_provider = sandcastle_auth::load(no_auth)?;

    let auth_state: SharedAuthState = Arc::new(AuthState {
        store: store.clone(),
        base_url: base_url.clone(),
        no_auth,
        provider: auth_provider,
    });

    if no_auth {
        if !auth_configured {
            tracing::warn!(
                "running in dev mode: no authentication configured — \
                 all requests are allowed without credentials. \
                 Set AUTH_PROVIDER, MCP_TOKEN, or SANDCASTLE_PASSWORD for production use."
            );
        } else {
            info!("auth: disabled (SANDCASTLE_NO_AUTH is set)");
        }
    }

    if !no_auth {
        if let Ok(token) = std::env::var("MCP_TOKEN") {
            if let Err(e) = store.set_token(&token, "client:mcp_token_user").await {
                tracing::warn!("failed to register MCP_TOKEN: {e}");
            }
            info!("auth: using pre-shared token from MCP_TOKEN");
        } else {
            info!("auth: open {base_url}/authorize to approve MCP access");
        }
    }

    let mut enabled = match std::env::var("SANDCASTLE_PROVIDERS") {
        Ok(val) => val
            .split(',')
            .map(|s| s.trim().to_string())
            .collect::<Vec<_>>(),
        Err(_) => config::load_provider_selection()?,
    };
    if std::env::var("DAYTONA_API_KEY").is_ok() && !enabled.contains(&"daytona".to_string()) {
        enabled.push("daytona".to_string());
    }

    let providers = sandcastle_sandbox_providers::load(&enabled).await;

    let rook_registry = providers.iter().find_map(|p| p.rook_registry());

    let github_token_provider = match GitHubDeviceFlowProvider::from_env() {
        Ok(Some(p)) => {
            info!("github device flow token provider: configured");
            Some(std::sync::Arc::new(p))
        }
        Ok(None) => {
            tracing::debug!(
                "github device flow token provider: not configured (GITHUB_OAUTH_CLIENT_ID not set)"
            );
            None
        }
        Err(e) => {
            tracing::warn!("github device flow token provider: misconfigured, disabling: {e}");
            None
        }
    };

    // ── GitHub auth pending store (shared across all connections) ────────────

    let github_auth_pending: GitHubAuthPendingStore =
        std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new()));

    // ── MCP service ───────────────────────────────────────────────────────────

    let service = StreamableHttpService::new(
        {
            let secret_backend = secret_backend.clone();
            let store = store.clone();
            let base_url = base_url.clone();
            let github_token_provider = github_token_provider.clone();
            let github_auth_pending = github_auth_pending.clone();
            move || {
                Ok(SandcastleHandler::new(
                    store.clone(),
                    providers.clone(),
                    secret_backend.clone(),
                    base_url.clone(),
                    github_token_provider.clone(),
                    github_auth_pending.clone(),
                ))
            }
        },
        LocalSessionManager::default().into(),
        Default::default(),
    );

    // route_layer applies middleware only to routes defined before it,
    // so /authorize, /token, /.well-known/*, and /secrets/* remain unauthenticated.
    let app = Router::new()
        .route_service("/", service)
        .route_layer(middleware::from_fn(require_auth))
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_authorization_server),
        )
        .route("/authorize", get(authorize_page))
        .route("/authorize/approve", post(authorize_approve))
        .route("/auth/callback", get(auth_callback))
        .route("/token", post(token_endpoint))
        .route("/register", post(register_client))
        .route(
            "/secrets/{token}",
            get(secret_routes::get_secret_page).post(secret_routes::post_secret_value),
        )
        .route(
            "/github-auth/{token}",
            get(github_auth_routes::get_github_auth_page),
        )
        .route(
            "/github-auth/{token}/status",
            get(github_auth_routes::get_github_auth_status),
        )
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/rook/ws", get(rook_ws::rook_ws_handler))
        .layer(Extension(rook_registry))
        .layer(Extension(secret_backend))
        .layer(Extension(github_auth_pending))
        .layer(Extension(BaseUrl(base_url.clone())))
        .layer(Extension(auth_state))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr = format!("0.0.0.0:{port}");
    info!("sandcastle listening on {addr}");
    info!("MCP endpoint: {base_url}/");
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = axum::serve(listener, app) => {}
        _ = sigterm.recv() => { info!("received SIGTERM, shutting down"); }
        _ = tokio::signal::ctrl_c() => { info!("received SIGINT, shutting down"); }
    }

    Ok(())
}
