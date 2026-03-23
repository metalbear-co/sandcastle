mod config;
mod handler;
mod secret_routes;
mod secrets;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Duration,
};

use anyhow::Result;
use axum::{
    Extension, Router, middleware,
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
use sandcastle_auth::provider::SharedAuthProvider;
use sandcastle_auth::providers::{
    github::GitHubAuthProvider, google::GoogleAuthProvider, local::LocalAuthProvider,
};
use sandcastle_auth::{AuthState, SharedAuthState, load_persisted_tokens};
use sandcastle_sandbox_providers::{
    Provider, daytona::DaytonaProvider, docker::DockerProvider, local::LocalProvider,
};

use handler::{SandboxRegistry, SandcastleHandler};
use secret_routes::BaseUrl;
use secrets::SecretStore;

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

    let no_auth = std::env::var("SANDCASTLE_NO_AUTH").is_ok();

    let stored_config = sandcastle_keychain::load_config();

    let auth_provider: SharedAuthProvider = if no_auth {
        Arc::new(LocalAuthProvider { password: None })
    } else {
        match std::env::var("AUTH_PROVIDER")
            .unwrap_or_else(|_| "local".to_string())
            .as_str()
        {
            "github" => {
                let client_id = std::env::var("GITHUB_OAUTH_CLIENT_ID").map_err(|_| {
                    anyhow::anyhow!("GITHUB_OAUTH_CLIENT_ID is required for AUTH_PROVIDER=github")
                })?;
                let client_secret = std::env::var("GITHUB_OAUTH_CLIENT_SECRET").map_err(|_| {
                    anyhow::anyhow!(
                        "GITHUB_OAUTH_CLIENT_SECRET is required for AUTH_PROVIDER=github"
                    )
                })?;
                info!("auth: using GitHub OAuth provider");
                Arc::new(GitHubAuthProvider {
                    client_id,
                    client_secret,
                })
            }
            "google" => {
                let client_id = std::env::var("GOOGLE_CLIENT_ID").map_err(|_| {
                    anyhow::anyhow!("GOOGLE_CLIENT_ID is required for AUTH_PROVIDER=google")
                })?;
                let client_secret = std::env::var("GOOGLE_CLIENT_SECRET").map_err(|_| {
                    anyhow::anyhow!("GOOGLE_CLIENT_SECRET is required for AUTH_PROVIDER=google")
                })?;
                info!("auth: using Google OAuth provider");
                Arc::new(GoogleAuthProvider {
                    client_id,
                    client_secret,
                })
            }
            _ => {
                // "local" or any unrecognised value
                let password =
                    sandcastle_auth::github_auth::load_sandcastle_password(&stored_config)?;
                if password.is_some() {
                    info!("auth: password required to approve OAuth flow");
                }
                Arc::new(LocalAuthProvider { password })
            }
        }
    };

    let auth_state: SharedAuthState = Arc::new(AuthState {
        pending_codes: RwLock::new(HashMap::new()),
        valid_tokens: RwLock::new(load_persisted_tokens(&stored_config)),
        pending_auth_requests: RwLock::new(HashMap::new()),
        base_url: base_url.clone(),
        no_auth,
        provider: auth_provider,
    });

    if no_auth {
        info!("auth: disabled (SANDCASTLE_NO_AUTH is set)");
    }

    if !no_auth {
        if let Ok(token) = std::env::var("MCP_TOKEN") {
            auth_state
                .valid_tokens
                .write()
                .unwrap()
                .insert(token, "client:mcp_token_user".to_string());
            info!("auth: using pre-shared token from MCP_TOKEN");
        } else {
            info!("auth: open {base_url}/authorize to approve MCP access");
        }
    }

    let mut enabled = config::load_provider_selection()?;
    if std::env::var("DAYTONA_API_KEY").is_ok() && !enabled.contains(&"daytona".to_string()) {
        enabled.push("daytona".to_string());
    }

    let mut providers: Vec<Arc<dyn Provider>> = Vec::new();

    if enabled.contains(&"local".to_string()) {
        let local = LocalProvider::new(Duration::from_secs(120 * 60));
        local.start_cleanup_task();
        providers.push(local);
        info!("local sandbox provider registered");
    }

    if enabled.contains(&"docker".to_string()) {
        match DockerProvider::new(Duration::from_secs(120 * 60)) {
            Ok(docker) => {
                docker.cleanup_stale_containers().await;
                docker.start_cleanup_task();
                providers.push(docker);
                info!("docker sandbox provider registered");
            }
            Err(e) => tracing::warn!("docker provider unavailable: {e}"),
        }
    }

    if enabled.contains(&"daytona".to_string()) {
        match sandcastle_sandbox_providers::daytona_auth::load_daytona_creds(&stored_config) {
            Ok(creds) => {
                match DaytonaProvider::new(
                    creds.api_key,
                    creds.base_url,
                    Duration::from_secs(120 * 60),
                ) {
                    Ok(daytona) => {
                        daytona.start_cleanup_task();
                        providers.push(daytona);
                        info!("daytona sandbox provider registered");
                    }
                    Err(e) => tracing::warn!("daytona provider unavailable: {e}"),
                }
            }
            Err(e) => tracing::warn!("daytona credentials unavailable: {e}"),
        }
    }

    let sandbox_registry = Arc::new(SandboxRegistry::default());
    let secret_store = SecretStore::new();

    let service = StreamableHttpService::new(
        {
            let secret_store = secret_store.clone();
            let base_url = base_url.clone();
            move || {
                Ok(SandcastleHandler::new(
                    sandbox_registry.clone(),
                    providers.clone(),
                    secret_store.clone(),
                    base_url.clone(),
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
        .layer(Extension(secret_store))
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
