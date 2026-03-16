mod auth;
mod handler;
mod sandbox_providers;

use std::{collections::HashMap, sync::{Arc, RwLock}};

use anyhow::Result;
use axum::{
    middleware,
    routing::{get, post},
    Extension, Router,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::info;

use auth::{AuthState, SharedAuthState};
use auth::handlers::{
    authorize_approve, authorize_page, oauth_authorization_server,
    oauth_protected_resource, register_client, token_endpoint,
};
use auth::middleware::require_auth;
use handler::SandcastleHandler;

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

    let base_url = std::env::var("BASE_URL")
        .unwrap_or_else(|_| format!("http://localhost:{port}"));

    let no_auth = std::env::var("SANDCASTLE_NO_AUTH").is_ok();
    let password = std::env::var("SANDCASTLE_PASSWORD").ok();

    let auth_state: SharedAuthState = Arc::new(AuthState {
        pending_codes: RwLock::new(HashMap::new()),
        valid_tokens: RwLock::new(HashMap::new()),
        base_url: base_url.clone(),
        no_auth,
        password,
    });

    if no_auth {
        info!("auth: disabled (SANDCASTLE_NO_AUTH is set)");
    } else if auth_state.password.is_some() {
        info!("auth: password required to approve OAuth flow");
    }

    if let Ok(token) = std::env::var("MCP_TOKEN") {
        auth_state
            .valid_tokens
            .write()
            .unwrap()
            .insert(token, "env".to_string());
        info!("auth: using pre-shared token from MCP_TOKEN");
    } else {
        info!("auth: open {base_url}/authorize to approve MCP access");
    }

    let service = StreamableHttpService::new(
        || Ok(SandcastleHandler::new()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    // route_layer applies middleware only to routes defined before it,
    // so /authorize, /token, and /.well-known/* remain unauthenticated.
    let app = Router::new()
        .route_service("/", service)
        .route_layer(middleware::from_fn(require_auth))
        .route("/.well-known/oauth-protected-resource", get(oauth_protected_resource))
        .route("/.well-known/oauth-authorization-server", get(oauth_authorization_server))
        .route("/authorize", get(authorize_page))
        .route("/authorize/approve", post(authorize_approve))
        .route("/token", post(token_endpoint))
        .route("/register", post(register_client))
        .layer(Extension(auth_state))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let addr = format!("0.0.0.0:{port}");
    info!("sandcastle listening on {addr}");
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
