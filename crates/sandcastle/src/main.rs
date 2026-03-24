mod config;
mod handler;
mod secret_routes;

use std::{sync::Arc, time::Duration};

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
use sandcastle_auth::providers::local::LocalAuthProvider;
use sandcastle_auth::{AuthState, SharedAuthState};
use sandcastle_auth_provider_github::GitHubAuthProvider;
use sandcastle_auth_provider_google::GoogleAuthProvider;
use sandcastle_sandbox_provider_daytona::{DaytonaProvider, load_daytona_creds};
use sandcastle_sandbox_provider_docker::DockerProvider;
use sandcastle_sandbox_provider_local::LocalProvider;
use sandcastle_sandbox_providers::Provider;
use sandcastle_secrets::SharedSecretBackend;
use sandcastle_secrets_gcp::GcpSecretManagerBackend;
use sandcastle_secrets_memory::MemorySecretBackend;
use sandcastle_store::SharedStateStore;
use sandcastle_store_memory::MemoryStore;
use sandcastle_store_postgres::{PostgresStore, start_cleanup_task};

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

    // ── Storage backend ───────────────────────────────────────────────────────

    let store: SharedStateStore = match std::env::var("STORAGE_BACKEND")
        .unwrap_or_default()
        .as_str()
    {
        "postgres" => {
            let url = std::env::var("DATABASE_URL").map_err(|_| {
                anyhow::anyhow!("DATABASE_URL is required for STORAGE_BACKEND=postgres")
            })?;
            info!("storage: using PostgreSQL backend");
            let pg = PostgresStore::new(&url).await?;
            start_cleanup_task(pg.pool.clone());
            Arc::new(pg)
        }
        _ => {
            info!("storage: using in-memory backend");
            MemoryStore::new(std::collections::HashMap::new())
        }
    };

    // ── Secret backend ────────────────────────────────────────────────────────

    let secret_backend: SharedSecretBackend =
        match std::env::var("SECRET_BACKEND").unwrap_or_default().as_str() {
            "gcp" => {
                let project_id = std::env::var("GCP_PROJECT_ID").map_err(|_| {
                    anyhow::anyhow!("GCP_PROJECT_ID is required for SECRET_BACKEND=gcp")
                })?;
                info!("secrets: using GCP Secret Manager backend (project={project_id})");
                Arc::new(GcpSecretManagerBackend::new(project_id, store.clone()))
            }
            _ => {
                info!("secrets: using in-memory backend");
                MemorySecretBackend::new()
            }
        };

    // ── Auth provider ─────────────────────────────────────────────────────────

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
                let password = sandcastle_auth::github_auth::load_sandcastle_password();
                if password.is_some() {
                    info!("auth: password required to approve OAuth flow");
                }
                Arc::new(LocalAuthProvider { password })
            }
        }
    };

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

    // ── Sandbox providers ─────────────────────────────────────────────────────

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
        match load_daytona_creds() {
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

    // ── MCP service ───────────────────────────────────────────────────────────

    let service = StreamableHttpService::new(
        {
            let secret_backend = secret_backend.clone();
            let store = store.clone();
            let base_url = base_url.clone();
            move || {
                Ok(SandcastleHandler::new(
                    store.clone(),
                    providers.clone(),
                    secret_backend.clone(),
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
        .layer(Extension(secret_backend))
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
