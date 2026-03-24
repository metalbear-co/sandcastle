pub mod handlers;
pub mod middleware;
pub mod provider;
pub mod providers;

use std::sync::Arc;

use anyhow::Result;
use sandcastle_auth_provider_github::GitHubAuthProvider;
use sandcastle_auth_provider_google::GoogleAuthProvider;
use sandcastle_store::SharedStateStore;
use tracing::info;

pub use provider::SharedAuthProvider;
pub use sandcastle_store::{PendingAuthRecord, PendingCodeRecord};

pub fn load(no_auth: bool) -> Result<SharedAuthProvider> {
    use providers::local::LocalAuthProvider;
    if no_auth {
        return Ok(Arc::new(LocalAuthProvider { password: None }));
    }
    match std::env::var("AUTH_PROVIDER")
        .unwrap_or_else(|_| "local".to_string())
        .as_str()
    {
        "github" => {
            let client_id = std::env::var("GITHUB_OAUTH_CLIENT_ID").map_err(|_| {
                anyhow::anyhow!("GITHUB_OAUTH_CLIENT_ID is required for AUTH_PROVIDER=github")
            })?;
            let client_secret = std::env::var("GITHUB_OAUTH_CLIENT_SECRET").map_err(|_| {
                anyhow::anyhow!("GITHUB_OAUTH_CLIENT_SECRET is required for AUTH_PROVIDER=github")
            })?;
            info!("auth: using GitHub OAuth provider");
            Ok(Arc::new(GitHubAuthProvider {
                client_id,
                client_secret,
            }))
        }
        "google" => {
            let client_id = std::env::var("GOOGLE_CLIENT_ID").map_err(|_| {
                anyhow::anyhow!("GOOGLE_CLIENT_ID is required for AUTH_PROVIDER=google")
            })?;
            let client_secret = std::env::var("GOOGLE_CLIENT_SECRET").map_err(|_| {
                anyhow::anyhow!("GOOGLE_CLIENT_SECRET is required for AUTH_PROVIDER=google")
            })?;
            info!("auth: using Google OAuth provider");
            Ok(Arc::new(GoogleAuthProvider {
                client_id,
                client_secret,
            }))
        }
        _ => {
            let password = std::env::var("SANDCASTLE_PASSWORD").ok();
            if password.is_some() {
                info!("auth: password required to approve OAuth flow");
            }
            Ok(Arc::new(LocalAuthProvider { password }))
        }
    }
}

pub struct AuthState {
    pub store: SharedStateStore,
    pub base_url: String,
    pub no_auth: bool,
    pub provider: SharedAuthProvider,
}

#[derive(Clone, Debug)]
pub struct RequestIdentity {
    pub owner_key: String,
    pub client_id: Option<String>,
    pub no_auth: bool,
}

pub type SharedAuthState = Arc<AuthState>;
