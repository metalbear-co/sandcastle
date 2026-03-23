pub mod github_auth;
pub mod handlers;
pub mod middleware;
pub mod provider;
pub mod providers;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Instant,
};

use sandcastle_keychain::{StoredConfig, load_config, save_config};

use provider::SharedAuthProvider;

pub struct PendingCode {
    pub created_at: Instant,
    pub redirect_uri: Option<String>,
    pub client_id: String,
    pub owner_key: String,
}

pub struct PendingAuthRequest {
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub client_state: Option<String>,
    pub created_at: Instant,
}

pub struct AuthState {
    pub pending_codes: RwLock<HashMap<String, PendingCode>>,
    /// token → owner_key (e.g. "client:abc", "github:12345", "google:sub")
    pub valid_tokens: RwLock<HashMap<String, String>>,
    /// server-side state → pending IdP auth request
    pub pending_auth_requests: RwLock<HashMap<String, PendingAuthRequest>>,
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

/// Load any tokens persisted from a previous run.
pub fn load_persisted_tokens(config: &StoredConfig) -> HashMap<String, String> {
    config.valid_tokens.clone().unwrap_or_default()
}

/// Persist the current token map to the keychain (best-effort).
pub fn persist_tokens(tokens: &HashMap<String, String>) {
    let mut config = load_config();
    config.valid_tokens = Some(tokens.clone());
    if let Err(e) = save_config(&config) {
        tracing::warn!("keychain: could not persist tokens: {e}");
    }
}
