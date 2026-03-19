pub mod github_auth;
pub mod handlers;
pub mod middleware;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Instant,
};

use sandcastle_keychain::{StoredConfig, load_config, save_config};

#[allow(dead_code)]
pub struct PendingCode {
    pub created_at: Instant,
    pub redirect_uri: Option<String>,
    pub client_id: String,
}

pub struct AuthState {
    pub pending_codes: RwLock<HashMap<String, PendingCode>>,
    pub valid_tokens: RwLock<HashMap<String, String>>, // token -> client_id
    pub base_url: String,
    pub no_auth: bool,
    pub password: Option<String>,
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
