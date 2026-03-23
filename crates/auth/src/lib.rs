pub mod github_auth;
pub mod handlers;
pub mod middleware;
pub mod provider;
pub mod providers;

use std::sync::Arc;

use sandcastle_keychain::{StoredConfig, load_config, save_config};
use sandcastle_store::SharedStateStore;

pub use provider::SharedAuthProvider;
pub use sandcastle_store::{PendingAuthRecord, PendingCodeRecord};

pub struct AuthState {
    pub store: SharedStateStore,
    pub base_url: String,
    pub no_auth: bool,
    pub provider: SharedAuthProvider,
    /// When true, token mutations are persisted to the OS keychain (memory-mode only).
    pub persist_to_keychain: bool,
}

#[derive(Clone, Debug)]
pub struct RequestIdentity {
    pub owner_key: String,
    pub client_id: Option<String>,
    pub no_auth: bool,
}

pub type SharedAuthState = Arc<AuthState>;

impl AuthState {
    /// Called after a token is written. Persists to keychain when in memory mode.
    pub async fn on_tokens_changed(&self) {
        if !self.persist_to_keychain {
            return;
        }
        if let Ok(tokens) = self.store.all_tokens().await {
            persist_tokens(&tokens);
        }
    }
}

/// Load any tokens persisted from a previous run (used to seed MemoryStore).
pub fn load_persisted_tokens(config: &StoredConfig) -> std::collections::HashMap<String, String> {
    config.valid_tokens.clone().unwrap_or_default()
}

/// Persist the current token map to the keychain (best-effort).
pub fn persist_tokens(tokens: &std::collections::HashMap<String, String>) {
    let mut config = load_config();
    config.valid_tokens = Some(tokens.clone());
    if let Err(e) = save_config(&config) {
        tracing::warn!("keychain: could not persist tokens: {e}");
    }
}
