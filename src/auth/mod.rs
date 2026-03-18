pub mod handlers;
pub mod middleware;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Instant,
};

use crate::keychain::{StoredConfig, load_config, save_config};

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

pub fn generate_token() -> String {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("cannot open /dev/urandom");
    let mut buf = [0u8; 32];
    f.read_exact(&mut buf).expect("cannot read /dev/urandom");
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_token_is_64_hex_chars() {
        let t = generate_token();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn generate_token_is_unique() {
        assert_ne!(generate_token(), generate_token());
    }
}
