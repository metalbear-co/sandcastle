pub mod handlers;
pub mod middleware;

use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::Instant,
};

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

const KEYCHAIN_SERVICE: &str = "sandcastle";
const KEYCHAIN_TOKENS_KEY: &str = "valid_tokens";

/// Load any tokens persisted from a previous run.
pub fn load_persisted_tokens() -> HashMap<String, String> {
    let entry = match keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_TOKENS_KEY) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("keychain: could not create token entry: {e}");
            return HashMap::new();
        }
    };
    match entry.get_password() {
        Ok(json) => serde_json::from_str(&json).unwrap_or_else(|e| {
            tracing::warn!("keychain: token JSON corrupt, starting fresh: {e}");
            HashMap::new()
        }),
        Err(keyring::Error::NoEntry) => HashMap::new(),
        Err(e) => {
            tracing::warn!("keychain: could not load tokens: {e}");
            HashMap::new()
        }
    }
}

/// Persist the current token map to the keychain (best-effort).
pub fn persist_tokens(tokens: &HashMap<String, String>) {
    let json = match serde_json::to_string(tokens) {
        Ok(j) => j,
        Err(e) => {
            tracing::warn!("keychain: could not serialize tokens: {e}");
            return;
        }
    };
    match keyring::Entry::new(KEYCHAIN_SERVICE, KEYCHAIN_TOKENS_KEY)
        .map_err(|e| e.to_string())
        .and_then(|e| e.set_password(&json).map_err(|e| e.to_string()))
    {
        Ok(()) => {}
        Err(e) => tracing::warn!("keychain: could not persist tokens: {e}"),
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
