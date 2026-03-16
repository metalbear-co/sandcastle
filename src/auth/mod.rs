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
