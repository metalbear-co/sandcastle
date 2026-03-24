pub mod github_auth;
pub mod handlers;
pub mod middleware;
pub mod provider;
pub mod providers;

use std::sync::Arc;

use sandcastle_store::SharedStateStore;

pub use provider::SharedAuthProvider;
pub use sandcastle_store::{PendingAuthRecord, PendingCodeRecord};

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
