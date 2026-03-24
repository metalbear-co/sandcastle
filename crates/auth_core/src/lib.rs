use std::sync::Arc;

use async_trait::async_trait;

pub type SharedAuthProvider = Arc<dyn AuthProvider>;

#[async_trait]
pub trait AuthProvider: Send + Sync {
    fn name(&self) -> &'static str;

    /// Returns `Some(redirect_url)` to redirect the user to the IdP,
    /// or `None` if the provider handles auth locally (shows the approval form).
    fn redirect_url(&self, callback_url: &str, state: &str) -> Option<String>;

    /// Exchange an IdP callback code for a stable `owner_key` (e.g. `"github:12345"`).
    /// Only called for providers that return `Some` from `redirect_url`.
    async fn exchange_code(&self, code: &str, callback_url: &str) -> Result<String, String>;

    /// Validate a password submitted via the local approval form.
    /// Returns `true` when the password is correct, or when no password is configured.
    /// IdP providers should always return `true` (the method is not called for them).
    fn check_password(&self, provided: &str) -> bool;

    /// Returns `true` if the local approval form should show a password field.
    fn needs_password(&self) -> bool;
}
