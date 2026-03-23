use std::sync::Arc;

use async_trait::async_trait;

#[async_trait]
pub trait SecretBackend: Send + Sync {
    /// Create a one-time upload token for the given owner and secret name.
    async fn create_upload_token(&self, owner_key: &str, name: &str) -> String;
    /// Look up a pending token without consuming it (for rendering the upload page).
    async fn get_token_info(&self, token: &str) -> Option<(String, String)>;
    /// Validate the token, store the secret value, and consume the token.
    async fn consume_token_and_store(&self, token: &str, value: &str) -> Result<String, String>;
    /// List the names of all stored secrets for an owner (values are never returned).
    async fn list_secrets(&self, owner_key: &str) -> Vec<String>;
    /// Retrieve a stored secret value.
    async fn get_secret(&self, owner_key: &str, name: &str) -> Option<String>;
}

pub type SharedSecretBackend = Arc<dyn SecretBackend>;
