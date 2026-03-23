use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use sandcastle_secrets::SecretBackend;
use sandcastle_util::generate_token;

#[derive(Default)]
pub struct MemorySecretBackend {
    // magic token -> (owner_key, secret_name)
    pending_tokens: RwLock<HashMap<String, (String, String)>>,
    // owner_key -> (name -> value)
    secrets: RwLock<HashMap<String, HashMap<String, String>>>,
}

impl MemorySecretBackend {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }
}

#[async_trait]
impl SecretBackend for MemorySecretBackend {
    async fn create_upload_token(&self, owner_key: &str, name: &str) -> String {
        let token = generate_token();
        self.pending_tokens
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(token.clone(), (owner_key.to_string(), name.to_string()));
        token
    }

    async fn get_token_info(&self, token: &str) -> Option<(String, String)> {
        self.pending_tokens
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(token)
            .cloned()
    }

    async fn consume_token_and_store(&self, token: &str, value: &str) -> Result<String, String> {
        let (owner_key, name) = self
            .pending_tokens
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(token)
            .ok_or_else(|| "Invalid or expired token".to_string())?;
        self.secrets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .entry(owner_key)
            .or_default()
            .insert(name.clone(), value.to_string());
        Ok(name)
    }

    async fn list_secrets(&self, owner_key: &str) -> Vec<String> {
        self.secrets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(owner_key)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default()
    }

    async fn get_secret(&self, owner_key: &str, name: &str) -> Option<String> {
        self.secrets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(owner_key)
            .and_then(|m| m.get(name))
            .cloned()
    }
}
