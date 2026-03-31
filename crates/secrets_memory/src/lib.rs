use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
    time::SystemTime,
};

use async_trait::async_trait;
use sandcastle_secrets_core::SecretBackend;
use sandcastle_util::generate_token;

struct SecretEntry {
    value: String,
    expires_at: Option<SystemTime>,
}

impl SecretEntry {
    fn is_expired(&self) -> bool {
        self.expires_at
            .map(|t| SystemTime::now() >= t)
            .unwrap_or(false)
    }
}

#[derive(Default)]
pub struct MemorySecretBackend {
    pending_tokens: RwLock<HashMap<String, (String, String)>>,
    secrets: RwLock<HashMap<String, HashMap<String, SecretEntry>>>,
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
            .insert(
                name.clone(),
                SecretEntry {
                    value: value.to_string(),
                    expires_at: None,
                },
            );
        Ok(name)
    }

    async fn list_secrets(&self, owner_key: &str) -> Vec<String> {
        self.secrets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(owner_key)
            .map(|m| {
                m.iter()
                    .filter(|(_, e)| !e.is_expired())
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    async fn get_secret(&self, owner_key: &str, name: &str) -> Option<String> {
        self.secrets
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(owner_key)
            .and_then(|m| m.get(name))
            .and_then(|e| {
                if e.is_expired() {
                    None
                } else {
                    Some(e.value.clone())
                }
            })
    }

    async fn store_secret_with_expiry(
        &self,
        owner_key: &str,
        name: &str,
        value: &str,
        expires_at: SystemTime,
    ) -> anyhow::Result<()> {
        self.secrets
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .entry(owner_key.to_string())
            .or_default()
            .insert(
                name.to_string(),
                SecretEntry {
                    value: value.to_string(),
                    expires_at: Some(expires_at),
                },
            );
        Ok(())
    }
}
