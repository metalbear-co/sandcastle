use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use sandcastle_store::{
    SandboxStatus, StateStore,
    types::{PendingAuthRecord, PendingCodeRecord, SandboxRecord, now_secs},
};

#[derive(Default)]
pub struct MemoryStore {
    tokens: RwLock<HashMap<String, String>>,
    pending_codes: RwLock<HashMap<String, PendingCodeRecord>>,
    pending_auth: RwLock<HashMap<String, PendingAuthRecord>>,
    sandboxes: RwLock<HashMap<String, SandboxRecord>>,
    /// owner_key → sandbox_id
    active_sandboxes: RwLock<HashMap<String, String>>,
    /// sandbox_id → owner_key
    sandbox_owners: RwLock<HashMap<String, String>>,
    /// token → (owner_key, name, expire_at)
    secret_upload_tokens: RwLock<HashMap<String, (String, String, i64)>>,
}

impl MemoryStore {
    pub fn new(initial_tokens: HashMap<String, String>) -> Arc<Self> {
        Arc::new(Self {
            tokens: RwLock::new(initial_tokens),
            ..Default::default()
        })
    }
}

#[async_trait]
impl StateStore for MemoryStore {
    async fn get_token(&self, token: &str) -> anyhow::Result<Option<String>> {
        Ok(self.tokens.read().unwrap().get(token).cloned())
    }

    async fn set_token(&self, token: &str, owner_key: &str) -> anyhow::Result<()> {
        self.tokens
            .write()
            .unwrap()
            .insert(token.to_string(), owner_key.to_string());
        Ok(())
    }

    async fn delete_token(&self, token: &str) -> anyhow::Result<()> {
        self.tokens.write().unwrap().remove(token);
        Ok(())
    }

    async fn all_tokens(&self) -> anyhow::Result<HashMap<String, String>> {
        Ok(self.tokens.read().unwrap().clone())
    }

    async fn set_pending_code(&self, code: &str, data: &PendingCodeRecord) -> anyhow::Result<()> {
        self.pending_codes
            .write()
            .unwrap()
            .insert(code.to_string(), data.clone());
        Ok(())
    }

    async fn take_pending_code(&self, code: &str) -> anyhow::Result<Option<PendingCodeRecord>> {
        let record = self.pending_codes.write().unwrap().remove(code);
        Ok(record.filter(|r| r.expire_at > now_secs()))
    }

    async fn set_pending_auth_request(
        &self,
        state: &str,
        data: &PendingAuthRecord,
    ) -> anyhow::Result<()> {
        self.pending_auth
            .write()
            .unwrap()
            .insert(state.to_string(), data.clone());
        Ok(())
    }

    async fn take_pending_auth_request(
        &self,
        state: &str,
    ) -> anyhow::Result<Option<PendingAuthRecord>> {
        let record = self.pending_auth.write().unwrap().remove(state);
        Ok(record.filter(|r| r.expire_at > now_secs()))
    }

    async fn register_sandbox(&self, meta: &SandboxRecord) -> anyhow::Result<()> {
        self.sandbox_owners
            .write()
            .unwrap()
            .insert(meta.id.clone(), meta.owner_key.clone());
        self.sandboxes
            .write()
            .unwrap()
            .insert(meta.id.clone(), meta.clone());
        Ok(())
    }

    async fn get_sandbox(&self, id: &str) -> anyhow::Result<Option<SandboxRecord>> {
        Ok(self.sandboxes.read().unwrap().get(id).cloned())
    }

    async fn remove_sandbox(&self, id: &str) -> anyhow::Result<()> {
        self.sandbox_owners.write().unwrap().remove(id);
        self.sandboxes.write().unwrap().remove(id);
        self.active_sandboxes
            .write()
            .unwrap()
            .retain(|_, active_id| active_id != id);
        Ok(())
    }

    async fn set_sandbox_status(&self, id: &str, status: SandboxStatus) -> anyhow::Result<()> {
        if let Some(record) = self.sandboxes.write().unwrap().get_mut(id) {
            record.status = status;
        }
        Ok(())
    }

    async fn set_active_sandbox(&self, owner_key: &str, sandbox_id: &str) -> anyhow::Result<()> {
        self.active_sandboxes
            .write()
            .unwrap()
            .insert(owner_key.to_string(), sandbox_id.to_string());
        Ok(())
    }

    async fn get_active_sandbox(&self, owner_key: &str) -> anyhow::Result<Option<String>> {
        Ok(self
            .active_sandboxes
            .read()
            .unwrap()
            .get(owner_key)
            .cloned())
    }

    async fn list_sandboxes(&self, owner_key: &str) -> anyhow::Result<Vec<SandboxRecord>> {
        Ok(self
            .sandboxes
            .read()
            .unwrap()
            .values()
            .filter(|s| s.owner_key == owner_key)
            .cloned()
            .collect())
    }

    async fn sandbox_owned_by(&self, sandbox_id: &str, owner_key: &str) -> anyhow::Result<bool> {
        Ok(self
            .sandbox_owners
            .read()
            .unwrap()
            .get(sandbox_id)
            .is_some_and(|o| o == owner_key))
    }

    async fn set_secret_upload_token(
        &self,
        token: &str,
        owner_key: &str,
        name: &str,
        expire_at: i64,
    ) -> anyhow::Result<()> {
        self.secret_upload_tokens.write().unwrap().insert(
            token.to_string(),
            (owner_key.to_string(), name.to_string(), expire_at),
        );
        Ok(())
    }

    async fn take_secret_upload_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<(String, String)>> {
        let entry = self.secret_upload_tokens.write().unwrap().remove(token);
        Ok(entry.and_then(|(owner, name, expire_at)| {
            if expire_at > now_secs() {
                Some((owner, name))
            } else {
                None
            }
        }))
    }

    async fn get_secret_upload_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<(String, String)>> {
        let guard = self.secret_upload_tokens.read().unwrap();
        Ok(guard.get(token).and_then(|(owner, name, expire_at)| {
            if *expire_at > now_secs() {
                Some((owner.clone(), name.clone()))
            } else {
                None
            }
        }))
    }
}
