pub mod types;

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;

pub use types::{PendingAuthRecord, PendingCodeRecord, SandboxRecord, SandboxStatus};

pub type SharedStateStore = Arc<dyn StateStore>;

#[async_trait]
pub trait StateStore: Send + Sync {
    // ── Auth tokens (persistent) ─────────────────────────────────────────────

    async fn get_token(&self, token: &str) -> anyhow::Result<Option<String>>;
    async fn set_token(&self, token: &str, owner_key: &str) -> anyhow::Result<()>;
    async fn delete_token(&self, token: &str) -> anyhow::Result<()>;
    /// Returns all stored tokens. Used only for keychain persistence in memory mode.
    async fn all_tokens(&self) -> anyhow::Result<HashMap<String, String>>;

    // ── Pending OAuth codes (short-lived, TTL enforced on read) ──────────────

    async fn set_pending_code(&self, code: &str, data: &PendingCodeRecord) -> anyhow::Result<()>;
    /// Atomically removes and returns the code, or None if missing/expired.
    async fn take_pending_code(&self, code: &str) -> anyhow::Result<Option<PendingCodeRecord>>;

    // ── Pending IdP auth requests (short-lived, TTL enforced on read) ────────

    async fn set_pending_auth_request(
        &self,
        state: &str,
        data: &PendingAuthRecord,
    ) -> anyhow::Result<()>;
    /// Atomically removes and returns the request, or None if missing/expired.
    async fn take_pending_auth_request(
        &self,
        state: &str,
    ) -> anyhow::Result<Option<PendingAuthRecord>>;

    // ── Sandbox registry ─────────────────────────────────────────────────────

    async fn register_sandbox(&self, meta: &SandboxRecord) -> anyhow::Result<()>;
    async fn get_sandbox(&self, id: &str) -> anyhow::Result<Option<SandboxRecord>>;
    async fn remove_sandbox(&self, id: &str) -> anyhow::Result<()>;
    async fn set_sandbox_status(&self, id: &str, status: SandboxStatus) -> anyhow::Result<()>;
    async fn set_active_sandbox(&self, owner_key: &str, sandbox_id: &str) -> anyhow::Result<()>;
    async fn get_active_sandbox(&self, owner_key: &str) -> anyhow::Result<Option<String>>;
    async fn list_sandboxes(&self, owner_key: &str) -> anyhow::Result<Vec<SandboxRecord>>;
    /// Returns true if the sandbox exists and is owned by owner_key.
    async fn sandbox_owned_by(&self, sandbox_id: &str, owner_key: &str) -> anyhow::Result<bool>;

    // ── Secret upload tokens (short-lived, used by GCP Secret Manager backend) ─

    /// Store a one-time upload token that maps to (owner_key, secret_name).
    async fn set_secret_upload_token(
        &self,
        token: &str,
        owner_key: &str,
        name: &str,
        expire_at: i64,
    ) -> anyhow::Result<()>;
    /// Atomically removes and returns (owner_key, name), or None if missing/expired.
    async fn take_secret_upload_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<(String, String)>>;
    /// Look up (owner_key, name) without consuming. Returns None if missing/expired.
    async fn get_secret_upload_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<(String, String)>>;
}
