use std::collections::HashMap;

use async_trait::async_trait;
use sandcastle_store::{
    StateStore,
    types::{PendingAuthRecord, PendingCodeRecord, SandboxRecord, now_secs},
};
use sqlx::postgres::PgPoolOptions;

pub struct PostgresStore {
    pub pool: sqlx::PgPool,
}

impl PostgresStore {
    pub async fn new(database_url: &str) -> anyhow::Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(10)
            .connect(database_url)
            .await?;
        sqlx::migrate!("./migrations").run(&pool).await?;
        Ok(Self { pool })
    }
}

// ── Row types for sqlx ────────────────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct TokenRow {
    token: String,
    owner_key: String,
}

#[derive(sqlx::FromRow)]
struct PendingCodeRow {
    owner_key: String,
    client_id: String,
    redirect_uri: Option<String>,
    expire_at: i64,
}

#[derive(sqlx::FromRow)]
struct PendingAuthRow {
    client_id: String,
    redirect_uri: Option<String>,
    client_state: Option<String>,
    expire_at: i64,
}

#[derive(sqlx::FromRow)]
struct SandboxRow {
    id: String,
    owner_key: String,
    provider: String,
    work_dir: String,
    name: String,
    created_at: i64,
}

#[derive(sqlx::FromRow)]
struct ActiveRow {
    sandbox_id: String,
}

#[derive(sqlx::FromRow)]
struct OwnerRow {
    owner_key: String,
}

// ── Impl ─────────────────────────────────────────────────────────────────────

#[async_trait]
impl StateStore for PostgresStore {
    async fn get_token(&self, token: &str) -> anyhow::Result<Option<String>> {
        let row =
            sqlx::query_as::<_, TokenRow>("SELECT token, owner_key FROM tokens WHERE token = $1")
                .bind(token)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|r| r.owner_key))
    }

    async fn set_token(&self, token: &str, owner_key: &str) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO tokens (token, owner_key, created_at)
             VALUES ($1, $2, $3)
             ON CONFLICT (token) DO UPDATE SET owner_key = EXCLUDED.owner_key",
        )
        .bind(token)
        .bind(owner_key)
        .bind(now_secs())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn delete_token(&self, token: &str) -> anyhow::Result<()> {
        sqlx::query("DELETE FROM tokens WHERE token = $1")
            .bind(token)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn all_tokens(&self) -> anyhow::Result<HashMap<String, String>> {
        let rows = sqlx::query_as::<_, TokenRow>("SELECT token, owner_key FROM tokens")
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.into_iter().map(|r| (r.token, r.owner_key)).collect())
    }

    async fn set_pending_code(&self, code: &str, data: &PendingCodeRecord) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO pending_codes (code, owner_key, client_id, redirect_uri, expire_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (code) DO UPDATE
               SET owner_key = EXCLUDED.owner_key,
                   client_id = EXCLUDED.client_id,
                   redirect_uri = EXCLUDED.redirect_uri,
                   expire_at = EXCLUDED.expire_at",
        )
        .bind(code)
        .bind(&data.owner_key)
        .bind(&data.client_id)
        .bind(&data.redirect_uri)
        .bind(data.expire_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn take_pending_code(&self, code: &str) -> anyhow::Result<Option<PendingCodeRecord>> {
        let row = sqlx::query_as::<_, PendingCodeRow>(
            "DELETE FROM pending_codes
             WHERE code = $1 AND expire_at > $2
             RETURNING owner_key, client_id, redirect_uri, expire_at",
        )
        .bind(code)
        .bind(now_secs())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| PendingCodeRecord {
            expire_at: r.expire_at,
            redirect_uri: r.redirect_uri,
            client_id: r.client_id,
            owner_key: r.owner_key,
        }))
    }

    async fn set_pending_auth_request(
        &self,
        state: &str,
        data: &PendingAuthRecord,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO pending_auth (state, client_id, redirect_uri, client_state, expire_at)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (state) DO UPDATE
               SET client_id = EXCLUDED.client_id,
                   redirect_uri = EXCLUDED.redirect_uri,
                   client_state = EXCLUDED.client_state,
                   expire_at = EXCLUDED.expire_at",
        )
        .bind(state)
        .bind(&data.client_id)
        .bind(&data.redirect_uri)
        .bind(&data.client_state)
        .bind(data.expire_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn take_pending_auth_request(
        &self,
        state: &str,
    ) -> anyhow::Result<Option<PendingAuthRecord>> {
        let row = sqlx::query_as::<_, PendingAuthRow>(
            "DELETE FROM pending_auth
             WHERE state = $1 AND expire_at > $2
             RETURNING client_id, redirect_uri, client_state, expire_at",
        )
        .bind(state)
        .bind(now_secs())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| PendingAuthRecord {
            expire_at: r.expire_at,
            client_id: r.client_id,
            redirect_uri: r.redirect_uri,
            client_state: r.client_state,
        }))
    }

    async fn register_sandbox(&self, meta: &SandboxRecord) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO sandboxes (id, owner_key, provider, work_dir, name, created_at)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(&meta.id)
        .bind(&meta.owner_key)
        .bind(&meta.provider)
        .bind(&meta.work_dir)
        .bind(&meta.name)
        .bind(meta.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_sandbox(&self, id: &str) -> anyhow::Result<Option<SandboxRecord>> {
        let row = sqlx::query_as::<_, SandboxRow>(
            "SELECT id, owner_key, provider, work_dir, name, created_at
             FROM sandboxes WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| SandboxRecord {
            id: r.id,
            owner_key: r.owner_key,
            provider: r.provider,
            work_dir: r.work_dir,
            name: r.name,
            created_at: r.created_at,
        }))
    }

    async fn remove_sandbox(&self, id: &str) -> anyhow::Result<()> {
        // active_sandboxes has no FK cascade, clean up manually
        sqlx::query("DELETE FROM active_sandboxes WHERE sandbox_id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM sandboxes WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn set_active_sandbox(&self, owner_key: &str, sandbox_id: &str) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO active_sandboxes (owner_key, sandbox_id)
             VALUES ($1, $2)
             ON CONFLICT (owner_key) DO UPDATE SET sandbox_id = EXCLUDED.sandbox_id",
        )
        .bind(owner_key)
        .bind(sandbox_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn get_active_sandbox(&self, owner_key: &str) -> anyhow::Result<Option<String>> {
        let row = sqlx::query_as::<_, ActiveRow>(
            "SELECT sandbox_id FROM active_sandboxes WHERE owner_key = $1",
        )
        .bind(owner_key)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| r.sandbox_id))
    }

    async fn list_sandboxes(&self, owner_key: &str) -> anyhow::Result<Vec<SandboxRecord>> {
        let rows = sqlx::query_as::<_, SandboxRow>(
            "SELECT id, owner_key, provider, work_dir, name, created_at
             FROM sandboxes WHERE owner_key = $1",
        )
        .bind(owner_key)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| SandboxRecord {
                id: r.id,
                owner_key: r.owner_key,
                provider: r.provider,
                work_dir: r.work_dir,
                name: r.name,
                created_at: r.created_at,
            })
            .collect())
    }

    async fn sandbox_owned_by(&self, sandbox_id: &str, owner_key: &str) -> anyhow::Result<bool> {
        let row = sqlx::query_as::<_, OwnerRow>("SELECT owner_key FROM sandboxes WHERE id = $1")
            .bind(sandbox_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.is_some_and(|r| r.owner_key == owner_key))
    }

    async fn set_secret_upload_token(
        &self,
        token: &str,
        owner_key: &str,
        name: &str,
        expire_at: i64,
    ) -> anyhow::Result<()> {
        sqlx::query(
            "INSERT INTO secret_upload_tokens (token, owner_key, name, expire_at)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (token) DO UPDATE
               SET owner_key = EXCLUDED.owner_key,
                   name = EXCLUDED.name,
                   expire_at = EXCLUDED.expire_at",
        )
        .bind(token)
        .bind(owner_key)
        .bind(name)
        .bind(expire_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn take_secret_upload_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<(String, String)>> {
        #[derive(sqlx::FromRow)]
        struct UploadTokenRow {
            owner_key: String,
            name: String,
        }
        let row = sqlx::query_as::<_, UploadTokenRow>(
            "DELETE FROM secret_upload_tokens
             WHERE token = $1 AND expire_at > $2
             RETURNING owner_key, name",
        )
        .bind(token)
        .bind(now_secs())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| (r.owner_key, r.name)))
    }

    async fn get_secret_upload_token(
        &self,
        token: &str,
    ) -> anyhow::Result<Option<(String, String)>> {
        #[derive(sqlx::FromRow)]
        struct UploadTokenRow {
            owner_key: String,
            name: String,
        }
        let row = sqlx::query_as::<_, UploadTokenRow>(
            "SELECT owner_key, name FROM secret_upload_tokens
             WHERE token = $1 AND expire_at > $2",
        )
        .bind(token)
        .bind(now_secs())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|r| (r.owner_key, r.name)))
    }
}

/// Spawns a background task that purges expired transient rows every 5 minutes.
pub fn start_cleanup_task(pool: sqlx::PgPool) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            let now = now_secs();
            let _ = sqlx::query("DELETE FROM pending_codes WHERE expire_at <= $1")
                .bind(now)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM pending_auth WHERE expire_at <= $1")
                .bind(now)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM secret_upload_tokens WHERE expire_at <= $1")
                .bind(now)
                .execute(&pool)
                .await;
        }
    });
}
