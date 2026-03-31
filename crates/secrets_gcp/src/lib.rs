use std::time::SystemTime;

use async_trait::async_trait;
use sandcastle_secrets_core::SecretBackend;
use sandcastle_store_core::{SharedStateStore, types::now_secs};
use sandcastle_util::generate_token;

/// GCP Secret Manager backend. Pending upload tokens are persisted in the shared
/// StateStore. Secrets are stored in Google Secret Manager.
pub struct GcpSecretManagerBackend {
    project_id: String,
    store: SharedStateStore,
    http: reqwest::Client,
}

impl GcpSecretManagerBackend {
    pub fn new(project_id: String, store: SharedStateStore) -> Self {
        Self {
            project_id,
            store,
            http: reqwest::Client::new(),
        }
    }

    /// Sanitise an owner_key for use in a GCP secret name / label value.
    /// GCP names/labels allow `[a-z0-9_-]`; replace everything else with `-`.
    fn safe_owner(owner_key: &str) -> String {
        owner_key
            .to_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect()
    }

    fn secret_id(owner_key: &str, name: &str) -> String {
        format!("sc-{}-{}", Self::safe_owner(owner_key), name)
    }

    /// Get an access token from the GCP metadata server (works in Cloud Run).
    async fn access_token(&self) -> anyhow::Result<String> {
        let resp = self
            .http
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .send()
            .await?
            .error_for_status()?
            .json::<serde_json::Value>()
            .await?;
        resp["access_token"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow::anyhow!("missing access_token in metadata response"))
    }

    /// Create or update a secret and add a new version with the given payload.
    /// If `expire_time` is provided it is set as an RFC 3339 timestamp on the secret resource
    /// so that GCP auto-deletes it after expiry.
    async fn upsert_secret(
        &self,
        secret_id: &str,
        value: &str,
        expire_time: Option<SystemTime>,
    ) -> anyhow::Result<()> {
        let token = self.access_token().await?;
        let parent = format!("projects/{}", self.project_id);
        let base = "https://secretmanager.googleapis.com/v1";

        // Build the secret resource body.
        let mut create_body = serde_json::json!({
            "replication": { "automatic": {} },
            "labels": { "managed-by": "sandcastle" }
        });
        if let Some(exp) = expire_time {
            let formatted = humantime::format_rfc3339(exp).to_string();
            create_body["expireTime"] = serde_json::Value::String(formatted);
        }

        // Try to create the secret (idempotent if it already exists).
        let _create = self
            .http
            .post(format!("{base}/{parent}/secrets?secretId={secret_id}"))
            .bearer_auth(&token)
            .json(&create_body)
            .send()
            .await?;
        // 409 ALREADY_EXISTS is fine; we proceed to add a new version.

        // Add a new version.
        let encoded = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, value);
        let version_body = serde_json::json!({ "payload": { "data": encoded } });
        self.http
            .post(format!(
                "{base}/{parent}/secrets/{secret_id}:addSecretVersion"
            ))
            .bearer_auth(&token)
            .json(&version_body)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Access the latest version of a secret.
    async fn access_secret(&self, secret_id: &str) -> anyhow::Result<Option<String>> {
        let token = self.access_token().await?;
        let parent = format!("projects/{}", self.project_id);
        let base = "https://secretmanager.googleapis.com/v1";

        let resp = self
            .http
            .get(format!(
                "{base}/{parent}/secrets/{secret_id}/versions/latest:access"
            ))
            .bearer_auth(&token)
            .send()
            .await?;

        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let body = resp.error_for_status()?.json::<serde_json::Value>().await?;
        let encoded = body["payload"]["data"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("missing payload.data in secret version"))?;
        let bytes = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    /// List secret IDs for an owner using name prefix filtering.
    async fn list_owner_secrets(&self, owner_key: &str) -> anyhow::Result<Vec<String>> {
        let token = self.access_token().await?;
        let parent = format!("projects/{}", self.project_id);
        let base = "https://secretmanager.googleapis.com/v1";
        let prefix = format!("sc-{}-", Self::safe_owner(owner_key));
        let filter = format!("name:{prefix}");

        let resp = self
            .http
            .get(format!("{base}/{parent}/secrets"))
            .bearer_auth(&token)
            .query(&[("filter", &filter)])
            .send()
            .await?
            .error_for_status()?
            .json::<serde_json::Value>()
            .await?;

        let secrets = resp["secrets"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| s["name"].as_str())
                    .filter_map(|full_name| {
                        // full_name: "projects/.../secrets/sc-owner-secretname"
                        let short = full_name.rsplit('/').next()?;
                        short.strip_prefix(&prefix).map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(secrets)
    }
}

#[async_trait]
impl SecretBackend for GcpSecretManagerBackend {
    async fn create_upload_token(&self, owner_key: &str, name: &str) -> String {
        let token = generate_token();
        let expire_at = now_secs() + 3600;
        if let Err(e) = self
            .store
            .set_secret_upload_token(&token, owner_key, name, expire_at)
            .await
        {
            tracing::warn!("gcp: failed to store upload token: {e}");
        }
        token
    }

    async fn get_token_info(&self, token: &str) -> Option<(String, String)> {
        self.store
            .get_secret_upload_token(token)
            .await
            .unwrap_or(None)
    }

    async fn consume_token_and_store(&self, token: &str, value: &str) -> Result<String, String> {
        let (owner_key, name) = self
            .store
            .take_secret_upload_token(token)
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "Invalid or expired token".to_string())?;

        let secret_id = Self::secret_id(&owner_key, &name);
        self.upsert_secret(&secret_id, value, None)
            .await
            .map_err(|e: anyhow::Error| format!("Failed to store secret: {e}"))?;
        Ok(name)
    }

    async fn list_secrets(&self, owner_key: &str) -> Vec<String> {
        self.list_owner_secrets(owner_key)
            .await
            .unwrap_or_else(|e: anyhow::Error| {
                tracing::warn!("gcp: list_secrets failed: {e}");
                vec![]
            })
    }

    async fn get_secret(&self, owner_key: &str, name: &str) -> Option<String> {
        let secret_id = Self::secret_id(owner_key, name);
        self.access_secret(&secret_id)
            .await
            .unwrap_or_else(|e: anyhow::Error| {
                tracing::warn!("gcp: get_secret failed: {e}");
                None
            })
    }

    async fn store_secret_with_expiry(
        &self,
        owner_key: &str,
        name: &str,
        value: &str,
        expires_at: SystemTime,
    ) -> anyhow::Result<()> {
        let secret_id = Self::secret_id(owner_key, name);
        self.upsert_secret(&secret_id, value, Some(expires_at))
            .await
    }
}
