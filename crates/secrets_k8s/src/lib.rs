use async_trait::async_trait;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    Api, Client,
    api::{ObjectMeta, Patch, PatchParams},
};
use sandcastle_secrets_core::SecretBackend;
use sandcastle_store_core::{SharedStateStore, types::now_secs};
use sandcastle_util::generate_token;
use std::collections::BTreeMap;

/// Kubernetes Secrets backend. Pending upload tokens are persisted in the
/// shared StateStore. Secrets are stored as Kubernetes Secret objects.
pub struct K8sSecretBackend {
    client: Client,
    namespace: String,
    store: SharedStateStore,
}

impl K8sSecretBackend {
    pub async fn new(namespace: String, store: SharedStateStore) -> anyhow::Result<Self> {
        let client = Client::try_default().await?;
        Ok(Self {
            client,
            namespace,
            store,
        })
    }

    /// Sanitise an owner_key for use as a Kubernetes resource name segment.
    /// K8s names must match `[a-z0-9-]`; replace everything else with `-`.
    fn safe_owner(owner_key: &str) -> String {
        owner_key
            .to_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else {
                    '-'
                }
            })
            .collect()
    }

    fn secret_name(owner_key: &str, name: &str) -> String {
        format!("sc-{}-{}", Self::safe_owner(owner_key), name)
    }

    fn api(&self) -> Api<Secret> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }
}

#[async_trait]
impl SecretBackend for K8sSecretBackend {
    async fn create_upload_token(&self, owner_key: &str, name: &str) -> String {
        let token = generate_token();
        let expire_at = now_secs() + 3600;
        if let Err(e) = self
            .store
            .set_secret_upload_token(&token, owner_key, name, expire_at)
            .await
        {
            tracing::warn!("k8s: failed to store upload token: {e}");
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

        let k8s_name = Self::secret_name(&owner_key, &name);
        let api = self.api();

        let mut labels = BTreeMap::new();
        labels.insert("managed-by".to_string(), "sandcastle".to_string());
        labels.insert("sc-owner".to_string(), Self::safe_owner(&owner_key));

        let mut data = BTreeMap::new();
        data.insert(
            "value".to_string(),
            k8s_openapi::ByteString(value.as_bytes().to_vec()),
        );

        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(k8s_name.clone()),
                namespace: Some(self.namespace.clone()),
                labels: Some(labels),
                ..Default::default()
            },
            data: Some(data),
            ..Default::default()
        };

        api.patch(
            &k8s_name,
            &PatchParams::apply("sandcastle").force(),
            &Patch::Apply(&secret),
        )
        .await
        .map_err(|e| format!("Failed to store secret: {e}"))?;

        Ok(name)
    }

    async fn list_secrets(&self, owner_key: &str) -> Vec<String> {
        let api = self.api();
        let label_selector = format!(
            "managed-by=sandcastle,sc-owner={}",
            Self::safe_owner(owner_key)
        );
        let lp = kube::api::ListParams::default().labels(&label_selector);
        match api.list(&lp).await {
            Ok(list) => {
                let prefix = format!("sc-{}-", Self::safe_owner(owner_key));
                list.items
                    .iter()
                    .filter_map(|s| s.metadata.name.as_deref())
                    .filter_map(|n| n.strip_prefix(&prefix))
                    .map(|s| s.to_string())
                    .collect()
            }
            Err(e) => {
                tracing::warn!("k8s: list_secrets failed: {e}");
                vec![]
            }
        }
    }

    async fn get_secret(&self, owner_key: &str, name: &str) -> Option<String> {
        let api = self.api();
        let k8s_name = Self::secret_name(owner_key, name);
        match api.get_opt(&k8s_name).await {
            Ok(Some(secret)) => secret
                .data
                .as_ref()
                .and_then(|d| d.get("value"))
                .map(|b| String::from_utf8_lossy(&b.0).into_owned()),
            Ok(None) => None,
            Err(e) => {
                tracing::warn!("k8s: get_secret failed: {e}");
                None
            }
        }
    }
}
