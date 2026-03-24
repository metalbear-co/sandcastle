pub use sandcastle_secrets_core::*;

use anyhow::Result;
use sandcastle_secrets_gcp::GcpSecretManagerBackend;
use sandcastle_secrets_memory::MemorySecretBackend;
use sandcastle_store_core::SharedStateStore;
use tracing::info;

pub async fn load(store: SharedStateStore) -> Result<SharedSecretBackend> {
    match std::env::var("SECRET_BACKEND").unwrap_or_default().as_str() {
        "gcp" => {
            let project_id = std::env::var("GCP_PROJECT_ID").map_err(|_| {
                anyhow::anyhow!("GCP_PROJECT_ID is required for SECRET_BACKEND=gcp")
            })?;
            info!("secrets: using GCP Secret Manager backend (project={project_id})");
            Ok(std::sync::Arc::new(GcpSecretManagerBackend::new(
                project_id, store,
            )))
        }
        _ => {
            info!("secrets: using in-memory backend");
            Ok(MemorySecretBackend::new())
        }
    }
}
