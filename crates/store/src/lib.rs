pub use sandcastle_store_core::*;

use anyhow::Result;
use sandcastle_store_memory::MemoryStore;
use sandcastle_store_postgres::{PostgresStore, start_cleanup_task};
use tracing::info;

pub async fn load() -> Result<SharedStateStore> {
    match std::env::var("STORAGE_BACKEND")
        .unwrap_or_default()
        .as_str()
    {
        "postgres" => {
            let url = std::env::var("DATABASE_URL").map_err(|_| {
                anyhow::anyhow!("DATABASE_URL is required for STORAGE_BACKEND=postgres")
            })?;
            info!("storage: using PostgreSQL backend");
            let pg = PostgresStore::new(&url).await?;
            start_cleanup_task(pg.pool.clone());
            Ok(std::sync::Arc::new(pg))
        }
        _ => {
            info!("storage: using in-memory backend");
            Ok(MemoryStore::new(std::collections::HashMap::new()))
        }
    }
}
