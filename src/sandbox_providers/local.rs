use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::RwLock;

use crate::auth::generate_token;

use super::{Provider, Sandbox};

struct SandboxRecord {
    work_dir: PathBuf,
    created_at: Instant,
}

pub struct LocalProvider {
    sandboxes: Arc<RwLock<HashMap<String, SandboxRecord>>>,
    ttl: Duration,
}

impl LocalProvider {
    pub fn new(ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            sandboxes: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        })
    }

    pub fn start_cleanup_task(self: &Arc<Self>) {
        let provider = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let expired: Vec<(String, PathBuf)> = {
                    let map = provider.sandboxes.read().await;
                    map.iter()
                        .filter(|(_, r)| r.created_at.elapsed() >= provider.ttl)
                        .map(|(id, r)| (id.clone(), r.work_dir.clone()))
                        .collect()
                };
                for (id, work_dir) in expired {
                    let _ = tokio::fs::remove_dir_all(&work_dir).await;
                    provider.sandboxes.write().await.remove(&id);
                    tracing::info!("sandbox {id} expired and removed");
                }
            }
        });
    }
}

#[async_trait::async_trait]
impl Provider for LocalProvider {
    fn name(&self) -> &'static str {
        "local"
    }

    fn description(&self) -> &'static str {
        "Local filesystem sandbox — files live on this server"
    }

    async fn create(&self) -> Result<Sandbox, String> {
        let id = generate_token()[..16].to_string();
        let work_dir = PathBuf::from(format!("/tmp/sandcastle/sessions/{id}"));
        tokio::fs::create_dir_all(&work_dir)
            .await
            .map_err(|e| format!("Failed to create sandbox: {e}"))?;
        self.sandboxes.write().await.insert(
            id.clone(),
            SandboxRecord { work_dir: work_dir.clone(), created_at: Instant::now() },
        );
        Ok(Sandbox { id, provider: self.name().to_string(), work_dir })
    }

    async fn resume(&self, id: &str) -> Result<Sandbox, String> {
        let map = self.sandboxes.read().await;
        match map.get(id) {
            None => Err(format!("Sandbox {id} not found")),
            Some(r) if r.created_at.elapsed() >= self.ttl => {
                Err(format!("Sandbox {id} has expired"))
            }
            Some(r) => Ok(Sandbox {
                id: id.to_string(),
                provider: self.name().to_string(),
                work_dir: r.work_dir.clone(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_description() {
        let p = LocalProvider::new(Duration::from_secs(7200));
        assert_eq!(p.name(), "local");
        assert!(!p.description().is_empty());
    }

    #[tokio::test]
    async fn create_makes_directory() {
        let p = LocalProvider::new(Duration::from_secs(7200));
        let sandbox = p.create().await.expect("create failed");
        assert!(sandbox.work_dir.exists());
        assert!(sandbox.work_dir.is_dir());
        let _ = tokio::fs::remove_dir_all(&sandbox.work_dir).await;
    }

    #[tokio::test]
    async fn create_returns_unique_dirs() {
        let p = LocalProvider::new(Duration::from_secs(7200));
        let a = p.create().await.unwrap();
        let b = p.create().await.unwrap();
        assert_ne!(a.work_dir, b.work_dir);
        let _ = tokio::fs::remove_dir_all(&a.work_dir).await;
        let _ = tokio::fs::remove_dir_all(&b.work_dir).await;
    }

    #[tokio::test]
    async fn resume_happy_path() {
        let p = LocalProvider::new(Duration::from_secs(7200));
        let created = p.create().await.unwrap();
        let resumed = p.resume(&created.id).await.expect("resume failed");
        assert_eq!(resumed.id, created.id);
        assert_eq!(resumed.work_dir, created.work_dir);
        let _ = tokio::fs::remove_dir_all(&created.work_dir).await;
    }

    #[tokio::test]
    async fn resume_unknown_id() {
        let p = LocalProvider::new(Duration::from_secs(7200));
        let result = p.resume("nonexistent-id").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn resume_after_ttl_expiry() {
        let p = LocalProvider::new(Duration::from_millis(1));
        let created = p.create().await.unwrap();
        // wait for TTL to lapse
        tokio::time::sleep(Duration::from_millis(5)).await;
        let result = p.resume(&created.id).await;
        assert!(result.is_err(), "expected expired error, got {:?}", result);
        let _ = tokio::fs::remove_dir_all(&created.work_dir).await;
    }
}
