use std::path::PathBuf;

use crate::auth::generate_token;

use super::{Provider, Sandbox};

pub struct LocalProvider;

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
        Ok(Sandbox { provider: self.name().to_string(), work_dir })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_and_description() {
        let p = LocalProvider;
        assert_eq!(p.name(), "local");
        assert!(!p.description().is_empty());
    }

    #[tokio::test]
    async fn create_makes_directory() {
        let sandbox = LocalProvider.create().await.expect("create failed");
        assert!(sandbox.work_dir.exists());
        assert!(sandbox.work_dir.is_dir());
        // cleanup
        let _ = tokio::fs::remove_dir(&sandbox.work_dir).await;
    }

    #[tokio::test]
    async fn create_returns_unique_dirs() {
        let a = LocalProvider.create().await.unwrap();
        let b = LocalProvider.create().await.unwrap();
        assert_ne!(a.work_dir, b.work_dir);
        let _ = tokio::fs::remove_dir(&a.work_dir).await;
        let _ = tokio::fs::remove_dir(&b.work_dir).await;
    }
}
