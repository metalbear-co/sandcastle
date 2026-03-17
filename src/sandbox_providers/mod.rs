pub mod local;

use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct Sandbox {
    pub id: String,
    #[allow(dead_code)] // reserved for future provider-specific logic
    pub provider: String,
    pub work_dir: PathBuf,
}

#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    async fn create(&self) -> Result<Sandbox, String>;
    async fn resume(&self, id: &str) -> Result<Sandbox, String>;
}

