pub mod local;

use std::path::PathBuf;

#[derive(Clone)]
pub struct Sandbox {
    pub provider: String,
    pub work_dir: PathBuf,
}

#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    async fn create(&self) -> Result<Sandbox, String>;
}

pub const ROOT_TOOLS: &[&str] = &["list_providers", "list_repositories", "create_sandbox"];
