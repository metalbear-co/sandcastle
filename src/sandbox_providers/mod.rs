pub mod local;

use std::{path::Path, sync::Arc};

#[async_trait::async_trait]
pub trait Sandbox: Send + Sync {
    fn id(&self) -> &str;
    fn work_dir(&self) -> &Path;

    async fn read_file(&self, path: &str, offset: Option<u32>, limit: Option<u32>) -> String;
    async fn write_file(&self, path: &str, content: &str) -> String;
    async fn edit_file(&self, path: &str, old_string: &str, new_string: &str) -> String;
    async fn glob(&self, pattern: &str, base_path: Option<String>) -> String;
    async fn grep(&self, pattern: &str, path: Option<String>, include: Option<String>) -> String;
    async fn run_command(&self, command: &str, dir: Option<String>) -> String;
    async fn clone_repository(&self, repo: &str, url: &str) -> String;
    async fn git_commit_and_push(&self, repo: &str, branch: &str, commit_message: &str) -> String;
}

#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    async fn create(&self) -> Result<Arc<dyn Sandbox>, String>;
    async fn resume(&self, id: &str) -> Result<Arc<dyn Sandbox>, String>;
}
