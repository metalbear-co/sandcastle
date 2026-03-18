pub mod daytona;
pub mod docker;
pub mod local;

use std::path::PathBuf;

use tokio::sync::{mpsc, oneshot};

pub enum SandboxMessage {
    ReadFile {
        path: String,
        offset: Option<u32>,
        limit: Option<u32>,
        reply: oneshot::Sender<String>,
    },
    WriteFile {
        path: String,
        content: String,
        reply: oneshot::Sender<String>,
    },
    EditFile {
        path: String,
        old_string: String,
        new_string: String,
        reply: oneshot::Sender<String>,
    },
    Glob {
        pattern: String,
        base_path: Option<String>,
        reply: oneshot::Sender<String>,
    },
    Grep {
        pattern: String,
        path: Option<String>,
        include: Option<String>,
        reply: oneshot::Sender<String>,
    },
    RunCommand {
        command: String,
        dir: Option<String>,
        reply: oneshot::Sender<String>,
    },
    CloneRepository {
        repo: String,
        url: String,
        reply: oneshot::Sender<String>,
    },
    GitCommitAndPush {
        repo: String,
        branch: String,
        commit_message: String,
        reply: oneshot::Sender<String>,
    },
}

#[derive(Clone)]
pub struct SandboxHandle {
    pub id: String,
    pub name: String,
    pub work_dir: PathBuf,
    tx: mpsc::Sender<SandboxMessage>,
}

impl SandboxHandle {
    pub fn new(
        id: String,
        name: String,
        work_dir: PathBuf,
        tx: mpsc::Sender<SandboxMessage>,
    ) -> Self {
        Self {
            id,
            name,
            work_dir,
            tx,
        }
    }

    pub async fn read_file(&self, path: &str, offset: Option<u32>, limit: Option<u32>) -> String {
        let (reply, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(SandboxMessage::ReadFile {
                path: path.to_string(),
                offset,
                limit,
                reply,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| "Error: sandbox actor dropped reply".to_string())
    }

    pub async fn write_file(&self, path: &str, content: &str) -> String {
        let (reply, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(SandboxMessage::WriteFile {
                path: path.to_string(),
                content: content.to_string(),
                reply,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| "Error: sandbox actor dropped reply".to_string())
    }

    pub async fn edit_file(&self, path: &str, old_string: &str, new_string: &str) -> String {
        let (reply, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(SandboxMessage::EditFile {
                path: path.to_string(),
                old_string: old_string.to_string(),
                new_string: new_string.to_string(),
                reply,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| "Error: sandbox actor dropped reply".to_string())
    }

    pub async fn glob(&self, pattern: &str, base_path: Option<String>) -> String {
        let (reply, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(SandboxMessage::Glob {
                pattern: pattern.to_string(),
                base_path,
                reply,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| "Error: sandbox actor dropped reply".to_string())
    }

    pub async fn grep(
        &self,
        pattern: &str,
        path: Option<String>,
        include: Option<String>,
    ) -> String {
        let (reply, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(SandboxMessage::Grep {
                pattern: pattern.to_string(),
                path,
                include,
                reply,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| "Error: sandbox actor dropped reply".to_string())
    }

    pub async fn run_command(&self, command: &str, dir: Option<String>) -> String {
        let (reply, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(SandboxMessage::RunCommand {
                command: command.to_string(),
                dir,
                reply,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| "Error: sandbox actor dropped reply".to_string())
    }

    pub async fn clone_repository(&self, repo: &str, url: &str) -> String {
        let (reply, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(SandboxMessage::CloneRepository {
                repo: repo.to_string(),
                url: url.to_string(),
                reply,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| "Error: sandbox actor dropped reply".to_string())
    }

    pub async fn git_commit_and_push(
        &self,
        repo: &str,
        branch: &str,
        commit_message: &str,
    ) -> String {
        let (reply, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(SandboxMessage::GitCommitAndPush {
                repo: repo.to_string(),
                branch: branch.to_string(),
                commit_message: commit_message.to_string(),
                reply,
            })
            .await;
        rx.await
            .unwrap_or_else(|_| "Error: sandbox actor dropped reply".to_string())
    }
}

#[async_trait::async_trait]
pub trait Provider: Send + Sync {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    async fn create(&self, name: String) -> Result<SandboxHandle, String>;
    async fn resume(&self, id: &str) -> Result<SandboxHandle, String>;
}
