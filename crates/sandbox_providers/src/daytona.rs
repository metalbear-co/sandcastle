use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use daytona_client::{
    DaytonaClient, DaytonaConfig,
    models::{CreateSandboxParams, ExecuteRequest, SandboxState},
};
use tokio::sync::{RwLock, mpsc};
use uuid::Uuid;

use crate::{Provider, SandboxHandle, SandboxMessage};
use sandcastle_util::generate_token;

const WORK_DIR: &str = "/home/user";

// ── Daytona Sandbox ───────────────────────────────────────────────────────────

struct ExecResult {
    exit_code: i32,
    result: String,
}

impl ExecResult {
    fn to_command_output(&self) -> String {
        format!("exit_code: {}\n{}", self.exit_code, self.result)
    }
}

struct DaytonaSandbox {
    sandbox_id: Uuid,
    client: Arc<DaytonaClient>,
}

impl DaytonaSandbox {
    async fn exec(&self, command: &str, cwd: Option<&str>) -> Result<ExecResult, String> {
        let req = ExecuteRequest {
            command: command.to_string(),
            cwd: cwd.map(|s| s.to_string()),
            timeout: Some(30),
        };
        tracing::debug!(sandbox_id = %self.sandbox_id, cmd = command, cwd = ?cwd, "daytona exec");
        let result = self
            .client
            .process()
            .execute_with_options(&self.sandbox_id, req)
            .await
            .map(|r| ExecResult {
                exit_code: r.exit_code,
                result: r.result,
            })
            .map_err(|e| e.to_string());
        match &result {
            Ok(r) => {
                tracing::debug!(exit_code = r.exit_code, output = %r.result, "daytona exec result")
            }
            Err(e) => tracing::warn!(error = %e, "daytona exec failed"),
        }
        result
    }

    async fn read_file(&self, path: &str, offset: Option<u32>, limit: Option<u32>) -> String {
        match self
            .client
            .files()
            .download_text(&self.sandbox_id, path)
            .await
        {
            Err(e) => format!("Error reading {path}: {e}"),
            Ok(content) => {
                if offset.is_none() && limit.is_none() {
                    content
                } else {
                    let start = offset.unwrap_or(1) as usize;
                    let lines: Vec<&str> = content.lines().collect();
                    let from = start.saturating_sub(1);
                    let to = limit
                        .map(|n| (from + n as usize).min(lines.len()))
                        .unwrap_or(lines.len());
                    lines[from..to]
                        .iter()
                        .enumerate()
                        .map(|(i, line)| format!("{:6}\t{}", from + i + 1, line))
                        .collect::<Vec<_>>()
                        .join("\n")
                }
            }
        }
    }

    async fn write_file(&self, path: &str, content: &str) -> String {
        match self
            .client
            .files()
            .upload_text(&self.sandbox_id, path, content)
            .await
        {
            Ok(()) => format!("Written {} bytes to {path}", content.len()),
            Err(e) => format!("Error writing {path}: {e}"),
        }
    }

    async fn edit_file(&self, path: &str, old_string: &str, new_string: &str) -> String {
        let content = match self
            .client
            .files()
            .download_text(&self.sandbox_id, path)
            .await
        {
            Ok(c) => c,
            Err(e) => return format!("Error reading {path}: {e}"),
        };
        let count = content.matches(old_string).count();
        let new_content = match count {
            0 => return format!("Error: old_string not found in {path}"),
            1 => content.replacen(old_string, new_string, 1),
            n => {
                return format!(
                    "Error: old_string matches {n} times in {path} — make it more specific"
                );
            }
        };
        match self
            .client
            .files()
            .upload_text(&self.sandbox_id, path, &new_content)
            .await
        {
            Ok(()) => format!("Edited {path}: replaced 1 occurrence"),
            Err(e) => format!("Error writing {path}: {e}"),
        }
    }

    async fn glob(&self, pattern: &str, base_path: Option<String>) -> String {
        let base = base_path.as_deref().unwrap_or(WORK_DIR);
        let recursive = pattern.contains("**");
        let name = pattern.split('/').next_back().unwrap_or(pattern);
        let prefix = pattern
            .split("**/")
            .next()
            .unwrap_or("")
            .trim_end_matches('/');
        let search_base = if prefix.is_empty() {
            base.to_string()
        } else {
            format!("{base}/{prefix}")
        };
        let depth_flag = if recursive { "" } else { "-maxdepth 1 " };
        let cmd = format!(
            "find '{search_base}' {depth_flag}-name '{name}' -type f 2>/dev/null | sort | head -1000"
        );
        match self.exec(&cmd, None).await {
            Ok(r) => {
                let matches: Vec<&str> = r.result.lines().filter(|l| !l.is_empty()).collect();
                serde_json::to_string(&matches).unwrap_or_default()
            }
            Err(e) => format!("Error: {e}"),
        }
    }

    async fn grep(&self, pattern: &str, path: Option<String>, include: Option<String>) -> String {
        let search_path = path.as_deref().unwrap_or(WORK_DIR);
        let include_flag = include
            .as_deref()
            .map(|i| format!("--include='{i}' "))
            .unwrap_or_default();
        let cmd = format!(
            "grep -rn -E {include_flag}-- '{pattern}' '{search_path}' 2>/dev/null | head -101"
        );
        match self.exec(&cmd, None).await {
            Ok(r) => r.result,
            Err(e) => format!("Error: {e}"),
        }
    }

    async fn run_command(
        &self,
        command: &str,
        dir: Option<String>,
        env: std::collections::HashMap<String, String>,
    ) -> String {
        let full_command = if env.is_empty() {
            command.to_string()
        } else {
            let prefix: String = env
                .iter()
                .map(|(k, v)| format!("{}={} ", shell_escape(k), shell_escape(v)))
                .collect();
            format!("{prefix}{command}")
        };
        match self.exec(&full_command, dir.as_deref()).await {
            Ok(r) => r.to_command_output(),
            Err(e) => format!("Failed to run command: {e}"),
        }
    }

    pub async fn run(self, mut rx: mpsc::Receiver<SandboxMessage>) {
        while let Some(msg) = rx.recv().await {
            match msg {
                SandboxMessage::ReadFile {
                    path,
                    offset,
                    limit,
                    reply,
                } => {
                    let _ = reply.send(self.read_file(&path, offset, limit).await);
                }
                SandboxMessage::WriteFile {
                    path,
                    content,
                    reply,
                } => {
                    let _ = reply.send(self.write_file(&path, &content).await);
                }
                SandboxMessage::EditFile {
                    path,
                    old_string,
                    new_string,
                    reply,
                } => {
                    let _ = reply.send(self.edit_file(&path, &old_string, &new_string).await);
                }
                SandboxMessage::Glob {
                    pattern,
                    base_path,
                    reply,
                } => {
                    let _ = reply.send(self.glob(&pattern, base_path).await);
                }
                SandboxMessage::Grep {
                    pattern,
                    path,
                    include,
                    reply,
                } => {
                    let _ = reply.send(self.grep(&pattern, path, include).await);
                }
                SandboxMessage::RunCommand {
                    command,
                    dir,
                    env,
                    reply,
                } => {
                    let _ = reply.send(self.run_command(&command, dir, env).await);
                }
            }
        }
    }
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

// ── DaytonaProvider ───────────────────────────────────────────────────────────

struct DaytonaRecord {
    handle: SandboxHandle,
    sandbox_id: Uuid,
    created_at: Instant,
}

pub struct DaytonaProvider {
    client: Arc<DaytonaClient>,
    ttl: Duration,
    sandboxes: Arc<RwLock<HashMap<String, DaytonaRecord>>>,
}

impl DaytonaProvider {
    pub fn new(api_key: String, base_url: String, ttl: Duration) -> Result<Arc<Self>, String> {
        let config = DaytonaConfig::new(api_key).with_base_url(base_url);
        let client = DaytonaClient::new(config).map_err(|e| e.to_string())?;
        Ok(Arc::new(Self {
            client: Arc::new(client),
            ttl,
            sandboxes: Arc::new(RwLock::new(HashMap::new())),
        }))
    }

    pub fn start_cleanup_task(self: &Arc<Self>) {
        let provider = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let expired: Vec<(String, Uuid)> = {
                    let map = provider.sandboxes.read().await;
                    map.iter()
                        .filter(|(_, r)| r.created_at.elapsed() >= provider.ttl)
                        .map(|(id, r)| (id.clone(), r.sandbox_id))
                        .collect()
                };
                for (id, sandbox_id) in expired {
                    let _ = provider
                        .client
                        .sandboxes()
                        .delete_with_force(&sandbox_id, true)
                        .await;
                    provider.sandboxes.write().await.remove(&id);
                    tracing::info!("daytona sandbox {id} expired and removed");
                }
            }
        });
    }
}

#[async_trait::async_trait]
impl Provider for DaytonaProvider {
    fn name(&self) -> &'static str {
        "daytona"
    }

    fn description(&self) -> &'static str {
        "Daytona cloud sandbox — commands run in managed remote containers"
    }

    async fn create(&self, name: String) -> Result<SandboxHandle, String> {
        let sandbox = self
            .client
            .sandboxes()
            .create(CreateSandboxParams::default())
            .await
            .map_err(|e| e.to_string())?;

        self.client
            .sandboxes()
            .wait_for_state(&sandbox.id, SandboxState::Started, 120)
            .await
            .map_err(|e| e.to_string())?;

        let id = generate_token()[..16].to_string();
        let work_dir = PathBuf::from(WORK_DIR);

        let (tx, rx) = mpsc::channel(32);
        let handle = SandboxHandle::new(id.clone(), name, work_dir, tx);

        tokio::spawn(
            DaytonaSandbox {
                sandbox_id: sandbox.id,
                client: Arc::clone(&self.client),
            }
            .run(rx),
        );

        self.sandboxes.write().await.insert(
            id,
            DaytonaRecord {
                handle: handle.clone(),
                sandbox_id: sandbox.id,
                created_at: Instant::now(),
            },
        );

        Ok(handle)
    }

    async fn resume(&self, id: &str) -> Result<SandboxHandle, String> {
        let map = self.sandboxes.read().await;
        match map.get(id) {
            None => Err(format!("Sandbox {id} not found")),
            Some(r) if r.created_at.elapsed() >= self.ttl => {
                Err(format!("Sandbox {id} has expired"))
            }
            Some(r) => Ok(r.handle.clone()),
        }
    }
}
