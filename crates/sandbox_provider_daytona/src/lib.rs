use std::{collections::HashMap, path::PathBuf, sync::Arc, time::Duration};

use sandcastle_daytona_sdk::{
    DaytonaClient, ExecuteRequest, SessionExecRequest, SessionExecResponse, SpawnPtyRequest,
};
use tokio::sync::{RwLock, mpsc, oneshot};
use uuid::Uuid;

use sandcastle_sandbox_providers_core::{Provider, SandboxHandle, SandboxMessage};
use sandcastle_util::generate_token;

const WORK_DIR: &str = "/home/user";
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(120);

// ── DaytonaSandbox ────────────────────────────────────────────────────────────

struct DaytonaSandbox {
    sandbox_id: Uuid,
    client: Arc<DaytonaClient>,
}

impl DaytonaSandbox {
    async fn exec(&self, command: &str, cwd: Option<&str>) -> Result<(i32, String), String> {
        tracing::debug!(sandbox_id = %self.sandbox_id, cmd = command, cwd = ?cwd, "daytona exec");
        let resp = self
            .client
            .execute(
                &self.sandbox_id,
                ExecuteRequest {
                    command: command.to_string(),
                    cwd: cwd.map(|s| s.to_string()),
                    timeout: Some(30),
                },
            )
            .await?;
        tracing::debug!(exit_code = resp.exit_code, output = %resp.result, "daytona exec result");
        Ok((resp.exit_code, resp.result))
    }

    async fn read_file(&self, path: &str, offset: Option<u32>, limit: Option<u32>) -> String {
        match self.client.download_text(&self.sandbox_id, path).await {
            Err(e) => format!("Error reading {path}: {e}"),
            Ok(content) => {
                if offset.is_none() && limit.is_none() {
                    return content;
                }
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

    async fn write_file(&self, path: &str, content: &str) -> String {
        match self
            .client
            .upload_text(&self.sandbox_id, path, content)
            .await
        {
            Ok(()) => format!("Written {} bytes to {path}", content.len()),
            Err(e) => format!("Error writing {path}: {e}"),
        }
    }

    async fn edit_file(&self, path: &str, old_string: &str, new_string: &str) -> String {
        let content = match self.client.download_text(&self.sandbox_id, path).await {
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
            Ok((_, output)) => {
                let matches: Vec<&str> = output.lines().filter(|l| !l.is_empty()).collect();
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
            Ok((_, output)) => output,
            Err(e) => format!("Error: {e}"),
        }
    }

    async fn run_command(
        &self,
        command: &str,
        dir: Option<String>,
        env: HashMap<String, String>,
        output_tx: mpsc::Sender<String>,
        reply: oneshot::Sender<i32>,
    ) {
        let session_id = match self
            .client
            .spawn_pty(
                &self.sandbox_id,
                SpawnPtyRequest {
                    cwd: dir,
                    envs: env,
                    ..Default::default()
                },
            )
            .await
        {
            Ok(id) => id,
            Err(e) => {
                let _ = output_tx.send(format!("Failed to spawn PTY: {e}")).await;
                drop(output_tx);
                let _ = reply.send(-1);
                return;
            }
        };

        let resp = match self
            .client
            .exec_in_pty(
                &self.sandbox_id,
                &session_id,
                SessionExecRequest {
                    command: command.to_string(),
                    run_async: Some(true),
                },
            )
            .await
        {
            Ok(r) => r,
            Err(e) => {
                let _ = output_tx.send(format!("Failed to exec: {e}")).await;
                drop(output_tx);
                let _ = reply.send(-1);
                let _ = self.client.delete_pty(&self.sandbox_id, &session_id).await;
                return;
            }
        };

        let (exit_code, logs) = match resp {
            // synchronous response (server ignored run_async)
            SessionExecResponse {
                cmd_id: None,
                output,
                exit_code,
            } => (exit_code.unwrap_or(-1), output.unwrap_or_default()),

            // asynchronous: poll until done
            SessionExecResponse {
                cmd_id: Some(ref cmd_id),
                ..
            } => {
                let exit_code = self.poll_command(&session_id, cmd_id).await;
                let logs = self
                    .client
                    .get_pty_command_logs(&self.sandbox_id, &session_id, cmd_id)
                    .await
                    .unwrap_or_default();
                (exit_code, logs)
            }
        };

        if !logs.is_empty() {
            let _ = output_tx.send(logs).await;
        }
        drop(output_tx);
        let _ = reply.send(exit_code);
        let _ = self.client.delete_pty(&self.sandbox_id, &session_id).await;
    }

    async fn poll_command(&self, session_id: &str, cmd_id: &str) -> i32 {
        let deadline = tokio::time::Instant::now() + COMMAND_TIMEOUT;
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(cmd_id, "command poll timed out");
                return -1;
            }
            match self
                .client
                .get_pty_command(&self.sandbox_id, session_id, cmd_id)
                .await
            {
                Ok(sc) => {
                    if let Some(code) = sc.exit_code {
                        return code;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "poll error");
                    return -1;
                }
            }
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
                    output_tx,
                    reply,
                } => {
                    self.run_command(&command, dir, env, output_tx, reply).await;
                }
            }
        }
    }
}

// ── DaytonaProvider ───────────────────────────────────────────────────────────

struct DaytonaRecord {
    handle: SandboxHandle,
}

pub struct DaytonaProvider {
    client: Arc<DaytonaClient>,
    sandboxes: Arc<RwLock<HashMap<String, DaytonaRecord>>>,
}

impl DaytonaProvider {
    pub fn new(api_key: String, base_url: String) -> Result<Arc<Self>, String> {
        let client = DaytonaClient::new(api_key, base_url)?;
        Ok(Arc::new(Self {
            client: Arc::new(client),
            sandboxes: Arc::new(RwLock::new(HashMap::new())),
        }))
    }

    pub fn from_env() -> anyhow::Result<Arc<Self>> {
        let api_key = std::env::var("DAYTONA_API_KEY").map_err(|_| {
            anyhow::anyhow!("DAYTONA_API_KEY is required to use the Daytona provider")
        })?;
        let base_url = std::env::var("DAYTONA_BASE_URL")
            .unwrap_or_else(|_| "https://app.daytona.io/api".to_string())
            .trim_end_matches('/')
            .to_string();
        Self::new(api_key, base_url).map_err(|e| anyhow::anyhow!(e))
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
        let sandbox = self.client.create_sandbox().await?;

        self.client.wait_until_started(&sandbox.id, 120).await?;

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
            },
        );

        Ok(handle)
    }

    async fn resume(&self, id: &str) -> Result<SandboxHandle, String> {
        self.sandboxes
            .read()
            .await
            .get(id)
            .map(|r| r.handle.clone())
            .ok_or_else(|| format!("Sandbox {id} not found"))
    }
}
