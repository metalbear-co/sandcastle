use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use bollard::{
    Docker,
    container::{
        Config, CreateContainerOptions, LogOutput, RemoveContainerOptions, StartContainerOptions,
    },
    exec::{CreateExecOptions, StartExecResults},
    image::CreateImageOptions,
    models::HostConfig,
};
use futures_util::StreamExt;
use tokio::{
    io::AsyncWriteExt,
    sync::{RwLock, mpsc},
};

use crate::{Provider, SandboxHandle, SandboxMessage};
use sandcastle_util::generate_token;

const WORK_DIR: &str = "/workspace";

// ── DockerSandbox ─────────────────────────────────────────────────────────────

struct ExecResult {
    exit_code: i64,
    stdout: String,
    stderr: String,
}

impl ExecResult {
    fn to_command_output(&self) -> String {
        format!(
            "exit_code: {}\nstdout:\n{}\nstderr:\n{}",
            self.exit_code, self.stdout, self.stderr
        )
    }
}

struct DockerSandbox {
    container_id: String,
    docker: Docker,
}

impl DockerSandbox {
    async fn exec_cmd(
        &self,
        cmd: &[&str],
        env: Option<Vec<String>>,
        dir: Option<&str>,
        stdin: Option<&[u8]>,
    ) -> Result<ExecResult, String> {
        let has_stdin = stdin.is_some();
        let env_refs: Option<Vec<&str>> = env
            .as_deref()
            .map(|v| v.iter().map(|s| s.as_str()).collect());

        let exec_id = self
            .docker
            .create_exec(
                &self.container_id,
                CreateExecOptions {
                    attach_stdout: Some(true),
                    attach_stderr: Some(true),
                    attach_stdin: Some(has_stdin),
                    cmd: Some(cmd.to_vec()),
                    env: env_refs,
                    working_dir: dir,
                    ..Default::default()
                },
            )
            .await
            .map_err(|e| format!("Failed to create exec: {e}"))?
            .id;

        let start_result = self
            .docker
            .start_exec(&exec_id, None)
            .await
            .map_err(|e| format!("Failed to start exec: {e}"))?;

        let mut stdout = String::new();
        let mut stderr = String::new();

        if let StartExecResults::Attached {
            mut output,
            mut input,
        } = start_result
        {
            if let Some(data) = stdin {
                let _ = input.write_all(data).await;
                drop(input);
            }
            while let Some(chunk) = output.next().await {
                match chunk {
                    Ok(LogOutput::StdOut { message }) => {
                        stdout.push_str(&String::from_utf8_lossy(&message));
                    }
                    Ok(LogOutput::StdErr { message }) => {
                        stderr.push_str(&String::from_utf8_lossy(&message));
                    }
                    _ => {}
                }
            }
        }

        let exit_code = self
            .docker
            .inspect_exec(&exec_id)
            .await
            .ok()
            .and_then(|i| i.exit_code)
            .unwrap_or(-1);

        Ok(ExecResult {
            exit_code,
            stdout,
            stderr,
        })
    }

    async fn read_file(&self, path: &str, offset: Option<u32>, limit: Option<u32>) -> String {
        let script = if offset.is_none() && limit.is_none() {
            format!("cat -- '{path}'")
        } else {
            let start = offset.unwrap_or(1);
            match limit {
                Some(n) => {
                    let end = start + n - 1;
                    format!(
                        "awk -v s={start} -v e={end} \
                         'NR>=s && NR<=e {{printf \"%6d\\t%s\\n\", NR, $0}}' '{path}'"
                    )
                }
                None => {
                    format!(
                        "awk -v s={start} \
                         'NR>=s {{printf \"%6d\\t%s\\n\", NR, $0}}' '{path}'"
                    )
                }
            }
        };
        match self
            .exec_cmd(&["sh", "-c", &script], None, None, None)
            .await
        {
            Ok(r) if r.exit_code == 0 => r.stdout,
            Ok(r) => format!("Error reading {path}: {}", r.stderr),
            Err(e) => format!("Error reading {path}: {e}"),
        }
    }

    async fn write_file(&self, path: &str, content: &str) -> String {
        // Create parent dirs
        if let Some(parent) = Path::new(path).parent() {
            let mkdir = format!("mkdir -p -- '{}'", parent.display());
            let _ = self.exec_cmd(&["sh", "-c", &mkdir], None, None, None).await;
        }
        let write_cmd = format!("cat > -- '{path}'");
        match self
            .exec_cmd(
                &["sh", "-c", &write_cmd],
                None,
                None,
                Some(content.as_bytes()),
            )
            .await
        {
            Ok(r) if r.exit_code == 0 => format!("Written {} bytes to {path}", content.len()),
            Ok(r) => format!("Error writing {path}: {}", r.stderr),
            Err(e) => format!("Error writing {path}: {e}"),
        }
    }

    async fn edit_file(&self, path: &str, old_string: &str, new_string: &str) -> String {
        let read_cmd = format!("cat -- '{path}'");
        let content = match self
            .exec_cmd(&["sh", "-c", &read_cmd], None, None, None)
            .await
        {
            Ok(r) if r.exit_code == 0 => r.stdout,
            Ok(r) => return format!("Error reading {path}: {}", r.stderr),
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
        let write_cmd = format!("cat > -- '{path}'");
        match self
            .exec_cmd(
                &["sh", "-c", &write_cmd],
                None,
                None,
                Some(new_content.as_bytes()),
            )
            .await
        {
            Ok(r) if r.exit_code == 0 => format!("Edited {path}: replaced 1 occurrence"),
            Ok(r) => format!("Error writing {path}: {}", r.stderr),
            Err(e) => format!("Error writing {path}: {e}"),
        }
    }

    async fn glob(&self, pattern: &str, base_path: Option<String>) -> String {
        let base = base_path.as_deref().unwrap_or(WORK_DIR);
        // Derive find(1) arguments from the glob pattern.
        // Patterns like **/*.rs  → recursive find with -name '*.rs'
        // Patterns like *.rs     → non-recursive (maxdepth 1) with -name '*.rs'
        let (search_base, name_pat, recursive) = {
            let recursive = pattern.contains("**");
            // The name filter is the last path component of the pattern.
            let name = pattern.split('/').next_back().unwrap_or(pattern);
            // The directory prefix before the first `**` component.
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
            (search_base, name, recursive)
        };
        let depth_flag = if recursive { "" } else { "-maxdepth 1 " };
        let cmd = format!(
            "find '{search_base}' {depth_flag}-name '{name_pat}' -type f 2>/dev/null | sort | head -1000"
        );
        match self.exec_cmd(&["sh", "-c", &cmd], None, None, None).await {
            Ok(r) => {
                let matches: Vec<&str> = r.stdout.lines().filter(|l| !l.is_empty()).collect();
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
        match self.exec_cmd(&["sh", "-c", &cmd], None, None, None).await {
            Ok(r) => r.stdout,
            Err(e) => format!("Error: {e}"),
        }
    }

    async fn run_command(
        &self,
        command: &str,
        dir: Option<String>,
        env: std::collections::HashMap<String, String>,
    ) -> String {
        let work_dir = dir.as_deref().unwrap_or(WORK_DIR);
        let env_vec: Option<Vec<String>> = if env.is_empty() {
            None
        } else {
            Some(env.iter().map(|(k, v)| format!("{k}={v}")).collect())
        };
        match self
            .exec_cmd(&["sh", "-c", command], env_vec, Some(work_dir), None)
            .await
        {
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

// ── Docker connection ─────────────────────────────────────────────────────────

/// Connect to Docker, trying macOS Docker Desktop's socket path when the
/// standard /var/run/docker.sock is absent.
fn connect_docker() -> Result<Docker, bollard::errors::Error> {
    // DOCKER_HOST env var takes priority (bollard handles it internally).
    if std::env::var("DOCKER_HOST").is_ok() {
        return Docker::connect_with_local_defaults();
    }

    // On macOS, Docker Desktop >= 4.x puts its socket in ~/.docker/run/.
    #[cfg(target_os = "macos")]
    if let Some(home) = std::env::var_os("HOME") {
        let mac_sock = PathBuf::from(home).join(".docker/run/docker.sock");
        if mac_sock.exists() {
            return Docker::connect_with_unix(
                mac_sock.to_str().unwrap_or("/var/run/docker.sock"),
                120,
                bollard::API_DEFAULT_VERSION,
            );
        }
    }

    Docker::connect_with_local_defaults()
}

// ── DockerProvider ────────────────────────────────────────────────────────────

struct SandboxRecord {
    handle: SandboxHandle,
    container_id: String,
    created_at: Instant,
}

pub struct DockerProvider {
    docker: Docker,
    image: String,
    sandboxes: Arc<RwLock<HashMap<String, SandboxRecord>>>,
    ttl: Duration,
}

impl DockerProvider {
    pub fn new(ttl: Duration) -> Result<Arc<Self>, bollard::errors::Error> {
        let docker = connect_docker()?;
        let image = std::env::var("SANDCASTLE_DOCKER_IMAGE")
            .unwrap_or_else(|_| "debian:bookworm-slim".to_string());
        Ok(Arc::new(Self {
            docker,
            image,
            sandboxes: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }))
    }

    async fn pull_image(&self) -> Result<(), String> {
        let mut stream = self.docker.create_image(
            Some(CreateImageOptions {
                from_image: self.image.as_str(),
                ..Default::default()
            }),
            None,
            None,
        );
        while let Some(item) = stream.next().await {
            if let Err(e) = item {
                return Err(format!("Failed to pull image: {e}"));
            }
        }
        Ok(())
    }

    async fn create_container(&self, id: &str) -> Result<String, String> {
        self.pull_image().await?;

        let container_name = format!("sandcastle-{id}");
        // Install git then idle as PID 1 so `docker exec` calls can run.
        let setup = "apt-get update -qq && apt-get install -y -qq git && tail -f /dev/null";

        let config = Config {
            image: Some(self.image.as_str()),
            entrypoint: Some(vec!["sh", "-c"]),
            cmd: Some(vec![setup]),
            working_dir: Some(WORK_DIR),
            host_config: Some(HostConfig {
                ..Default::default()
            }),
            ..Default::default()
        };

        let container = self
            .docker
            .create_container(
                Some(CreateContainerOptions {
                    name: container_name.as_str(),
                    platform: None,
                }),
                config,
            )
            .await
            .map_err(|e| format!("Failed to create container: {e}"))?;

        self.docker
            .start_container(&container.id, None::<StartContainerOptions<String>>)
            .await
            .map_err(|e| format!("Failed to start container: {e}"))?;

        Ok(container.id)
    }

    pub fn start_cleanup_task(self: &Arc<Self>) {
        let provider = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let expired: Vec<(String, String)> = {
                    let map = provider.sandboxes.read().await;
                    map.iter()
                        .filter(|(_, r)| r.created_at.elapsed() >= provider.ttl)
                        .map(|(id, r)| (id.clone(), r.container_id.clone()))
                        .collect()
                };
                for (id, container_id) in expired {
                    let _ = provider.docker.stop_container(&container_id, None).await;
                    let _ = provider
                        .docker
                        .remove_container(
                            &container_id,
                            Some(RemoveContainerOptions {
                                force: true,
                                ..Default::default()
                            }),
                        )
                        .await;
                    provider.sandboxes.write().await.remove(&id);
                    tracing::info!("docker sandbox {id} expired and removed");
                }
            }
        });
    }
}

#[async_trait::async_trait]
impl Provider for DockerProvider {
    fn name(&self) -> &'static str {
        "docker"
    }

    fn description(&self) -> &'static str {
        "Docker sandbox — all operations run inside an isolated container"
    }

    async fn create(&self, name: String) -> Result<SandboxHandle, String> {
        let id = generate_token()[..16].to_string();
        let container_id = self.create_container(&id).await?;

        let (tx, rx) = mpsc::channel(32);
        let handle = SandboxHandle::new(id.clone(), name, PathBuf::from(WORK_DIR), tx);

        tokio::spawn(
            DockerSandbox {
                container_id: container_id.clone(),
                docker: self.docker.clone(),
            }
            .run(rx),
        );

        self.sandboxes.write().await.insert(
            id,
            SandboxRecord {
                handle: handle.clone(),
                container_id,
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
