use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::{Container, Pod, PodSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{
    Api, Client,
    api::{AttachParams, DeleteParams, ListParams, PostParams},
};
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio_util::io::ReaderStream;

use sandcastle_sandbox_providers_core::{Provider, SandboxHandle, SandboxMessage};
use sandcastle_util::generate_token;

const WORK_DIR: &str = "/workspace";
const DEFAULT_TTL: Duration = Duration::from_secs(120 * 60);

// ── Helpers ───────────────────────────────────────────────────────────────────

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn exit_code_from_status(
    status: Option<k8s_openapi::apimachinery::pkg::apis::meta::v1::Status>,
) -> i32 {
    match status {
        None => -1,
        Some(s) => {
            if s.status.as_deref() == Some("Success") {
                0
            } else {
                s.details
                    .and_then(|d| d.causes)
                    .and_then(|causes| {
                        causes
                            .into_iter()
                            .find(|c| c.reason.as_deref() == Some("ExitCode"))
                    })
                    .and_then(|c| c.message)
                    .and_then(|m| m.parse::<i32>().ok())
                    .unwrap_or(-1)
            }
        }
    }
}

// ── K8sSandbox ────────────────────────────────────────────────────────────────

struct ExecResult {
    exit_code: i32,
    stdout: String,
    stderr: String,
}

struct K8sSandbox {
    pod_name: String,
    namespace: String,
    client: Client,
}

impl K8sSandbox {
    fn api(&self) -> Api<Pod> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    async fn exec_cmd(&self, cmd: &[&str]) -> Result<ExecResult, String> {
        let api = self.api();
        let mut attached = api
            .exec(
                &self.pod_name,
                cmd.to_vec(),
                &AttachParams::default()
                    .stdin(false)
                    .stdout(true)
                    .stderr(true),
            )
            .await
            .map_err(|e| format!("exec failed: {e}"))?;

        let status_rx = attached.take_status();

        let mut stdout = String::new();
        let mut stderr = String::new();

        if let Some(out) = attached.stdout() {
            let mut stream = ReaderStream::new(out);
            while let Some(chunk) = stream.next().await {
                if let Ok(bytes) = chunk {
                    stdout.push_str(&String::from_utf8_lossy(&bytes));
                }
            }
        }
        if let Some(err) = attached.stderr() {
            let mut stream = ReaderStream::new(err);
            while let Some(chunk) = stream.next().await {
                if let Ok(bytes) = chunk {
                    stderr.push_str(&String::from_utf8_lossy(&bytes));
                }
            }
        }

        let exit_code = if let Some(rx) = status_rx {
            exit_code_from_status(rx.await)
        } else {
            0
        };

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
                None => format!(
                    "awk -v s={start} \
                     'NR>=s {{printf \"%6d\\t%s\\n\", NR, $0}}' '{path}'"
                ),
            }
        };
        match self.exec_cmd(&["sh", "-c", &script]).await {
            Ok(r) if r.exit_code == 0 => r.stdout,
            Ok(r) => format!("Error reading {path}: {}", r.stderr),
            Err(e) => format!("Error reading {path}: {e}"),
        }
    }

    async fn write_file(&self, path: &str, content: &str) -> String {
        // Use base64 to avoid stdin complexity with K8s exec.
        // base64 chars are shell-safe: [A-Za-z0-9+/=]
        let b64 = B64.encode(content.as_bytes());
        let parent = std::path::Path::new(path)
            .parent()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        let script = if parent.is_empty() {
            format!("printf '%s' '{b64}' | base64 -d > '{path}'")
        } else {
            format!("mkdir -p -- '{parent}' && printf '%s' '{b64}' | base64 -d > '{path}'")
        };
        match self.exec_cmd(&["sh", "-c", &script]).await {
            Ok(r) if r.exit_code == 0 => format!("Written {} bytes to {path}", content.len()),
            Ok(r) => format!("Error writing {path}: {}", r.stderr),
            Err(e) => format!("Error writing {path}: {e}"),
        }
    }

    async fn edit_file(&self, path: &str, old_string: &str, new_string: &str) -> String {
        let content = match self
            .exec_cmd(&["sh", "-c", &format!("cat -- '{path}'")])
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
        let b64 = B64.encode(new_content.as_bytes());
        let script = format!("printf '%s' '{b64}' | base64 -d > '{path}'");
        match self.exec_cmd(&["sh", "-c", &script]).await {
            Ok(r) if r.exit_code == 0 => format!("Edited {path}: replaced 1 occurrence"),
            Ok(r) => format!("Error writing {path}: {}", r.stderr),
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
        match self.exec_cmd(&["sh", "-c", &cmd]).await {
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
        match self.exec_cmd(&["sh", "-c", &cmd]).await {
            Ok(r) => r.stdout,
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
        let work_dir = dir.as_deref().unwrap_or(WORK_DIR);

        // K8s exec doesn't support per-exec env injection; prepend as shell assignments.
        let env_prefix: String = env
            .iter()
            .map(|(k, v)| format!("{}={} ", k, shell_quote(v)))
            .collect();
        let full_command = format!("cd {work_dir} && {env_prefix}{command}");

        let api = self.api();
        let cmd_vec = vec!["sh".to_string(), "-c".to_string(), full_command.clone()];
        let mut attached = match api
            .exec(
                &self.pod_name,
                cmd_vec,
                &AttachParams::default()
                    .stdin(false)
                    .stdout(true)
                    .stderr(true),
            )
            .await
        {
            Ok(a) => a,
            Err(e) => {
                let _ = output_tx.send(format!("Failed to exec: {e}")).await;
                let _ = reply.send(-1);
                return;
            }
        };

        let status_rx = attached.take_status();

        // Stream stdout
        if let Some(out) = attached.stdout() {
            let mut stream = ReaderStream::new(out);
            while let Some(chunk) = stream.next().await {
                if let Ok(bytes) = chunk {
                    for line in String::from_utf8_lossy(&bytes).lines() {
                        if output_tx.send(line.to_string()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
        // Stream stderr
        if let Some(err) = attached.stderr() {
            let mut stream = ReaderStream::new(err);
            while let Some(chunk) = stream.next().await {
                if let Ok(bytes) = chunk {
                    for line in String::from_utf8_lossy(&bytes).lines() {
                        if output_tx.send(line.to_string()).await.is_err() {
                            break;
                        }
                    }
                }
            }
        }
        drop(output_tx);

        let exit_code = if let Some(rx) = status_rx {
            exit_code_from_status(rx.await)
        } else {
            0
        };
        let _ = reply.send(exit_code);
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

// ── K8sProvider ───────────────────────────────────────────────────────────────

struct SandboxRecord {
    handle: SandboxHandle,
    pod_name: String,
    created_at: Instant,
}

pub struct K8sProvider {
    client: Client,
    namespace: String,
    image: String,
    sandboxes: Arc<RwLock<HashMap<String, SandboxRecord>>>,
    ttl: Duration,
}

impl K8sProvider {
    pub async fn from_env() -> anyhow::Result<Arc<Self>> {
        Self::new(DEFAULT_TTL).await
    }

    pub async fn new(ttl: Duration) -> anyhow::Result<Arc<Self>> {
        let client = Client::try_default().await?;
        let namespace = std::env::var("K8S_SANDBOX_NAMESPACE")
            .unwrap_or_else(|_| "sandcastle-sandboxes".to_string());
        let image = std::env::var("SANDCASTLE_K8S_IMAGE")
            .unwrap_or_else(|_| "debian:bookworm-slim".to_string());
        Ok(Arc::new(Self {
            client,
            namespace,
            image,
            sandboxes: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }))
    }

    fn api(&self) -> Api<Pod> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    async fn create_pod(&self, id: &str) -> anyhow::Result<String> {
        let pod_name = format!("sandbox-{id}");
        let setup = "apt-get update -qq && apt-get install -y -qq git && mkdir -p /workspace && tail -f /dev/null";

        let mut labels = std::collections::BTreeMap::new();
        labels.insert("managed-by".to_string(), "sandcastle".to_string());
        labels.insert("sandbox-id".to_string(), id.to_string());

        let pod = Pod {
            metadata: ObjectMeta {
                name: Some(pod_name.clone()),
                namespace: Some(self.namespace.clone()),
                labels: Some(labels),
                ..Default::default()
            },
            spec: Some(PodSpec {
                restart_policy: Some("Never".to_string()),
                containers: vec![Container {
                    name: "sandbox".to_string(),
                    image: Some(self.image.clone()),
                    command: Some(vec!["sh".to_string(), "-c".to_string(), setup.to_string()]),
                    working_dir: Some(WORK_DIR.to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        self.api().create(&PostParams::default(), &pod).await?;

        // Wait up to 60s for Running
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match self.api().get(&pod_name).await {
                Ok(p) => {
                    let phase = p
                        .status
                        .as_ref()
                        .and_then(|s| s.phase.as_deref())
                        .unwrap_or("");
                    if phase == "Running" {
                        break;
                    }
                    if phase == "Failed" || phase == "Succeeded" {
                        anyhow::bail!("pod {pod_name} entered phase {phase} unexpectedly");
                    }
                }
                Err(e) => tracing::warn!("waiting for pod {pod_name}: {e}"),
            }
            if Instant::now() >= deadline {
                anyhow::bail!("timed out waiting for pod {pod_name} to reach Running");
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }

        Ok(pod_name)
    }

    pub async fn cleanup_stale_pods(&self) {
        let lp = ListParams::default().labels("managed-by=sandcastle");
        match self.api().list(&lp).await {
            Ok(list) => {
                for pod in list.items {
                    let Some(name) = pod.metadata.name else {
                        continue;
                    };
                    if let Err(e) = self.api().delete(&name, &DeleteParams::default()).await {
                        tracing::warn!("failed to delete stale pod {name}: {e}");
                    } else {
                        tracing::info!("deleted stale pod {name}");
                    }
                }
            }
            Err(e) => tracing::warn!("failed to list stale k8s pods: {e}"),
        }
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
                        .map(|(id, r)| (id.clone(), r.pod_name.clone()))
                        .collect()
                };
                for (id, pod_name) in expired {
                    if let Err(e) = provider
                        .api()
                        .delete(&pod_name, &DeleteParams::default())
                        .await
                    {
                        tracing::warn!("failed to delete expired pod {pod_name}: {e}");
                    }
                    provider.sandboxes.write().await.remove(&id);
                    tracing::info!("k8s sandbox {id} expired and removed");
                }
            }
        });
    }
}

#[async_trait::async_trait]
impl Provider for K8sProvider {
    fn name(&self) -> &'static str {
        "k8s"
    }

    fn description(&self) -> &'static str {
        "Kubernetes sandbox — each sandbox runs as an isolated Pod"
    }

    async fn create(&self, name: String) -> Result<SandboxHandle, String> {
        let id = generate_token()[..16].to_string();
        let pod_name = self
            .create_pod(&id)
            .await
            .map_err(|e| format!("failed to create pod: {e}"))?;

        let (tx, rx) = mpsc::channel(32);
        let handle = SandboxHandle::new(id.clone(), name, PathBuf::from(WORK_DIR), tx);

        tokio::spawn(
            K8sSandbox {
                pod_name: pod_name.clone(),
                namespace: self.namespace.clone(),
                client: self.client.clone(),
            }
            .run(rx),
        );

        self.sandboxes.write().await.insert(
            id,
            SandboxRecord {
                handle: handle.clone(),
                pod_name,
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
