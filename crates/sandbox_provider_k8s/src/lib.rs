use std::{
    collections::HashMap,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use k8s_openapi::api::core::v1::{Container, EnvVar, Pod, PodSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{
    Api, Client,
    api::{DeleteParams, ListParams, PostParams},
};
use tokio::sync::{RwLock, mpsc};

use sandcastle_rook_proto::{RookCommand, RookResponse};
use sandcastle_sandbox_providers_core::{
    Provider, RookConnection, RookRegistry, SandboxHandle, SandboxMessage,
};
use sandcastle_util::generate_token;

const WORK_DIR: &str = "/workspace";
const DEFAULT_TTL: Duration = Duration::from_secs(120 * 60);
const DEFAULT_IMAGE: &str = "ghcr.io/metalbear-co/sandcastle-rook:latest";

struct RookSandbox {
    conn: RookConnection,
}

impl RookSandbox {
    async fn send(&mut self, cmd: &RookCommand) {
        let json = match serde_json::to_string(cmd) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("failed to serialize rook command: {e}");
                return;
            }
        };
        let _ = self.conn.sender.send(json);
    }

    async fn recv(&mut self) -> Option<RookResponse> {
        let text = self.conn.receiver.recv().await?;
        match serde_json::from_str::<RookResponse>(&text) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!("failed to deserialize rook response: {e}");
                None
            }
        }
    }

    pub async fn run(mut self, mut rx: mpsc::Receiver<SandboxMessage>) {
        let mut req_id: u64 = 0;

        while let Some(msg) = rx.recv().await {
            req_id += 1;

            match msg {
                SandboxMessage::ReadFile {
                    path,
                    offset,
                    limit,
                    reply,
                } => {
                    self.send(&RookCommand::ReadFile {
                        req_id,
                        path,
                        offset,
                        limit,
                    })
                    .await;
                    let out = match self.recv().await {
                        Some(RookResponse::Result { output, .. }) => output,
                        Some(RookResponse::Error { message, .. }) => {
                            format!("Error: {message}")
                        }
                        _ => "Error: unexpected response from rook".to_string(),
                    };
                    let _ = reply.send(out);
                }

                SandboxMessage::WriteFile {
                    path,
                    content,
                    reply,
                } => {
                    self.send(&RookCommand::WriteFile {
                        req_id,
                        path,
                        content,
                    })
                    .await;
                    let out = match self.recv().await {
                        Some(RookResponse::Result { output, .. }) => output,
                        Some(RookResponse::Error { message, .. }) => {
                            format!("Error: {message}")
                        }
                        _ => "Error: unexpected response from rook".to_string(),
                    };
                    let _ = reply.send(out);
                }

                SandboxMessage::EditFile {
                    path,
                    old_string,
                    new_string,
                    reply,
                } => {
                    self.send(&RookCommand::EditFile {
                        req_id,
                        path,
                        old_string,
                        new_string,
                    })
                    .await;
                    let out = match self.recv().await {
                        Some(RookResponse::Result { output, .. }) => output,
                        Some(RookResponse::Error { message, .. }) => {
                            format!("Error: {message}")
                        }
                        _ => "Error: unexpected response from rook".to_string(),
                    };
                    let _ = reply.send(out);
                }

                SandboxMessage::Glob {
                    pattern,
                    base_path,
                    reply,
                } => {
                    self.send(&RookCommand::Glob {
                        req_id,
                        pattern,
                        base_path,
                    })
                    .await;
                    let out = match self.recv().await {
                        Some(RookResponse::Result { output, .. }) => output,
                        Some(RookResponse::Error { message, .. }) => {
                            format!("Error: {message}")
                        }
                        _ => "Error: unexpected response from rook".to_string(),
                    };
                    let _ = reply.send(out);
                }

                SandboxMessage::Grep {
                    pattern,
                    path,
                    include,
                    reply,
                } => {
                    self.send(&RookCommand::Grep {
                        req_id,
                        pattern,
                        path,
                        include,
                    })
                    .await;
                    let out = match self.recv().await {
                        Some(RookResponse::Result { output, .. }) => output,
                        Some(RookResponse::Error { message, .. }) => {
                            format!("Error: {message}")
                        }
                        _ => "Error: unexpected response from rook".to_string(),
                    };
                    let _ = reply.send(out);
                }

                SandboxMessage::RunCommand {
                    command,
                    dir,
                    env,
                    output_tx,
                    reply,
                } => {
                    self.send(&RookCommand::RunCommand {
                        req_id,
                        command,
                        dir,
                        env,
                    })
                    .await;
                    let exit_code = loop {
                        match self.recv().await {
                            Some(RookResponse::Output { line, .. }) => {
                                let _ = output_tx.send(line).await;
                            }
                            Some(RookResponse::Done { exit_code, .. }) => {
                                break exit_code;
                            }
                            Some(RookResponse::Error { message, .. }) => {
                                let _ = output_tx.send(message).await;
                                break -1;
                            }
                            _ => break -1,
                        }
                    };
                    let _ = reply.send(exit_code);
                }
            }
        }
    }
}

struct SandboxRecord {
    handle: SandboxHandle,
    pod_name: String,
    created_at: Instant,
}

pub struct K8sProvider {
    client: Client,
    namespace: String,
    image: String,
    rook_url: String,
    rook_registry: Arc<RookRegistry>,
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
        let image =
            std::env::var("SANDCASTLE_K8S_IMAGE").unwrap_or_else(|_| DEFAULT_IMAGE.to_string());
        let rook_url = std::env::var("SANDCASTLE_ROOK_URL")
            .unwrap_or_else(|_| "ws://localhost:3000/rook/ws".to_string());
        Ok(Arc::new(Self {
            client,
            namespace,
            image,
            rook_url,
            rook_registry: RookRegistry::new(),
            sandboxes: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }))
    }

    fn api(&self) -> Api<Pod> {
        Api::namespaced(self.client.clone(), &self.namespace)
    }

    async fn create_pod(&self, id: &str) -> anyhow::Result<String> {
        let pod_name = format!("sandbox-{id}");

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
                    env: Some(vec![
                        EnvVar {
                            name: "SANDCASTLE_ROOK_URL".to_string(),
                            value: Some(self.rook_url.clone()),
                            ..Default::default()
                        },
                        EnvVar {
                            name: "SANDBOX_ID".to_string(),
                            value: Some(id.to_string()),
                            ..Default::default()
                        },
                    ]),
                    working_dir: Some(WORK_DIR.to_string()),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };

        self.api().create(&PostParams::default(), &pod).await?;

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

    fn rook_registry(&self) -> Option<Arc<RookRegistry>> {
        Some(Arc::clone(&self.rook_registry))
    }

    async fn create(&self, name: String) -> Result<SandboxHandle, String> {
        let id = generate_token()[..16].to_string();

        let conn_rx = self.rook_registry.register(id.clone());

        let pod_name = self
            .create_pod(&id)
            .await
            .map_err(|e| format!("failed to create pod: {e}"))?;

        tracing::info!("k8s pod {pod_name} created, waiting for rook to connect");

        let conn = tokio::time::timeout(Duration::from_secs(60), conn_rx)
            .await
            .map_err(|_| format!("timed out waiting for rook to connect for sandbox {id}"))?
            .map_err(|_| format!("rook registry channel dropped for sandbox {id}"))?;

        tracing::info!("rook connected for sandbox {id}");

        let (tx, rx) = mpsc::channel(32);
        let handle = SandboxHandle::new(id.clone(), name, PathBuf::from(WORK_DIR), tx);

        tokio::spawn(RookSandbox { conn }.run(rx));

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
