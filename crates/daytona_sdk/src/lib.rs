use std::collections::HashMap;
use std::time::{Duration, Instant};

use reqwest::{Client, multipart};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

const DEFAULT_BASE_URL: &str = "https://app.daytona.io/api";

// ── Client ────────────────────────────────────────────────────────────────────

pub struct DaytonaClient {
    http: Client,
    base_url: String,
    api_key: String,
}

impl DaytonaClient {
    pub fn new(api_key: String, base_url: String) -> Result<Self, String> {
        let http = Client::builder()
            .timeout(Duration::from_secs(60))
            .build()
            .map_err(|e| e.to_string())?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key,
        })
    }

    pub fn from_env() -> anyhow::Result<Self> {
        let api_key = std::env::var("DAYTONA_API_KEY")
            .map_err(|_| anyhow::anyhow!("DAYTONA_API_KEY is required"))?;
        let base_url =
            std::env::var("DAYTONA_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_string());
        Self::new(api_key, base_url).map_err(|e| anyhow::anyhow!(e))
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    async fn check(&self, resp: reqwest::Response) -> Result<reqwest::Response, String> {
        if resp.status().is_success() {
            Ok(resp)
        } else {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            Err(format!("API {status}: {body}"))
        }
    }

    // ── Sandbox ───────────────────────────────────────────────────────────────

    pub async fn create_sandbox(&self) -> Result<Sandbox, String> {
        let resp = self
            .http
            .post(self.url("/sandbox"))
            .bearer_auth(&self.api_key)
            .json(&serde_json::json!({}))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.check(resp)
            .await?
            .json::<Sandbox>()
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_sandbox(&self, sandbox_id: &Uuid) -> Result<Sandbox, String> {
        let resp = self
            .http
            .get(self.url(&format!("/sandbox/{sandbox_id}")))
            .bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.check(resp)
            .await?
            .json::<Sandbox>()
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn wait_until_started(
        &self,
        sandbox_id: &Uuid,
        timeout_secs: u64,
    ) -> Result<(), String> {
        let deadline = Instant::now() + Duration::from_secs(timeout_secs);
        loop {
            let sb = self.get_sandbox(sandbox_id).await?;
            match sb.state {
                SandboxState::Started => return Ok(()),
                SandboxState::Error => {
                    return Err(format!("sandbox {sandbox_id} entered error state"));
                }
                _ => {}
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "sandbox {sandbox_id} did not start within {timeout_secs}s"
                ));
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    // ── Process (one-shot) ────────────────────────────────────────────────────

    pub async fn execute(
        &self,
        sandbox_id: &Uuid,
        req: ExecuteRequest,
    ) -> Result<ExecuteResponse, String> {
        let resp = self
            .http
            .post(self.url(&format!("/toolbox/{sandbox_id}/toolbox/process/execute")))
            .bearer_auth(&self.api_key)
            .json(&req)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.check(resp)
            .await?
            .json::<ExecuteResponse>()
            .await
            .map_err(|e| e.to_string())
    }

    // ── Sessions (PTY) ────────────────────────────────────────────────────────

    pub async fn spawn_pty(
        &self,
        sandbox_id: &Uuid,
        req: SpawnPtyRequest,
    ) -> Result<String, String> {
        let resp = self
            .http
            .post(self.url(&format!("/toolbox/{sandbox_id}/process/pty")))
            .bearer_auth(&self.api_key)
            .json(&req)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.check(resp)
            .await?
            .json::<SpawnPtyResponse>()
            .await
            .map_err(|e| e.to_string())
            .map(|r| r.session_id)
    }

    pub async fn delete_pty(&self, sandbox_id: &Uuid, session_id: &str) -> Result<(), String> {
        let resp = self
            .http
            .delete(self.url(&format!("/toolbox/{sandbox_id}/process/pty/{session_id}")))
            .bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.check(resp).await?;
        Ok(())
    }

    pub async fn exec_in_pty(
        &self,
        sandbox_id: &Uuid,
        session_id: &str,
        req: SessionExecRequest,
    ) -> Result<SessionExecResponse, String> {
        let resp = self
            .http
            .post(self.url(&format!(
                "/toolbox/{sandbox_id}/process/pty/{session_id}/exec"
            )))
            .bearer_auth(&self.api_key)
            .json(&req)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.check(resp)
            .await?
            .json::<SessionExecResponse>()
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_pty_command(
        &self,
        sandbox_id: &Uuid,
        session_id: &str,
        cmd_id: &str,
    ) -> Result<SessionCommand, String> {
        let resp = self
            .http
            .get(self.url(&format!(
                "/toolbox/{sandbox_id}/process/pty/{session_id}/command/{cmd_id}"
            )))
            .bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.check(resp)
            .await?
            .json::<SessionCommand>()
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn get_pty_command_logs(
        &self,
        sandbox_id: &Uuid,
        session_id: &str,
        cmd_id: &str,
    ) -> Result<String, String> {
        let resp = self
            .http
            .get(self.url(&format!(
                "/toolbox/{sandbox_id}/process/pty/{session_id}/command/{cmd_id}/logs"
            )))
            .bearer_auth(&self.api_key)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.check(resp)
            .await?
            .text()
            .await
            .map_err(|e| e.to_string())
    }

    // ── Files ─────────────────────────────────────────────────────────────────

    pub async fn download_text(&self, sandbox_id: &Uuid, path: &str) -> Result<String, String> {
        let resp = self
            .http
            .get(self.url(&format!("/toolbox/{sandbox_id}/toolbox/files/download")))
            .bearer_auth(&self.api_key)
            .query(&[("path", path)])
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.check(resp)
            .await?
            .text()
            .await
            .map_err(|e| e.to_string())
    }

    pub async fn upload_text(
        &self,
        sandbox_id: &Uuid,
        path: &str,
        content: &str,
    ) -> Result<(), String> {
        let part = multipart::Part::bytes(content.as_bytes().to_vec())
            .file_name("file")
            .mime_str("text/plain")
            .map_err(|e| e.to_string())?;
        let form = multipart::Form::new().part("file", part);
        let resp = self
            .http
            .post(self.url(&format!("/toolbox/{sandbox_id}/toolbox/files/upload")))
            .bearer_auth(&self.api_key)
            .query(&[("path", path)])
            .multipart(form)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        self.check(resp).await?;
        Ok(())
    }
}

// ── Models ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct Sandbox {
    pub id: Uuid,
    pub state: SandboxState,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SandboxState {
    Creating,
    Started,
    Stopped,
    Stopping,
    Error,
    Archived,
    Archiving,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Serialize)]
pub struct ExecuteRequest {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecuteResponse {
    pub exit_code: i32,
    pub result: String,
}

#[derive(Debug, Serialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SpawnPtyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub envs: HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cols: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rows: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lazy_start: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SpawnPtyResponse {
    session_id: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionExecRequest {
    pub command: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_async: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionExecResponse {
    pub cmd_id: Option<String>,
    pub output: Option<String>,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionCommand {
    pub id: String,
    pub exit_code: Option<i32>,
}
