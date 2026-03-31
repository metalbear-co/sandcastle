use std::time::{Duration, SystemTime};

use anyhow::{Context, anyhow};
use reqwest::Client;

pub struct GitHubDeviceFlowProvider {
    client_id: String,
    http: Client,
}

/// Returned by `start_flow` — contains what the user needs to authorize.
pub struct DeviceFlowState {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

/// Returned by `poll_token`.
pub enum PollResult {
    /// User has not yet authorized; caller should wait `interval` seconds and retry.
    Pending,
    /// Authorization complete. `expires_at` is `None` if the app does not use token expiration.
    Complete {
        token: String,
        expires_at: Option<SystemTime>,
    },
    /// The device code has expired; a new flow must be started.
    Expired,
}

impl GitHubDeviceFlowProvider {
    pub fn new(client_id: String) -> Self {
        Self {
            client_id,
            http: Client::new(),
        }
    }

    /// Construct from the `GITHUB_OAUTH_CLIENT_ID` environment variable.
    /// Returns `None` if the variable is absent (feature disabled).
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        match std::env::var("GITHUB_OAUTH_CLIENT_ID") {
            Ok(id) if !id.is_empty() => Ok(Some(Self::new(id))),
            Ok(_) | Err(_) => Ok(None),
        }
    }

    /// Begin a Device Flow authorization request.
    ///
    /// `repos` is informational — Device Flow scopes are coarse-grained (`repo`),
    /// not per-repository.  The caller may display the repo list to the user as
    /// context for what they are authorizing.
    pub async fn start_flow(&self, _repos: &[String]) -> anyhow::Result<DeviceFlowState> {
        let resp = self
            .http
            .post("https://github.com/login/device/code")
            .header("Accept", "application/json")
            .header("User-Agent", "sandcastle")
            .form(&[("client_id", self.client_id.as_str()), ("scope", "repo")])
            .send()
            .await
            .context("failed to contact GitHub device code endpoint")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "GitHub device code request failed {}: {}",
                status.as_u16(),
                text
            ));
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse GitHub device code response")?;

        if let Some(err) = data["error"].as_str() {
            return Err(anyhow!("GitHub device code error: {}", err));
        }

        let device_code = data["device_code"]
            .as_str()
            .ok_or_else(|| anyhow!("missing device_code in response"))?
            .to_string();
        let user_code = data["user_code"]
            .as_str()
            .ok_or_else(|| anyhow!("missing user_code in response"))?
            .to_string();
        let verification_uri = data["verification_uri"]
            .as_str()
            .ok_or_else(|| anyhow!("missing verification_uri in response"))?
            .to_string();
        let expires_in = data["expires_in"].as_u64().unwrap_or(900);
        let interval = data["interval"].as_u64().unwrap_or(5);

        Ok(DeviceFlowState {
            device_code,
            user_code,
            verification_uri,
            expires_in,
            interval,
        })
    }

    /// Poll GitHub once for the access token associated with `device_code`.
    ///
    /// The caller is responsible for respecting the `interval` from `start_flow`
    /// between calls.
    pub async fn poll_token(&self, device_code: &str) -> anyhow::Result<PollResult> {
        let resp = self
            .http
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .header("User-Agent", "sandcastle")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await
            .context("failed to contact GitHub token endpoint")?;

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "GitHub token poll failed {}: {}",
                status.as_u16(),
                text
            ));
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse GitHub token response")?;

        if let Some(token) = data["access_token"].as_str().filter(|t| !t.is_empty()) {
            // `expires_in` is present when the OAuth App has token expiration enabled.
            let expires_at = data["expires_in"]
                .as_u64()
                .map(|secs| SystemTime::now() + Duration::from_secs(secs));
            return Ok(PollResult::Complete {
                token: token.to_string(),
                expires_at,
            });
        }

        match data["error"].as_str() {
            Some("authorization_pending") | Some("slow_down") => Ok(PollResult::Pending),
            Some("expired_token") => Ok(PollResult::Expired),
            Some(other) => Err(anyhow!("GitHub token error: {}", other)),
            None => Err(anyhow!("unexpected GitHub token response: {}", data)),
        }
    }
}
