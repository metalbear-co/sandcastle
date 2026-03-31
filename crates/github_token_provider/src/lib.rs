use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, anyhow};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::Client;
use serde::Serialize;

pub struct GitHubAppTokenProvider {
    app_id: u64,
    private_key_pem: String,
    installation_id: u64,
    http: Client,
}

pub struct GitHubToken {
    pub token: String,
    pub expires_at: SystemTime,
}

#[derive(Serialize)]
struct AppClaims {
    iat: i64,
    exp: i64,
    iss: String,
}

impl GitHubAppTokenProvider {
    pub fn new(app_id: u64, private_key_pem: String, installation_id: u64) -> Self {
        Self {
            app_id,
            private_key_pem,
            installation_id,
            http: Client::new(),
        }
    }

    /// Construct from environment variables. Returns `None` if `GITHUB_APP_ID` is not set
    /// (feature is disabled). Returns `Err` if any required variable is present but malformed.
    pub fn from_env() -> anyhow::Result<Option<Self>> {
        let app_id_str = match std::env::var("GITHUB_APP_ID") {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        let app_id: u64 = app_id_str
            .parse()
            .context("GITHUB_APP_ID must be a numeric value")?;

        let raw_key =
            std::env::var("GITHUB_APP_PRIVATE_KEY").context("GITHUB_APP_PRIVATE_KEY not set")?;
        // Support environments where the PEM is stored with literal \n instead of real newlines.
        let private_key_pem = raw_key.replace("\\n", "\n");

        let installation_id_str = std::env::var("GITHUB_APP_INSTALLATION_ID")
            .context("GITHUB_APP_INSTALLATION_ID not set")?;
        let installation_id: u64 = installation_id_str
            .parse()
            .context("GITHUB_APP_INSTALLATION_ID must be a numeric value")?;

        Ok(Some(Self::new(app_id, private_key_pem, installation_id)))
    }

    pub fn app_id(&self) -> u64 {
        self.app_id
    }

    /// Generate a scoped GitHub installation token for the given repositories.
    ///
    /// `repos` may be bare names (`"my-repo"`) or prefixed (`"owner/my-repo"`).
    /// Any `owner/` prefix is stripped — GitHub's API only accepts bare names scoped to the
    /// configured installation.
    pub async fn get_token(&self, repos: &[String]) -> anyhow::Result<GitHubToken> {
        let jwt = self.make_jwt()?;

        let bare_names: Vec<&str> = repos
            .iter()
            .map(|r| {
                if let Some((_owner, name)) = r.split_once('/') {
                    tracing::warn!(
                        repo = %r,
                        "get_github_token: stripping owner prefix from repository name"
                    );
                    name
                } else {
                    r.as_str()
                }
            })
            .collect();

        let body = serde_json::json!({
            "repositories": bare_names,
            "permissions": {
                "contents": "write",
                "pull_requests": "write"
            }
        });

        let url = format!(
            "https://api.github.com/app/installations/{}/access_tokens",
            self.installation_id
        );

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&jwt)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", "sandcastle")
            .json(&body)
            .send()
            .await
            .context("failed to contact GitHub API")?;

        let status = resp.status();
        if !status.is_success() {
            let body_text = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "GitHub API returned {}: {}",
                status.as_u16(),
                body_text
            ));
        }

        let data: serde_json::Value = resp
            .json()
            .await
            .context("failed to parse GitHub API response")?;

        let token = data["token"]
            .as_str()
            .ok_or_else(|| anyhow!("GitHub API response missing 'token' field"))?
            .to_string();

        let expires_at_str = data["expires_at"]
            .as_str()
            .ok_or_else(|| anyhow!("GitHub API response missing 'expires_at' field"))?;

        let expires_at = humantime::parse_rfc3339(expires_at_str)
            .with_context(|| format!("invalid expires_at from GitHub API: {expires_at_str}"))?;

        Ok(GitHubToken { token, expires_at })
    }

    fn make_jwt(&self) -> anyhow::Result<String> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before UNIX epoch")?
            .as_secs() as i64;

        let claims = AppClaims {
            iat: now - 60,
            exp: now + 600,
            iss: self.app_id.to_string(),
        };

        let key = EncodingKey::from_rsa_pem(self.private_key_pem.as_bytes())
            .context("failed to parse GITHUB_APP_PRIVATE_KEY as RSA PEM")?;

        encode(&Header::new(Algorithm::RS256), &claims, &key)
            .context("failed to sign GitHub App JWT")
    }
}
