use async_trait::async_trait;
use sandcastle_auth_core::AuthProvider;

pub struct GitHubAuthProvider {
    pub client_id: String,
    pub client_secret: String,
}

impl GitHubAuthProvider {
    pub fn from_env() -> anyhow::Result<Self> {
        Ok(Self {
            client_id: std::env::var("GITHUB_OAUTH_CLIENT_ID").map_err(|_| {
                anyhow::anyhow!("GITHUB_OAUTH_CLIENT_ID is required for AUTH_PROVIDER=github")
            })?,
            client_secret: std::env::var("GITHUB_OAUTH_CLIENT_SECRET").map_err(|_| {
                anyhow::anyhow!("GITHUB_OAUTH_CLIENT_SECRET is required for AUTH_PROVIDER=github")
            })?,
        })
    }
}

#[async_trait]
impl AuthProvider for GitHubAuthProvider {
    fn name(&self) -> &'static str {
        "github"
    }

    fn redirect_url(&self, callback_url: &str, state: &str) -> Option<String> {
        let mut url = reqwest::Url::parse("https://github.com/login/oauth/authorize")
            .expect("static URL is valid");
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", callback_url)
            .append_pair("scope", "read:user")
            .append_pair("state", state);
        Some(url.to_string())
    }

    async fn exchange_code(&self, code: &str, callback_url: &str) -> Result<String, String> {
        let client = reqwest::Client::new();

        let resp = client
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", code),
                ("redirect_uri", callback_url),
            ])
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        let access_token = body["access_token"]
            .as_str()
            .ok_or_else(|| format!("no access_token in response: {body}"))?
            .to_string();

        let user_resp = client
            .get("https://api.github.com/user")
            .header("Authorization", format!("Bearer {access_token}"))
            .header("User-Agent", "sandcastle")
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let user: serde_json::Value = user_resp.json().await.map_err(|e| e.to_string())?;
        let id = user["id"]
            .as_i64()
            .ok_or_else(|| format!("no id in user response: {user}"))?;

        Ok(format!("github:{id}"))
    }

    fn check_password(&self, _provided: &str) -> bool {
        true
    }

    fn needs_password(&self) -> bool {
        false
    }
}
