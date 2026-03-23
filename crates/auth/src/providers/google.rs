use async_trait::async_trait;
use base64::Engine;

use crate::provider::AuthProvider;

pub struct GoogleAuthProvider {
    pub client_id: String,
    pub client_secret: String,
}

/// Decode the payload section of a JWT without verifying the signature.
/// Safe here because the token is obtained directly from Google over HTTPS.
fn decode_jwt_payload(token: &str) -> Result<serde_json::Value, String> {
    let payload_b64 = token
        .split('.')
        .nth(1)
        .ok_or("invalid JWT: expected at least 2 parts")?;
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload_b64))
        .map_err(|e| format!("failed to base64-decode JWT payload: {e}"))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("failed to parse JWT payload: {e}"))
}

#[async_trait]
impl AuthProvider for GoogleAuthProvider {
    fn name(&self) -> &'static str {
        "google"
    }

    fn redirect_url(&self, callback_url: &str, state: &str) -> Option<String> {
        let mut url = reqwest::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")
            .expect("static URL is valid");
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", callback_url)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid")
            .append_pair("state", state);
        Some(url.to_string())
    }

    async fn exchange_code(&self, code: &str, callback_url: &str) -> Result<String, String> {
        let client = reqwest::Client::new();

        let resp = client
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("code", code),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("redirect_uri", callback_url),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| e.to_string())?;

        let body: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        let id_token = body["id_token"]
            .as_str()
            .ok_or_else(|| format!("no id_token in response: {body}"))?;

        let claims = decode_jwt_payload(id_token)?;
        let sub = claims["sub"]
            .as_str()
            .ok_or_else(|| format!("no sub in id_token claims: {claims}"))?;

        Ok(format!("google:{sub}"))
    }

    fn check_password(&self, _provided: &str) -> bool {
        true
    }

    fn needs_password(&self) -> bool {
        false
    }
}
