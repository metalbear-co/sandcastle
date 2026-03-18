use std::collections::HashMap;

use anyhow::Result;
use serde::{Deserialize, Serialize};

const SERVICE: &str = "sandcastle";
const KEY: &str = "config";

#[derive(Serialize, Deserialize, Default)]
pub struct StoredConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_app_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_app_installation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_app_private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandcastle_password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daytona_api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub daytona_base_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_tokens: Option<HashMap<String, String>>,
}

/// Load the stored config from the keychain. Returns a default (empty) config on any error.
pub fn load_config() -> StoredConfig {
    let entry = match keyring::Entry::new(SERVICE, KEY) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!("keychain: could not open config entry: {e}");
            return StoredConfig::default();
        }
    };
    match entry.get_password() {
        Ok(json) => serde_json::from_str(&json).unwrap_or_else(|e| {
            tracing::warn!("keychain: config JSON corrupt, starting fresh: {e}");
            StoredConfig::default()
        }),
        Err(keyring::Error::NoEntry) => StoredConfig::default(),
        Err(e) => {
            tracing::warn!("keychain: could not read config: {e}");
            StoredConfig::default()
        }
    }
}

/// Persist the config to the keychain.
pub fn save_config(config: &StoredConfig) -> Result<()> {
    let json = serde_json::to_string(config)?;
    keyring::Entry::new(SERVICE, KEY)
        .map_err(|e| anyhow::anyhow!("keychain entry error: {e}"))?
        .set_password(&json)
        .map_err(|e| anyhow::anyhow!("keychain write error: {e}"))
}
