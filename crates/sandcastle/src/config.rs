use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub providers: Option<Vec<String>>,
}

fn config_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(home).join(".sandcastle").join("config.json")
}

fn load_app_config() -> AppConfig {
    let path = config_path();
    let Ok(data) = std::fs::read_to_string(&path) else {
        return AppConfig::default();
    };
    serde_json::from_str(&data).unwrap_or_default()
}

pub fn load_provider_selection() -> Result<Vec<String>> {
    let config = load_app_config();
    if let Some(providers) = config.providers
        && !providers.is_empty()
    {
        return Ok(providers);
    }
    Ok(vec!["local".to_string()])
}
