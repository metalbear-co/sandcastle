use anyhow::Result;

use sandcastle_keychain::{StoredConfig, load_config, save_config};
use sandcastle_util::prompt;

const DEFAULT_BASE_URL: &str = "https://app.daytona.io/api";

pub struct DaytonaCreds {
    pub api_key: String,
    pub base_url: String,
}

pub fn load_daytona_creds(config: &StoredConfig) -> Result<DaytonaCreds> {
    // Env var override
    if let Ok(api_key) = std::env::var("DAYTONA_API_KEY") {
        let base_url = std::env::var("DAYTONA_BASE_URL")
            .unwrap_or_else(|_| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();
        return Ok(DaytonaCreds { api_key, base_url });
    }

    // Try keychain
    if let Some(api_key) = config.daytona_api_key.clone() {
        let base_url = config
            .daytona_base_url
            .clone()
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string())
            .trim_end_matches('/')
            .to_string();
        return Ok(DaytonaCreds { api_key, base_url });
    }

    // Run wizard
    run_wizard()
}

fn run_wizard() -> Result<DaytonaCreds> {
    eprintln!("\nSandcastle needs Daytona credentials to use the Daytona cloud sandbox provider.");
    eprintln!("You can find your API key at https://app.daytona.io/dashboard/keys\n");

    let api_key = loop {
        let k = prompt("  Enter your Daytona API key: ")?;
        if !k.is_empty() {
            break k;
        }
        eprintln!("  API key cannot be empty.");
    };

    let base_url_input = prompt(&format!(
        "  Enter Daytona base URL [default: {DEFAULT_BASE_URL}]: "
    ))?;
    let base_url = if base_url_input.is_empty() {
        DEFAULT_BASE_URL.to_string()
    } else {
        base_url_input
    };

    // Persist to keychain (best-effort)
    let mut config = load_config();
    config.daytona_api_key = Some(api_key.clone());
    config.daytona_base_url = Some(base_url.clone());
    if let Err(e) = save_config(&config) {
        eprintln!(
            "Warning: could not save to keychain ({e}). You will be prompted again next run."
        );
    } else {
        eprintln!("\nDaytona credentials saved to keychain.");
    }

    Ok(DaytonaCreds { api_key, base_url })
}
