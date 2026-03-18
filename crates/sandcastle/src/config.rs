use std::io::{self, Write};
use std::path::PathBuf;

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub providers: Option<Vec<String>>,
}

struct ProviderMeta {
    id: &'static str,
    label: &'static str,
    warning: Option<&'static str>,
}

const PROVIDERS: &[ProviderMeta] = &[
    ProviderMeta {
        id: "docker",
        label: "Docker sandbox — commands run in isolated containers",
        warning: None,
    },
    ProviderMeta {
        id: "daytona",
        label: "Daytona cloud sandbox — managed remote containers",
        warning: None,
    },
    ProviderMeta {
        id: "local",
        label: "Local sandbox — runs directly on this machine",
        warning: Some(
            "WARNING! This is not a real sandbox, should be used only if you know what you're doing",
        ),
    },
];

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

fn save_app_config(config: &AppConfig) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let data = serde_json::to_string_pretty(config)?;
    std::fs::write(&path, data)?;
    Ok(())
}

pub fn load_provider_selection() -> Result<Vec<String>> {
    let config = load_app_config();
    if let Some(providers) = config.providers
        && !providers.is_empty()
    {
        return Ok(providers);
    }
    let selected = wizard_provider_selection()?;
    save_app_config(&AppConfig {
        providers: Some(selected.clone()),
    })?;
    Ok(selected)
}

fn wizard_provider_selection() -> Result<Vec<String>> {
    println!("\nWhich sandbox providers do you want to enable?\n");
    for (i, p) in PROVIDERS.iter().enumerate() {
        println!("  {}) {}  — {}", i + 1, p.id, p.label);
        if let Some(w) = p.warning {
            println!("             ⚠ {w}");
        }
    }
    println!("\nEnter numbers separated by spaces (default: 1): ");

    loop {
        print!("> ");
        io::stdout().flush()?;

        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let line = line.trim();

        if line.is_empty() {
            return Ok(vec!["docker".to_string()]);
        }

        let mut selected = Vec::new();
        let mut valid = true;
        for part in line.split_whitespace() {
            match part.parse::<usize>() {
                Ok(n) if n >= 1 && n <= PROVIDERS.len() => {
                    selected.push(PROVIDERS[n - 1].id.to_string());
                }
                _ => {
                    println!(
                        "Invalid selection '{part}'. Enter numbers between 1 and {}.",
                        PROVIDERS.len()
                    );
                    valid = false;
                    break;
                }
            }
        }

        if !valid {
            continue;
        }
        if selected.is_empty() {
            println!("Please select at least one provider.");
            continue;
        }

        return Ok(selected);
    }
}
