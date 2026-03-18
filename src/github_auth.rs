use std::io::{self, BufRead, Write};
use std::sync::Arc;

use anyhow::{Context, Result};
use jsonwebtoken::EncodingKey;
use octocrab::{
    Octocrab,
    models::{AppId, InstallationId},
};

const SERVICE: &str = "sandcastle";

fn keychain_set(key: &str, value: &str) -> Result<()> {
    keyring::Entry::new(SERVICE, key)
        .map_err(|e| anyhow::anyhow!("keychain entry error for '{key}': {e}"))?
        .set_password(value)
        .map_err(|e| anyhow::anyhow!("keychain write error for '{key}': {e}"))
}

fn keychain_get_optional(key: &str) -> Result<Option<String>> {
    match keyring::Entry::new(SERVICE, key)
        .map_err(|e| anyhow::anyhow!("keychain entry error: {e}"))?
        .get_password()
    {
        Ok(v) => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("keychain read error for '{key}': {e}")),
    }
}

fn keychain_get(key: &str) -> Result<String> {
    keychain_get_optional(key)?.ok_or_else(|| anyhow::anyhow!("'{key}' not found in keychain"))
}

pub enum GitHubCreds {
    PersonalToken {
        token: String,
        user: String,
    },
    App {
        app_octocrab: Arc<Octocrab>,
        installation_id: u64,
    },
}

pub fn load_github_creds() -> Result<(Arc<Octocrab>, GitHubCreds)> {
    // Env var override for CI/scripted use
    if let (Ok(token), Ok(user)) = (std::env::var("GITHUB_TOKEN"), std::env::var("GITHUB_USER")) {
        let oct = Octocrab::builder()
            .personal_token(token.clone())
            .build()
            .context("failed to build Octocrab client")?;
        return Ok((Arc::new(oct), GitHubCreds::PersonalToken { token, user }));
    }

    // Try keychain
    match load_from_keychain() {
        Ok(Some(result)) => return Ok(result),
        Ok(None) => {}
        Err(e) => eprintln!("Warning: could not read credentials from keychain: {e:#}"),
    }

    // Run wizard — returns creds directly (also persists to keychain for future runs)
    run_wizard()
}

pub fn load_sandcastle_password() -> Result<Option<String>> {
    // Env var override
    if let Ok(pw) = std::env::var("SANDCASTLE_PASSWORD") {
        return Ok(Some(pw));
    }

    // Try keychain
    if let Some(pw) = keychain_get_optional("sandcastle_password")? {
        return Ok(Some(pw));
    }

    // Prompt user
    eprintln!("\nNo approval password is configured for the MCP authorization page.");
    eprintln!("  1) Generate a random password (recommended)");
    eprintln!("  2) Enter my own password");
    eprintln!("  3) Skip (no password required — anyone who can reach the server can approve)");
    eprintln!();

    let choice = loop {
        let c = prompt("Choice [1/2/3]: ")?;
        match c.as_str() {
            "1" | "2" | "3" => break c,
            _ => eprintln!("Please enter 1, 2, or 3."),
        }
    };

    match choice.as_str() {
        "1" => {
            let pw = generate_password();
            eprintln!("\nGenerated password: {pw}");
            eprintln!("(stored in keychain — shown only once)\n");
            keychain_set("sandcastle_password", &pw)?;
            Ok(Some(pw))
        }
        "2" => {
            let pw = loop {
                let p = prompt("  Password: ")?;
                if p.is_empty() {
                    eprintln!("  Password cannot be empty.");
                } else {
                    break p;
                }
            };
            keychain_set("sandcastle_password", &pw)?;
            Ok(Some(pw))
        }
        "3" => Ok(None),
        _ => unreachable!(),
    }
}

fn generate_password() -> String {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("cannot open /dev/urandom");
    let mut buf = [0u8; 15];
    f.read_exact(&mut buf).expect("cannot read /dev/urandom");
    // base64-like: use URL-safe chars (a-z, A-Z, 0-9, -, _) for 20-char password
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_";
    buf.iter()
        .flat_map(|&b| {
            // split each byte into two 4-bit nibbles → index into 64-char alphabet
            [
                ALPHABET[(b >> 4) as usize] as char,
                ALPHABET[(b & 0xf) as usize] as char,
            ]
        })
        .collect()
}

fn load_from_keychain() -> Result<Option<(Arc<Octocrab>, GitHubCreds)>> {
    let auth_mode = match keychain_get_optional("auth_mode")? {
        Some(v) => v,
        None => return Ok(None),
    };

    match auth_mode.as_str() {
        "personal_token" => {
            let token = keychain_get("github_token")?;
            let user = keychain_get("github_user")?;
            let oct = Octocrab::builder()
                .personal_token(token.clone())
                .build()
                .context("failed to build Octocrab client")?;
            Ok(Some((
                Arc::new(oct),
                GitHubCreds::PersonalToken { token, user },
            )))
        }
        "github_app" => {
            let app_id: u64 = keychain_get("github_app_id")?
                .parse()
                .context("invalid app_id in keychain")?;
            let installation_id: u64 = keychain_get("github_app_installation_id")?
                .parse()
                .context("invalid installation_id in keychain")?;
            let private_key = keychain_get("github_app_private_key")?;

            let key = EncodingKey::from_rsa_pem(private_key.as_bytes())
                .context("invalid private key PEM in keychain")?;

            let app_oct = Octocrab::builder()
                .app(AppId(app_id), key)
                .build()
                .context("failed to build app Octocrab client")?;

            let inst_oct = app_oct
                .installation(InstallationId(installation_id))
                .context("failed to create installation client")?;

            Ok(Some((
                Arc::new(inst_oct),
                GitHubCreds::App {
                    app_octocrab: Arc::new(app_oct),
                    installation_id,
                },
            )))
        }
        other => anyhow::bail!("unknown auth_mode in keychain: {other}"),
    }
}

fn prompt(msg: &str) -> Result<String> {
    eprint!("{msg}");
    io::stderr().flush()?;
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;
    Ok(line
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .trim()
        .to_string())
}

fn run_wizard() -> Result<(Arc<Octocrab>, GitHubCreds)> {
    eprintln!("\nSandcastle needs GitHub credentials. Choose an auth method:\n");
    eprintln!("  1) Personal access token  (simple, tied to your user account)");
    eprintln!("  2) GitHub App             (recommended for production, uses short-lived tokens)");
    eprintln!();

    let choice = loop {
        let c = prompt("Choice [1/2]: ")?;
        match c.as_str() {
            "1" | "2" => break c,
            _ => eprintln!("Please enter 1 or 2."),
        }
    };

    match choice.as_str() {
        "1" => wizard_personal_token(),
        "2" => wizard_github_app(),
        _ => unreachable!(),
    }
}

fn wizard_personal_token() -> Result<(Arc<Octocrab>, GitHubCreds)> {
    eprintln!();
    let token = prompt(
        "  Enter your GitHub personal access token (needs repo + workflow scopes):\n  Token: ",
    )?;
    if token.is_empty() {
        anyhow::bail!("token cannot be empty");
    }
    let user = prompt("  Enter your GitHub username:\n  Username: ")?;
    if user.is_empty() {
        anyhow::bail!("username cannot be empty");
    }

    // Persist to keychain (best-effort — warn but don't fail if keychain is unavailable)
    if let Err(e) = (|| -> Result<()> {
        keychain_set("github_token", &token)?;
        keychain_set("github_user", &user)?;
        keychain_set("auth_mode", "personal_token")
    })() {
        eprintln!(
            "Warning: could not save to keychain ({e}). You will be prompted again next run."
        );
    } else {
        eprintln!("\nCredentials saved to keychain.");
    }

    let oct = Octocrab::builder()
        .personal_token(token.clone())
        .build()
        .context("failed to build Octocrab client")?;

    Ok((Arc::new(oct), GitHubCreds::PersonalToken { token, user }))
}

fn wizard_github_app() -> Result<(Arc<Octocrab>, GitHubCreds)> {
    eprintln!();
    eprintln!("  To create a GitHub App:");
    eprintln!("    1. Go to https://github.com/settings/apps/new");
    eprintln!("    2. Name it, set Homepage URL to anything");
    eprintln!("    3. Permissions: Contents (R/W), Pull requests (R/W), Metadata (Read)");
    eprintln!("    4. Create it — note the App ID at the top of the settings page");
    eprintln!("    5. Scroll down → Generate a private key (.pem file download)");
    eprintln!("    6. Install the app: https://github.com/settings/installations");
    eprintln!("       (click the installed app — the Installation ID is in the URL)");
    eprintln!();

    let app_id_str = loop {
        let s = prompt("  Enter App ID: ")?;
        match s.parse::<u64>() {
            Ok(_) => break s,
            Err(_) => eprintln!("  App ID must be a number, please try again."),
        }
    };
    let app_id: u64 = app_id_str.parse().unwrap();

    let installation_id_str = loop {
        let s = prompt("  Enter Installation ID: ")?;
        match s.parse::<u64>() {
            Ok(_) => break s,
            Err(_) => eprintln!("  Installation ID must be a number, please try again."),
        }
    };
    let installation_id: u64 = installation_id_str.parse().unwrap();

    eprintln!("  Paste private key PEM (all lines; press Enter on an empty line to finish):");
    let (pem, key) = loop {
        let mut lines: Vec<String> = Vec::new();
        loop {
            let mut line = String::new();
            io::stdin().lock().read_line(&mut line)?;
            let line = line
                .trim_end_matches('\n')
                .trim_end_matches('\r')
                .to_string();
            let done =
                line == "-----END RSA PRIVATE KEY-----" || line == "-----END PRIVATE KEY-----";
            lines.push(line);
            if done {
                break;
            }
        }
        let pem = lines.join("\n");
        match EncodingKey::from_rsa_pem(pem.as_bytes()) {
            Ok(key) => break (pem, key),
            Err(e) => eprintln!("  Invalid PEM ({e}). Please paste again:"),
        }
    };

    // Persist to keychain (best-effort)
    if let Err(e) = (|| -> Result<()> {
        keychain_set("github_app_id", &app_id_str)?;
        keychain_set("github_app_installation_id", &installation_id_str)?;
        keychain_set("github_app_private_key", &pem)?;
        keychain_set("auth_mode", "github_app")
    })() {
        eprintln!(
            "Warning: could not save to keychain ({e}). You will be prompted again next run."
        );
    } else {
        eprintln!("\nApp credentials saved to keychain.");
    }

    let app_oct = Octocrab::builder()
        .app(AppId(app_id), key)
        .build()
        .context("failed to build app Octocrab client")?;

    let inst_oct = app_oct
        .installation(InstallationId(installation_id))
        .context("failed to create installation client")?;

    Ok((
        Arc::new(inst_oct),
        GitHubCreds::App {
            app_octocrab: Arc::new(app_oct),
            installation_id,
        },
    ))
}
