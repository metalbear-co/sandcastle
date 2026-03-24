use std::sync::Arc;

use anyhow::{Context, Result};
use jsonwebtoken::EncodingKey;
use octocrab::{
    Octocrab,
    models::{AppId, InstallationId},
};

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
    if let (Ok(token), Ok(user)) = (std::env::var("GITHUB_TOKEN"), std::env::var("GITHUB_USER")) {
        let oct = Octocrab::builder()
            .personal_token(token.clone())
            .build()
            .context("failed to build Octocrab client")?;
        return Ok((Arc::new(oct), GitHubCreds::PersonalToken { token, user }));
    }

    if let (Ok(app_id_str), Ok(installation_id_str), Ok(private_key)) = (
        std::env::var("GITHUB_APP_ID"),
        std::env::var("GITHUB_APP_INSTALLATION_ID"),
        std::env::var("GITHUB_APP_PRIVATE_KEY"),
    ) {
        let app_id: u64 = app_id_str.parse().context("invalid GITHUB_APP_ID")?;
        let installation_id: u64 = installation_id_str
            .parse()
            .context("invalid GITHUB_APP_INSTALLATION_ID")?;
        let key = EncodingKey::from_rsa_pem(private_key.as_bytes())
            .context("invalid GITHUB_APP_PRIVATE_KEY PEM")?;
        let app_oct = Octocrab::builder()
            .app(AppId(app_id), key)
            .build()
            .context("failed to build app Octocrab client")?;
        let inst_oct = app_oct
            .installation(InstallationId(installation_id))
            .context("failed to create installation client")?;
        return Ok((
            Arc::new(inst_oct),
            GitHubCreds::App {
                app_octocrab: Arc::new(app_oct),
                installation_id,
            },
        ));
    }

    anyhow::bail!(
        "GitHub credentials not configured. Set GITHUB_TOKEN + GITHUB_USER, \
         or GITHUB_APP_ID + GITHUB_APP_INSTALLATION_ID + GITHUB_APP_PRIVATE_KEY."
    )
}

/// Returns the approval password from SANDCASTLE_PASSWORD, or None if unset.
pub fn load_sandcastle_password() -> Option<String> {
    std::env::var("SANDCASTLE_PASSWORD").ok()
}
