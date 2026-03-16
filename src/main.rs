use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::Result;
use axum::{Router, http::StatusCode, response::IntoResponse, routing::get};
use octocrab::Octocrab;
use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
};
use rmcp::transport::streamable_http_server::{
    StreamableHttpService, session::local::LocalSessionManager,
};
use serde::Deserialize;
use tokio::process::Command;
use tower_http::cors::CorsLayer;
use tracing::info;

// ── Config ──────────────────────────────────────────────────────────────────

fn github_token() -> String {
    std::env::var("GITHUB_TOKEN").expect("GITHUB_TOKEN must be set")
}

fn github_user() -> String {
    std::env::var("GITHUB_USER").expect("GITHUB_USER must be set")
}

fn work_dir() -> PathBuf {
    PathBuf::from("/tmp/mamcp")
}

// ── Parameter types ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CloneRepoParams {
    #[schemars(description = "Owner/repo, e.g. \"octocat/Hello-World\"")]
    repo: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadFileParams {
    #[schemars(description = "Absolute path to the file to read")]
    path: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EditFileParams {
    #[schemars(description = "Absolute path to the file to write")]
    path: String,
    #[schemars(description = "New content to write (replaces existing content)")]
    content: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RunCommandParams {
    #[schemars(description = "Absolute path to the directory to run the command in")]
    dir: String,
    #[schemars(description = "Shell command to execute (runs via sh -c)")]
    command: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreatePrParams {
    #[schemars(description = "Owner/repo, e.g. \"octocat/Hello-World\"")]
    repo: String,
    #[schemars(description = "Name for the new branch")]
    branch: String,
    #[schemars(description = "Commit message")]
    commit_message: String,
    #[schemars(description = "PR title")]
    pr_title: String,
    #[schemars(description = "PR body / description")]
    pr_body: String,
}

// ── Server handler ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct GithubManager {
    tool_router: ToolRouter<Self>,
    octocrab: Arc<Octocrab>,
}

#[tool_router]
impl GithubManager {
    fn new() -> Self {
        let token = github_token();
        let octocrab = Arc::new(
            Octocrab::builder()
                .personal_token(token)
                .build()
                .expect("Failed to build Octocrab client"),
        );
        Self {
            tool_router: Self::tool_router(),
            octocrab,
        }
    }

    #[tool(description = "List GitHub repositories accessible with the configured token")]
    async fn list_repositories(&self) -> String {
        match self
            .octocrab
            .current()
            .list_repos_for_authenticated_user()
            .send()
            .await
        {
            Ok(page) => {
                let repos: Vec<String> = page
                    .items
                    .iter()
                    .map(|r| r.full_name.clone().unwrap_or_default())
                    .collect();
                serde_json::to_string(&repos).unwrap_or_else(|e| e.to_string())
            }
            Err(e) => format!("Error listing repositories: {e}"),
        }
    }

    #[tool(description = "Clone a GitHub repository to /tmp/mamcp/<repo>. Returns the local path.")]
    async fn clone_repository(
        &self,
        Parameters(CloneRepoParams { repo }): Parameters<CloneRepoParams>,
    ) -> String {
        let token = github_token();
        let user = github_user();
        let dest = work_dir().join(&repo);

        if dest.exists() {
            return format!("Already cloned at {}", dest.display());
        }

        if let Some(parent) = dest.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                return format!("Failed to create directory: {e}");
            }
        }

        let url = format!("https://{user}:{token}@github.com/{repo}.git");
        match Command::new("git")
            .args(["clone", &url, dest.to_str().unwrap()])
            .output()
            .await
        {
            Ok(o) if o.status.success() => format!("Cloned to {}", dest.display()),
            Ok(o) => format!("git clone failed: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => format!("Failed to run git: {e}"),
        }
    }

    #[tool(description = "Read a file from a cloned repository")]
    async fn read_file(
        &self,
        Parameters(ReadFileParams { path }): Parameters<ReadFileParams>,
    ) -> String {
        match tokio::fs::read_to_string(&path).await {
            Ok(content) => content,
            Err(e) => format!("Error reading {path}: {e}"),
        }
    }

    #[tool(description = "Write/replace the content of a file in a cloned repository")]
    async fn edit_file(
        &self,
        Parameters(EditFileParams { path, content }): Parameters<EditFileParams>,
    ) -> String {
        let p = Path::new(&path);
        if let Some(parent) = p.parent() {
            if let Err(e) = tokio::fs::create_dir_all(parent).await {
                return format!("Failed to create parent dirs: {e}");
            }
        }
        match tokio::fs::write(&path, &content).await {
            Ok(()) => format!("Written {} bytes to {path}", content.len()),
            Err(e) => format!("Error writing {path}: {e}"),
        }
    }

    #[tool(description = "Run a shell command inside a cloned repository directory")]
    async fn run_command(
        &self,
        Parameters(RunCommandParams { dir, command }): Parameters<RunCommandParams>,
    ) -> String {
        match Command::new("sh")
            .arg("-c")
            .arg(&command)
            .current_dir(&dir)
            .output()
            .await
        {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                let stderr = String::from_utf8_lossy(&o.stderr);
                format!(
                    "exit_code: {}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                    o.status.code().unwrap_or(-1)
                )
            }
            Err(e) => format!("Failed to run command: {e}"),
        }
    }

    #[tool(
        description = "Commit all changes in a cloned repo, push to a new branch, and open a GitHub PR"
    )]
    async fn create_pr(
        &self,
        Parameters(CreatePrParams {
            repo,
            branch,
            commit_message,
            pr_title,
            pr_body,
        }): Parameters<CreatePrParams>,
    ) -> String {
        let repo_dir = work_dir().join(&repo);

        // Configure git identity
        for args in &[
            vec!["config", "user.email", "mamcp@localhost"],
            vec!["config", "user.name", "mamcp"],
        ] {
            let _ = Command::new("git")
                .args(args)
                .current_dir(&repo_dir)
                .output()
                .await;
        }

        // Create and checkout branch
        let checkout = Command::new("git")
            .args(["checkout", "-b", &branch])
            .current_dir(&repo_dir)
            .output()
            .await;
        if let Err(e) = checkout {
            return format!("Failed to create branch: {e}");
        }

        // Stage all changes
        let add = Command::new("git")
            .args(["add", "-A"])
            .current_dir(&repo_dir)
            .output()
            .await;
        if let Ok(o) = &add {
            if !o.status.success() {
                return format!("git add failed: {}", String::from_utf8_lossy(&o.stderr));
            }
        }

        // Commit
        match Command::new("git")
            .args(["commit", "-m", &commit_message])
            .current_dir(&repo_dir)
            .output()
            .await
        {
            Ok(o) if !o.status.success() => {
                return format!(
                    "git commit failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            Err(e) => return format!("Failed to run git commit: {e}"),
            _ => {}
        }

        // Push
        match Command::new("git")
            .args(["push", "origin", &branch])
            .current_dir(&repo_dir)
            .output()
            .await
        {
            Ok(o) if !o.status.success() => {
                return format!(
                    "git push failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            Err(e) => return format!("Failed to run git push: {e}"),
            _ => {}
        }

        // Parse owner/repo
        let parts: Vec<&str> = repo.splitn(2, '/').collect();
        if parts.len() != 2 {
            return format!("Invalid repo format (expected owner/repo): {repo}");
        }
        let (owner, repo_name) = (parts[0], parts[1]);

        // Open PR via GitHub API
        match self
            .octocrab
            .pulls(owner, repo_name)
            .create(&pr_title, &branch, "main")
            .body(&pr_body)
            .send()
            .await
        {
            Ok(pr) => format!(
                "PR created: {}",
                pr.html_url
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "unknown URL".into())
            ),
            Err(e) => format!("Failed to create PR: {e}"),
        }
    }
}

#[tool_handler]
impl ServerHandler for GithubManager {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "GitHub repository manager: clone repos, read/edit files, run commands, open PRs"
                    .to_string(),
            )
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

async fn not_found() -> impl IntoResponse {
    StatusCode::NOT_FOUND
}

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("mamcp=info".parse().unwrap()),
        )
        .init();

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);

    let service = StreamableHttpService::new(
        || Ok(GithubManager::new()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    // Claude's MCP connector hits / for the protocol and also probes OAuth endpoints.
    // Returning 404 on oauth-protected-resource tells it no auth is required.
    // The MCP service itself must be at / (not /mcp).
    let app = Router::new()
        .route_service("/", service)
        .route("/.well-known/oauth-protected-resource", get(not_found))
        .route("/.well-known/oauth-authorization-server", get(not_found))
        .layer(CorsLayer::permissive());

    let addr = format!("0.0.0.0:{port}");
    info!("mamcp listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
