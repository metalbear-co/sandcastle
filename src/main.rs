use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
    time::{Duration, Instant}
};

use anyhow::Result;
use axum::{
    extract::{Extension, Form, Query},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
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
    PathBuf::from("/tmp/sandcastle")
}

// ── Auth state ───────────────────────────────────────────────────────────────

#[allow(dead_code)]
struct PendingCode {
    created_at: Instant,
    redirect_uri: Option<String>,
    client_id: String,
}

struct AuthState {
    pending_codes: RwLock<HashMap<String, PendingCode>>,
    valid_tokens: RwLock<HashMap<String, String>>, // token -> client_id
    base_url: String,
    no_auth: bool,
}

type SharedAuthState = Arc<AuthState>;

fn generate_token() -> String {
    use std::io::Read;
    let mut f = std::fs::File::open("/dev/urandom").expect("cannot open /dev/urandom");
    let mut buf = [0u8; 32];
    f.read_exact(&mut buf).expect("cannot read /dev/urandom");
    buf.iter().map(|b| format!("{:02x}", b)).collect()
}

// ── Auth middleware ───────────────────────────────────────────────────────────

async fn require_auth(
    Extension(auth): Extension<SharedAuthState>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));

    if auth.no_auth
        || token
            .map(|t| auth.valid_tokens.read().unwrap().contains_key(t))
            .unwrap_or(false)
    {
        next.run(request).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(
                "WWW-Authenticate",
                format!(
                    "Bearer realm=\"{base}\", resource_metadata=\"{base}/.well-known/oauth-protected-resource\"",
                    base = auth.base_url
                ),
            )],
        )
            .into_response()
    }
}

// ── Auth endpoint parameter types ─────────────────────────────────────────────

#[derive(Deserialize)]
struct AuthorizeParams {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    #[allow(dead_code)]
    response_type: Option<String>,
    #[allow(dead_code)]
    code_challenge: Option<String>,
    #[allow(dead_code)]
    code_challenge_method: Option<String>,
}

#[derive(Deserialize)]
struct ApproveForm {
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
}

// Dynamic Client Registration request (RFC 7591) — we accept anything, assign a client_id
#[derive(Deserialize)]
struct RegisterRequest {
    client_name: Option<String>,
    redirect_uris: Option<Vec<String>>,
    // All other fields are accepted and silently ignored
}

#[derive(Deserialize)]
struct TokenRequest {
    #[allow(dead_code)]
    grant_type: Option<String>,
    code: String,
    #[allow(dead_code)]
    redirect_uri: Option<String>,
    #[allow(dead_code)]
    client_id: Option<String>,
    #[allow(dead_code)]
    code_verifier: Option<String>,
}

// ── Auth handlers ─────────────────────────────────────────────────────────────

async fn oauth_protected_resource(
    Extension(auth): Extension<SharedAuthState>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "resource": auth.base_url,
        "authorization_servers": [auth.base_url]
    }))
}

async fn oauth_authorization_server(
    Extension(auth): Extension<SharedAuthState>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "issuer": auth.base_url,
        "authorization_endpoint": format!("{}/authorize", auth.base_url),
        "token_endpoint": format!("{}/token", auth.base_url),
        "registration_endpoint": format!("{}/register", auth.base_url),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "client_id_metadata_document_supported": true
    }))
}

async fn authorize_page(
    Query(params): Query<AuthorizeParams>,
) -> impl IntoResponse {
    let client_id = params.client_id.unwrap_or_default();
    let redirect_uri = params.redirect_uri.unwrap_or_default();
    let state = params.state.unwrap_or_default();

    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <title>Sandcastle — MCP Access Request</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 480px; margin: 80px auto; padding: 0 16px; }}
    h2 {{ margin-bottom: 8px; }}
    p {{ color: #555; margin-bottom: 24px; }}
    button {{ background: #1a1a1a; color: #fff; border: none; padding: 10px 20px;
              font-size: 15px; border-radius: 6px; cursor: pointer; }}
    button:hover {{ background: #333; }}
    code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
  </style>
</head>
<body>
  <h2>MCP Access Request</h2>
  <p>Client <code>{client_id}</code> is requesting access to this Sandcastle MCP server.</p>
  <form method="POST" action="/authorize/approve">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="state" value="{state}">
    <button type="submit">Approve Access</button>
  </form>
</body>
</html>"#
    );

    (StatusCode::OK, [("Content-Type", "text/html")], html)
}

async fn authorize_approve(
    Extension(auth): Extension<SharedAuthState>,
    Form(form): Form<ApproveForm>,
) -> impl IntoResponse {
    let code = generate_token();
    let client_id = form.client_id.clone().unwrap_or_default();
    let redirect_uri = form.redirect_uri.clone();

    {
        let mut codes = auth.pending_codes.write().unwrap();
        codes.insert(
            code.clone(),
            PendingCode {
                created_at: Instant::now(),
                redirect_uri: redirect_uri.clone(),
                client_id: client_id.clone(),
            },
        );
    }

    let base_redirect = redirect_uri.unwrap_or_else(|| format!("{}/", auth.base_url));
    let location = if let Some(s) = &form.state {
        format!("{base_redirect}?code={code}&state={s}")
    } else {
        format!("{base_redirect}?code={code}")
    };

    (StatusCode::FOUND, [("Location", location)])
}

async fn token_endpoint(
    Extension(auth): Extension<SharedAuthState>,
    Form(req): Form<TokenRequest>,
) -> impl IntoResponse {
    let code_data = {
        let mut codes = auth.pending_codes.write().unwrap();
        codes.remove(&req.code)
    };

    match code_data {
        None => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Code not found or already used"
            })),
        ),
        Some(c) if c.created_at.elapsed() > Duration::from_secs(300) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Code expired"
            })),
        ),
        Some(c) => {
            let token = generate_token();
            auth.valid_tokens
                .write()
                .unwrap()
                .insert(token.clone(), c.client_id.clone());
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "access_token": token,
                    "token_type": "Bearer"
                })),
            )
        }
    }
}

// Dynamic Client Registration (RFC 7591) — accept any client, assign a client_id
async fn register_client(
    axum::extract::Json(req): axum::extract::Json<RegisterRequest>,
) -> impl IntoResponse {
    let client_id = generate_token();
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "client_id": client_id,
            "client_name": req.client_name.unwrap_or_else(|| "MCP Client".to_string()),
            "redirect_uris": req.redirect_uris.unwrap_or_default(),
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        })),
    )
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

    #[tool(description = "Clone a GitHub repository to /tmp/sandcastle/<repo>. Returns the local path.")]
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
            vec!["config", "user.email", "sandcastle@localhost"],
            vec!["config", "user.name", "sandcastle"],
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

// ── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stdout)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("sandcastle=info")),
        )
        .init();

    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);

    let base_url = std::env::var("BASE_URL")
        .unwrap_or_else(|_| format!("http://localhost:{port}"));

    let no_auth = std::env::var("SANDCASTLE_NO_AUTH").is_ok();

    // Build auth state
    let auth_state: SharedAuthState = Arc::new(AuthState {
        pending_codes: RwLock::new(HashMap::new()),
        valid_tokens: RwLock::new(HashMap::new()),
        base_url: base_url.clone(),
        no_auth,
    });

    if no_auth {
        info!("auth: disabled (SANDCASTLE_NO_AUTH is set)");
    } else if let Ok(token) = std::env::var("MCP_TOKEN") {
        auth_state
            .valid_tokens
            .write()
            .unwrap()
            .insert(token, "env".to_string());
        info!("auth: using pre-shared token from MCP_TOKEN");
    } else {
        info!("auth: open {base_url}/authorize to approve MCP access");
    }

    let service = StreamableHttpService::new(
        || Ok(GithubManager::new()),
        LocalSessionManager::default().into(),
        Default::default(),
    );

    // route_layer applies middleware only to routes defined before it,
    // so /authorize, /token, and /.well-known/* remain unauthenticated.
    let app = Router::new()
        .route_service("/", service)
        .route_layer(middleware::from_fn(require_auth))
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_authorization_server),
        )
        .route("/authorize", get(authorize_page))
        .route("/authorize/approve", post(authorize_approve))
        .route("/token", post(token_endpoint))
        .route("/register", post(register_client))
        .layer(Extension(auth_state))
        .layer(CorsLayer::permissive());

    let addr = format!("0.0.0.0:{port}");
    info!("sandcastle listening on {addr}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to install SIGTERM handler");

    tokio::select! {
        _ = axum::serve(listener, app) => {}
        _ = sigterm.recv() => { info!("received SIGTERM, shutting down"); }
        _ = tokio::signal::ctrl_c() => { info!("received SIGINT, shutting down"); }
    }

    Ok(())
}
