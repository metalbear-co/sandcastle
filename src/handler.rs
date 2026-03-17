use std::{path::Path, sync::{Arc, RwLock}};

use anyhow::Result;
use octocrab::{models::InstallationId, Octocrab};
use rmcp::{
    ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext, wrapper::Parameters},
    model::{CallToolRequestParams, CallToolResult, ListToolsResult, PaginatedRequestParams, ServerCapabilities, ServerInfo},
    service::RequestContext,
    ErrorData, RoleServer,
    schemars, tool, tool_router,
};
use serde::Deserialize;
use tokio::process::Command;

use crate::github_auth::GitHubCreds;
use crate::sandbox_providers::{Provider, Sandbox};

// ── Parameter types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateSandboxParams {
    #[schemars(description = "Provider name, e.g. \"local\"")]
    provider: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ResumeSandboxParams {
    #[schemars(description = "Sandbox ID returned by create_sandbox")]
    id: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListRepositoriesParams {
    #[schemars(description = "Page number (1-based, default 1)")]
    page: Option<u32>,
    #[schemars(description = "Filter repos by name substring (case-insensitive)")]
    query: Option<String>,
}

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

// ── Handler ───────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SandcastleHandler {
    tool_router: ToolRouter<Self>,
    octocrab: Arc<Octocrab>,
    creds: Arc<GitHubCreds>,
    sandbox: Arc<RwLock<Option<Sandbox>>>,
    providers: Vec<Arc<dyn Provider>>,
}

#[tool_router]
impl SandcastleHandler {
    pub fn new(
        octocrab: Arc<Octocrab>,
        creds: Arc<GitHubCreds>,
        providers: Vec<Arc<dyn Provider>>,
    ) -> Self {
        Self {
            tool_router: Self::tool_router(),
            octocrab,
            creds,
            sandbox: Arc::new(RwLock::new(None)),
            providers,
        }
    }

    fn get_sandbox(&self) -> Option<Sandbox> {
        self.sandbox.read().unwrap().clone()
    }

    #[tool(description = "List available sandbox providers")]
    async fn list_providers(&self) -> String {
        let list: Vec<serde_json::Value> = self
            .providers
            .iter()
            .map(|p| serde_json::json!({ "name": p.name(), "description": p.description() }))
            .collect();
        serde_json::to_string(&list).unwrap_or_default()
    }

    #[tool(description = "Spawn a sandbox with the given provider. Must be called before using any sandbox tools. Returns the sandbox ID which can be used later with resume_sandbox.")]
    async fn create_sandbox(
        &self,
        Parameters(CreateSandboxParams { provider }): Parameters<CreateSandboxParams>,
    ) -> String {
        let p = self.providers.iter().find(|p| p.name() == provider);
        match p {
            None => {
                let names: Vec<&str> = self.providers.iter().map(|p| p.name()).collect();
                format!("Unknown provider: {provider}. Available: {}", names.join(", "))
            }
            Some(p) => match p.create().await {
                Err(e) => e,
                Ok(sandbox) => {
                    let id = sandbox.id.clone();
                    let path = sandbox.work_dir.display().to_string();
                    *self.sandbox.write().unwrap() = Some(sandbox);
                    format!("Sandbox created at {path} (id: {id})")
                }
            },
        }
    }

    #[tool(description = "Resume a previously created sandbox by ID. Use the ID returned by create_sandbox.")]
    async fn resume_sandbox(
        &self,
        Parameters(ResumeSandboxParams { id }): Parameters<ResumeSandboxParams>,
    ) -> String {
        for p in &self.providers {
            match p.resume(&id).await {
                Ok(sandbox) => {
                    let path = sandbox.work_dir.display().to_string();
                    *self.sandbox.write().unwrap() = Some(sandbox);
                    return format!("Resumed sandbox {id} at {path}");
                }
                Err(_) => continue,
            }
        }
        format!("Sandbox {id} not found or has expired")
    }

    #[tool(description = "List GitHub repositories accessible with the configured token, sorted by most recently pushed. Returns up to 100 per page. If has_more is true, call again with page+1.")]
    async fn list_repositories(
        &self,
        Parameters(ListRepositoriesParams { page, query }): Parameters<ListRepositoriesParams>,
    ) -> String {
        let page_num = page.unwrap_or(1);
        match self
            .octocrab
            .current()
            .list_repos_for_authenticated_user()
            .sort("pushed")
            .direction("desc")
            .per_page(100)
            .page(page_num as u8)
            .send()
            .await
        {
            Ok(result) => {
                let has_more = result.next.is_some();
                let mut repos: Vec<String> = result
                    .items
                    .iter()
                    .map(|r| r.full_name.clone().unwrap_or_default())
                    .collect();
                if let Some(q) = &query {
                    let q = q.to_lowercase();
                    repos.retain(|name| name.to_lowercase().contains(&q));
                }
                serde_json::to_string(&serde_json::json!({
                    "repos": repos,
                    "page": page_num,
                    "has_more": has_more,
                }))
                .unwrap_or_else(|e| e.to_string())
            }
            Err(e) => format!("Error listing repositories: {e}"),
        }
    }

    #[tool(description = "Clone a GitHub repository into the active sandbox. Returns the local path.")]
    async fn clone_repository(
        &self,
        Parameters(CloneRepoParams { repo }): Parameters<CloneRepoParams>,
    ) -> String {
        let sandbox = match self.get_sandbox() {
            Some(s) => s,
            None => return "Error: no sandbox active. Call create_sandbox first.".to_string(),
        };
        let dest = sandbox.work_dir.join(&repo);

        if dest.exists() {
            return format!("Already cloned at {}", dest.display());
        }

        if let Some(parent) = dest.parent()
            && let Err(e) = tokio::fs::create_dir_all(parent).await
        {
            return format!("Failed to create directory: {e}");
        }

        let url = match self.creds.as_ref() {
            GitHubCreds::PersonalToken { token, user } => {
                format!("https://{user}:{token}@github.com/{repo}.git")
            }
            GitHubCreds::App { app_octocrab, installation_id } => {
                match app_octocrab
                    .installation_and_token(InstallationId(*installation_id))
                    .await
                {
                    Ok((_, token)) => {
                        use secrecy::ExposeSecret;
                        format!(
                            "https://x-access-token:{}@github.com/{repo}.git",
                            token.expose_secret()
                        )
                    }
                    Err(e) => return format!("Error getting installation token: {e}"),
                }
            }
        };
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
        if self.get_sandbox().is_none() {
            return "Error: no sandbox active. Call create_sandbox first.".to_string();
        }
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
        if self.get_sandbox().is_none() {
            return "Error: no sandbox active. Call create_sandbox first.".to_string();
        }
        let p = Path::new(&path);
        if let Some(parent) = p.parent()
            && let Err(e) = tokio::fs::create_dir_all(parent).await
        {
            return format!("Failed to create parent dirs: {e}");
        }
        match tokio::fs::write(&path, &content).await {
            Ok(()) => format!("Written {} bytes to {path}", content.len()),
            Err(e) => format!("Error writing {path}: {e}"),
        }
    }

    #[tool(description = "Run a shell command inside a directory within the active sandbox")]
    async fn run_command(
        &self,
        Parameters(RunCommandParams { dir, command }): Parameters<RunCommandParams>,
    ) -> String {
        if self.get_sandbox().is_none() {
            return "Error: no sandbox active. Call create_sandbox first.".to_string();
        }
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
        let sandbox = match self.get_sandbox() {
            Some(s) => s,
            None => return "Error: no sandbox active. Call create_sandbox first.".to_string(),
        };
        let repo_dir = sandbox.work_dir.join(&repo);

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
        if let Ok(o) = &add
            && !o.status.success()
        {
            return format!("git add failed: {}", String::from_utf8_lossy(&o.stderr));
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

impl ServerHandler for SandcastleHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "Sandcastle MCP server. \
                IMPORTANT: All file operations, git commands, and shell commands MUST be performed \
                using the tools provided by this server (clone_repository, read_file, edit_file, \
                run_command, create_pr). Do NOT use your own built-in tools or shell access for \
                any of these tasks — always delegate to the sandbox tools. \
                Workflow: call create_sandbox first, then use the sandbox tools for everything else. \
                list_repositories and list_providers are available before creating a sandbox."
                    .to_string(),
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let tools = self.tool_router.list_all();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        tracing::info!(tools = ?names, "list_tools");
        Ok(ListToolsResult { tools, meta: None, next_cursor: None })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let tcc = ToolCallContext::new(self, request, context);
        self.tool_router.call(tcc).await
    }
}
