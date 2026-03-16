use std::{path::Path, sync::{Arc, RwLock}};

use anyhow::Result;
use octocrab::Octocrab;
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

use crate::sandbox_providers::{local::LocalProvider, Provider, Sandbox, ROOT_TOOLS};

fn github_token() -> String {
    std::env::var("GITHUB_TOKEN").expect("GITHUB_TOKEN must be set")
}

fn github_user() -> String {
    std::env::var("GITHUB_USER").expect("GITHUB_USER must be set")
}

fn providers() -> Vec<Box<dyn Provider>> {
    vec![Box::new(LocalProvider)]
}

// ── Parameter types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateSandboxParams {
    #[schemars(description = "Provider name, e.g. \"local\"")]
    provider: String,
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
    sandbox: Arc<RwLock<Option<Sandbox>>>,
}

#[tool_router]
impl SandcastleHandler {
    pub fn new() -> Self {
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
            sandbox: Arc::new(RwLock::new(None)),
        }
    }

    fn get_sandbox(&self) -> Option<Sandbox> {
        self.sandbox.read().unwrap().clone()
    }

    #[tool(description = "List available sandbox providers")]
    async fn list_providers(&self) -> String {
        let list: Vec<serde_json::Value> = providers()
            .iter()
            .map(|p| serde_json::json!({ "name": p.name(), "description": p.description() }))
            .collect();
        serde_json::to_string(&list).unwrap_or_default()
    }

    #[tool(description = "Spawn a sandbox with the given provider. Must be called before using any sandbox tools.")]
    async fn create_sandbox(
        &self,
        Parameters(CreateSandboxParams { provider }): Parameters<CreateSandboxParams>,
    ) -> String {
        let all = providers();
        let p = all.iter().find(|p| p.name() == provider);
        match p {
            None => {
                let names: Vec<&str> = all.iter().map(|p| p.name()).collect();
                format!("Unknown provider: {provider}. Available: {}", names.join(", "))
            }
            Some(p) => match p.create().await {
                Err(e) => e,
                Ok(sandbox) => {
                    let path = sandbox.work_dir.display().to_string();
                    *self.sandbox.write().unwrap() = Some(sandbox);
                    format!("Sandbox created at {path}")
                }
            },
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

    #[tool(description = "Clone a GitHub repository into the active sandbox. Returns the local path.")]
    async fn clone_repository(
        &self,
        Parameters(CloneRepoParams { repo }): Parameters<CloneRepoParams>,
    ) -> String {
        let sandbox = match self.get_sandbox() {
            Some(s) => s,
            None => return "Error: no sandbox active. Call create_sandbox first.".to_string(),
        };
        let token = github_token();
        let user = github_user();
        let dest = sandbox.work_dir.join(&repo);

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

impl ServerHandler for SandcastleHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "Sandcastle MCP server. \
                Call list_providers to see available sandbox providers, \
                then create_sandbox to start a session. \
                list_repositories is available without a sandbox."
                    .to_string(),
            )
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        let mut tools = self.tool_router.list_all();
        if self.get_sandbox().is_none() {
            tools.retain(|t| ROOT_TOOLS.contains(&t.name.as_ref()));
        }
        Ok(ListToolsResult { tools, meta: None, next_cursor: None })
    }

    fn get_tool(&self, name: &str) -> Option<rmcp::model::Tool> {
        if self.get_sandbox().is_none() && !ROOT_TOOLS.contains(&name) {
            return None;
        }
        self.tool_router.get(name).cloned()
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
