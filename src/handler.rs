use std::{path::Path, sync::{Arc, RwLock}};

use anyhow::Result;
use octocrab::{models::InstallationId, Octocrab};
use regex::Regex;
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
use walkdir::WalkDir;

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
    #[schemars(description = "1-indexed line number to start reading from (default: 1)")]
    offset: Option<u32>,
    #[schemars(description = "Maximum number of lines to return (default: all)")]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WriteFileParams {
    #[schemars(description = "Absolute path to the file to create or overwrite")]
    path: String,
    #[schemars(description = "Content to write (replaces existing content)")]
    content: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EditFileParams {
    #[schemars(description = "Absolute path to the file to edit")]
    path: String,
    #[schemars(description = "Exact text to find — must appear exactly once in the file")]
    old_string: String,
    #[schemars(description = "Replacement text")]
    new_string: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GlobParams {
    #[schemars(description = "Glob pattern, e.g. \"**/*.rs\" or \"src/*.toml\"")]
    pattern: String,
    #[schemars(description = "Base directory to search from (default: sandbox work_dir)")]
    path: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GrepParams {
    #[schemars(description = "Regex pattern to search for")]
    pattern: String,
    #[schemars(description = "File or directory to search (default: sandbox work_dir)")]
    path: Option<String>,
    #[schemars(description = "Glob pattern to filter filenames, e.g. \"*.rs\"")]
    include: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RunCommandParams {
    #[schemars(description = "Shell command to execute (runs via sh -c)")]
    command: String,
    #[schemars(description = "Directory to run the command in (default: sandbox work_dir)")]
    dir: Option<String>,
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

    #[tool(description = "Read a file from the sandbox. Optionally specify offset (1-indexed start line) and limit (max lines) to read a range; line numbers are prefixed when a range is requested.")]
    async fn read_file(
        &self,
        Parameters(ReadFileParams { path, offset, limit }): Parameters<ReadFileParams>,
    ) -> String {
        if self.get_sandbox().is_none() {
            return "Error: no sandbox active. Call create_sandbox first.".to_string();
        }
        let content = match tokio::fs::read_to_string(&path).await {
            Ok(c) => c,
            Err(e) => return format!("Error reading {path}: {e}"),
        };

        if offset.is_none() && limit.is_none() {
            return content;
        }

        let lines: Vec<&str> = content.lines().collect();
        let total = lines.len();
        let start = (offset.unwrap_or(1).saturating_sub(1)) as usize;
        let start = start.min(total);
        let end = match limit {
            Some(n) => (start + n as usize).min(total),
            None => total,
        };

        lines[start..end]
            .iter()
            .enumerate()
            .map(|(i, line)| format!("{:>6}\t{line}", start + i + 1))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[tool(description = "Create or overwrite a file with the given content. Parent directories are created automatically.")]
    async fn write_file(
        &self,
        Parameters(WriteFileParams { path, content }): Parameters<WriteFileParams>,
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

    #[tool(description = "Edit a file by replacing an exact string. old_string must appear exactly once in the file; use more context if it matches multiple times.")]
    async fn edit_file(
        &self,
        Parameters(EditFileParams { path, old_string, new_string }): Parameters<EditFileParams>,
    ) -> String {
        if self.get_sandbox().is_none() {
            return "Error: no sandbox active. Call create_sandbox first.".to_string();
        }
        let content = match tokio::fs::read_to_string(&path).await {
            Ok(c) => c,
            Err(e) => return format!("Error reading {path}: {e}"),
        };
        let count = content.matches(old_string.as_str()).count();
        match count {
            0 => format!("Error: old_string not found in {path}"),
            1 => {
                let new_content = content.replacen(old_string.as_str(), new_string.as_str(), 1);
                match tokio::fs::write(&path, &new_content).await {
                    Ok(()) => format!("Edited {path}: replaced 1 occurrence"),
                    Err(e) => format!("Error writing {path}: {e}"),
                }
            }
            n => format!("Error: old_string matches {n} times in {path} — make it more specific"),
        }
    }

    #[tool(description = "Find files matching a glob pattern. Returns a JSON array of matching paths. Use ** for recursive matching, e.g. \"**/*.rs\".")]
    async fn glob(
        &self,
        Parameters(GlobParams { pattern, path }): Parameters<GlobParams>,
    ) -> String {
        let sandbox = match self.get_sandbox() {
            Some(s) => s,
            None => return "Error: no sandbox active. Call create_sandbox first.".to_string(),
        };
        let base = path.unwrap_or_else(|| sandbox.work_dir.display().to_string());
        let full_pattern = format!("{base}/{pattern}");

        let entries = match ::glob::glob(&full_pattern) {
            Ok(paths) => paths,
            Err(e) => return format!("Error: invalid glob pattern: {e}"),
        };

        let mut matches: Vec<String> = Vec::new();
        for entry in entries {
            match entry {
                Ok(p) => {
                    matches.push(p.display().to_string());
                    if matches.len() >= 1000 {
                        matches.push("... (truncated at 1000 results)".to_string());
                        break;
                    }
                }
                Err(_) => continue,
            }
        }
        serde_json::to_string(&matches).unwrap_or_default()
    }

    #[tool(description = "Search file contents using a regex pattern. Returns matching lines as \"path:line_num:content\". Optionally filter files by name pattern (include), e.g. \"*.rs\".")]
    async fn grep(
        &self,
        Parameters(GrepParams { pattern, path, include }): Parameters<GrepParams>,
    ) -> String {
        let sandbox = match self.get_sandbox() {
            Some(s) => s,
            None => return "Error: no sandbox active. Call create_sandbox first.".to_string(),
        };

        let re = match Regex::new(&pattern) {
            Ok(r) => r,
            Err(e) => return format!("Error: invalid regex pattern: {e}"),
        };

        let search_path = path.unwrap_or_else(|| sandbox.work_dir.display().to_string());
        let search_path = std::path::Path::new(&search_path);

        let files: Vec<std::path::PathBuf> = if search_path.is_file() {
            vec![search_path.to_path_buf()]
        } else {
            WalkDir::new(search_path)
                .into_iter()
                .filter_map(|e| e.ok())
                .filter(|e| e.file_type().is_file())
                .filter(|e| {
                    if let Some(ref inc) = include {
                        let filename = e.file_name().to_string_lossy();
                        ::glob::Pattern::new(inc)
                            .map(|p| p.matches(&filename))
                            .unwrap_or(false)
                    } else {
                        true
                    }
                })
                .map(|e| e.into_path())
                .collect()
        };

        let mut results: Vec<String> = Vec::new();
        let mut total = 0usize;
        'outer: for file in &files {
            let content = match std::fs::read_to_string(file) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for (line_num, line) in content.lines().enumerate() {
                if re.is_match(line) {
                    total += 1;
                    if results.len() < 100 {
                        results.push(format!("{}:{}:{}", file.display(), line_num + 1, line));
                    } else {
                        results.push(format!("... (truncated, {total}+ matches total)"));
                        break 'outer;
                    }
                }
            }
        }

        results.join("\n")
    }

    #[tool(description = "Run a shell command in the sandbox. dir defaults to the sandbox work directory if not specified.")]
    async fn run_command(
        &self,
        Parameters(RunCommandParams { command, dir }): Parameters<RunCommandParams>,
    ) -> String {
        let sandbox = match self.get_sandbox() {
            Some(s) => s,
            None => return "Error: no sandbox active. Call create_sandbox first.".to_string(),
        };
        let work_dir = dir.unwrap_or_else(|| sandbox.work_dir.display().to_string());
        match Command::new("sh")
            .arg("-c")
            .arg(&command)
            .current_dir(&work_dir)
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

        let checkout = Command::new("git")
            .args(["checkout", "-b", &branch])
            .current_dir(&repo_dir)
            .output()
            .await;
        if let Err(e) = checkout {
            return format!("Failed to create branch: {e}");
        }

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

        let parts: Vec<&str> = repo.splitn(2, '/').collect();
        if parts.len() != 2 {
            return format!("Invalid repo format (expected owner/repo): {repo}");
        }
        let (owner, repo_name) = (parts[0], parts[1]);

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
                using the tools provided by this server (clone_repository, read_file, write_file, \
                edit_file, glob, grep, run_command, create_pr). Do NOT use your own built-in tools \
                or shell access for any of these tasks — always delegate to the sandbox tools. \
                Workflow: call create_sandbox first, then use the sandbox tools for everything else. \
                list_repositories and list_providers are available before creating a sandbox. \
                \n\nTool reference:\
                \n- read_file(path, offset?, limit?): read a file; offset/limit for line ranges with line numbers\
                \n- write_file(path, content): create or overwrite a file\
                \n- edit_file(path, old_string, new_string): targeted search-replace within a file\
                \n- glob(pattern, path?): find files matching a glob pattern (e.g. **/*.rs)\
                \n- grep(pattern, path?, include?): search file contents with regex\
                \n- run_command(command, dir?): run a shell command (dir defaults to sandbox root)"
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
