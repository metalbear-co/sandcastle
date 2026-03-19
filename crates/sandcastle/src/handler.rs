use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use anyhow::Result;
use octocrab::{Octocrab, models::InstallationId};
use rmcp::{
    ErrorData, RoleServer, ServerHandler,
    handler::server::{router::tool::ToolRouter, tool::ToolCallContext, wrapper::Parameters},
    model::{
        CallToolRequestParams, CallToolResult, ListToolsResult, PaginatedRequestParams,
        ServerCapabilities, ServerInfo,
    },
    schemars,
    service::RequestContext,
    tool, tool_router,
};
use serde::Deserialize;

use sandcastle_auth::RequestIdentity;
use sandcastle_auth::github_auth::GitHubCreds;
use sandcastle_sandbox_providers::{Provider, SandboxHandle};

// ── Parameter types ───────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreateSandboxParams {
    #[schemars(description = "Provider name, e.g. \"local\"")]
    provider: String,
    #[schemars(
        description = "A short descriptive name for this sandbox session, e.g. \"fix-auth-bug\" or \"add-dark-mode\". Choose something meaningful to the current task, or ask the user if nothing obvious applies."
    )]
    name: String,
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
    #[schemars(
        description = "Sandbox ID to operate on. Optional when this client has an active sandbox."
    )]
    sandbox_id: Option<String>,
    #[schemars(description = "Owner/repo, e.g. \"octocat/Hello-World\"")]
    repo: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ReadFileParams {
    #[schemars(
        description = "Sandbox ID to operate on. Optional when this client has an active sandbox."
    )]
    sandbox_id: Option<String>,
    #[schemars(description = "Absolute path to the file to read")]
    path: String,
    #[schemars(description = "1-indexed line number to start reading from (default: 1)")]
    offset: Option<u32>,
    #[schemars(description = "Maximum number of lines to return (default: all)")]
    limit: Option<u32>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct WriteFileParams {
    #[schemars(
        description = "Sandbox ID to operate on. Optional when this client has an active sandbox."
    )]
    sandbox_id: Option<String>,
    #[schemars(description = "Absolute path to the file to create or overwrite")]
    path: String,
    #[schemars(description = "Content to write (replaces existing content)")]
    content: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct EditFileParams {
    #[schemars(
        description = "Sandbox ID to operate on. Optional when this client has an active sandbox."
    )]
    sandbox_id: Option<String>,
    #[schemars(description = "Absolute path to the file to edit")]
    path: String,
    #[schemars(description = "Exact text to find — must appear exactly once in the file")]
    old_string: String,
    #[schemars(description = "Replacement text")]
    new_string: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GlobParams {
    #[schemars(
        description = "Sandbox ID to operate on. Optional when this client has an active sandbox."
    )]
    sandbox_id: Option<String>,
    #[schemars(description = "Glob pattern, e.g. \"**/*.rs\" or \"src/*.toml\"")]
    pattern: String,
    #[schemars(description = "Base directory to search from (default: sandbox work_dir)")]
    path: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct GrepParams {
    #[schemars(
        description = "Sandbox ID to operate on. Optional when this client has an active sandbox."
    )]
    sandbox_id: Option<String>,
    #[schemars(description = "Regex pattern to search for")]
    pattern: String,
    #[schemars(description = "File or directory to search (default: sandbox work_dir)")]
    path: Option<String>,
    #[schemars(description = "Glob pattern to filter filenames, e.g. \"*.rs\"")]
    include: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct RunCommandParams {
    #[schemars(
        description = "Sandbox ID to operate on. Optional when this client has an active sandbox."
    )]
    sandbox_id: Option<String>,
    #[schemars(description = "Shell command to execute (runs via sh -c)")]
    command: String,
    #[schemars(description = "Directory to run the command in (default: sandbox work_dir)")]
    dir: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct CreatePrParams {
    #[schemars(
        description = "Sandbox ID to operate on. Optional when this client has an active sandbox."
    )]
    sandbox_id: Option<String>,
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

#[derive(Default)]
pub struct SandboxRegistry {
    owners: RwLock<HashMap<String, String>>,
    active_by_owner: RwLock<HashMap<String, String>>,
}

#[derive(Clone)]
pub struct SandcastleHandler {
    tool_router: ToolRouter<Self>,
    octocrab: Option<Arc<Octocrab>>,
    creds: Option<Arc<GitHubCreds>>,
    sandbox_registry: Arc<SandboxRegistry>,
    providers: Vec<Arc<dyn Provider>>,
}

#[tool_router]
impl SandcastleHandler {
    pub fn new(
        octocrab: Option<Arc<Octocrab>>,
        creds: Option<Arc<GitHubCreds>>,
        sandbox_registry: Arc<SandboxRegistry>,
        providers: Vec<Arc<dyn Provider>>,
    ) -> Self {
        Self {
            tool_router: Self::tool_router(),
            octocrab,
            creds,
            sandbox_registry,
            providers,
        }
    }

    fn request_identity(ctx: &RequestContext<RoleServer>) -> RequestIdentity {
        ctx.extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<RequestIdentity>())
            .cloned()
            .unwrap_or_else(|| RequestIdentity {
                owner_key: "anonymous".to_string(),
                client_id: None,
            })
    }

    fn set_active_sandbox(&self, identity: &RequestIdentity, sandbox_id: &str) {
        self.sandbox_registry
            .owners
            .write()
            .unwrap()
            .insert(sandbox_id.to_string(), identity.owner_key.clone());
        self.sandbox_registry
            .active_by_owner
            .write()
            .unwrap()
            .insert(identity.owner_key.clone(), sandbox_id.to_string());
    }

    fn is_owned_by(&self, identity: &RequestIdentity, sandbox_id: &str) -> bool {
        self.sandbox_registry
            .owners
            .read()
            .unwrap()
            .get(sandbox_id)
            .is_some_and(|owner| owner == &identity.owner_key)
    }

    fn clear_sandbox_tracking(&self, sandbox_id: &str) {
        self.sandbox_registry
            .owners
            .write()
            .unwrap()
            .remove(sandbox_id);
        self.sandbox_registry
            .active_by_owner
            .write()
            .unwrap()
            .retain(|_, active_id| active_id != sandbox_id);
    }

    async fn resume_known_sandbox(&self, sandbox_id: &str) -> Result<SandboxHandle, String> {
        for p in &self.providers {
            if let Ok(handle) = p.resume(sandbox_id).await {
                return Ok(handle);
            }
        }
        self.clear_sandbox_tracking(sandbox_id);
        Err(format!("Sandbox {sandbox_id} not found or has expired"))
    }

    async fn resolve_sandbox(
        &self,
        identity: &RequestIdentity,
        sandbox_id: Option<&str>,
    ) -> Result<SandboxHandle, String> {
        let sandbox_id = match sandbox_id {
            Some(id) => id.to_string(),
            None => self
                .sandbox_registry
                .active_by_owner
                .read()
                .unwrap()
                .get(&identity.owner_key)
                .cloned()
                .ok_or_else(|| {
                    "Error: no sandbox active for this client. Call create_sandbox, \
                     resume_sandbox, or pass sandbox_id."
                        .to_string()
                })?,
        };

        if !self.is_owned_by(identity, &sandbox_id) {
            return Err(format!(
                "Error: sandbox {sandbox_id} is not accessible to this client."
            ));
        }

        self.resume_known_sandbox(&sandbox_id).await
    }

    fn github_enabled(&self) -> bool {
        self.octocrab.is_some() && self.creds.is_some()
    }

    fn github_disabled_message(tool: &str) -> String {
        format!(
            "Error: {tool} requires GitHub integration. Restart Sandcastle without SANDCASTLE_NO_GITHUB, or provide GitHub credentials."
        )
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

    #[tool(
        description = "Spawn a sandbox with the given provider. Must be called before using any sandbox tools. Returns the sandbox ID which can be used later with resume_sandbox."
    )]
    async fn create_sandbox(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(CreateSandboxParams { provider, name }): Parameters<CreateSandboxParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);
        let p = self.providers.iter().find(|p| p.name() == provider);
        match p {
            None => {
                let names: Vec<&str> = self.providers.iter().map(|p| p.name()).collect();
                format!(
                    "Unknown provider: {provider}. Available: {}",
                    names.join(", ")
                )
            }
            Some(p) => match p.create(name).await {
                Err(e) => e,
                Ok(handle) => {
                    let id = handle.id.clone();
                    let name = handle.name.clone();
                    let path = handle.work_dir.display().to_string();
                    self.set_active_sandbox(&identity, &id);
                    format!("Sandbox \"{name}\" created at {path} (id: {id})")
                }
            },
        }
    }

    #[tool(
        description = "Resume a previously created sandbox by ID. Use the ID returned by create_sandbox."
    )]
    async fn resume_sandbox(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(ResumeSandboxParams { id }): Parameters<ResumeSandboxParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);
        if !self.is_owned_by(&identity, &id) {
            return format!("Error: sandbox {id} is not accessible to this client.");
        }
        match self.resume_known_sandbox(&id).await {
            Ok(handle) => {
                let path = handle.work_dir.display().to_string();
                let name = handle.name.clone();
                self.set_active_sandbox(&identity, &id);
                format!("Resumed sandbox \"{name}\" ({id}) at {path}")
            }
            Err(e) => e,
        }
    }

    #[tool(
        description = "List GitHub repositories accessible with the configured token, sorted by most recently pushed. Returns up to 100 per page. If has_more is true, call again with page+1."
    )]
    async fn list_repositories(
        &self,
        Parameters(ListRepositoriesParams { page, query }): Parameters<ListRepositoriesParams>,
    ) -> String {
        let Some(octocrab) = &self.octocrab else {
            return Self::github_disabled_message("list_repositories");
        };
        let page_num = page.unwrap_or(1);
        match octocrab
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

    #[tool(
        description = "Clone a GitHub repository into a sandbox. Pass sandbox_id when working with multiple sandboxes or clients. Returns the local path."
    )]
    async fn clone_repository(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(CloneRepoParams { sandbox_id, repo }): Parameters<CloneRepoParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);
        let Some(creds) = &self.creds else {
            return Self::github_disabled_message("clone_repository");
        };
        let sandbox = match self.resolve_sandbox(&identity, sandbox_id.as_deref()).await {
            Ok(s) => s,
            Err(e) => return e,
        };

        let auth_url = match creds.as_ref() {
            GitHubCreds::PersonalToken { token, user } => {
                format!("https://{user}:{token}@github.com/{repo}.git")
            }
            GitHubCreds::App {
                app_octocrab,
                installation_id,
            } => {
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

        sandbox.clone_repository(&repo, &auth_url).await
    }

    #[tool(
        description = "Read a file from the sandbox. Optionally specify offset (1-indexed start line) and limit (max lines) to read a range; line numbers are prefixed when a range is requested."
    )]
    async fn read_file(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(ReadFileParams {
            sandbox_id,
            path,
            offset,
            limit,
        }): Parameters<ReadFileParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);
        match self.resolve_sandbox(&identity, sandbox_id.as_deref()).await {
            Err(e) => e,
            Ok(s) => s.read_file(&path, offset, limit).await,
        }
    }

    #[tool(
        description = "Create or overwrite a file with the given content. Parent directories are created automatically."
    )]
    async fn write_file(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(WriteFileParams {
            sandbox_id,
            path,
            content,
        }): Parameters<WriteFileParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);
        match self.resolve_sandbox(&identity, sandbox_id.as_deref()).await {
            Err(e) => e,
            Ok(s) => s.write_file(&path, &content).await,
        }
    }

    #[tool(
        description = "Edit a file by replacing an exact string. old_string must appear exactly once in the file; use more context if it matches multiple times."
    )]
    async fn edit_file(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(EditFileParams {
            sandbox_id,
            path,
            old_string,
            new_string,
        }): Parameters<EditFileParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);
        match self.resolve_sandbox(&identity, sandbox_id.as_deref()).await {
            Err(e) => e,
            Ok(s) => s.edit_file(&path, &old_string, &new_string).await,
        }
    }

    #[tool(
        description = "Find files matching a glob pattern. Returns a JSON array of matching paths. Use ** for recursive matching, e.g. \"**/*.rs\"."
    )]
    async fn glob(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(GlobParams {
            sandbox_id,
            pattern,
            path,
        }): Parameters<GlobParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);
        match self.resolve_sandbox(&identity, sandbox_id.as_deref()).await {
            Err(e) => e,
            Ok(s) => s.glob(&pattern, path).await,
        }
    }

    #[tool(
        description = "Search file contents using a regex pattern. Returns matching lines as \"path:line_num:content\". Optionally filter files by name pattern (include), e.g. \"*.rs\"."
    )]
    async fn grep(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(GrepParams {
            sandbox_id,
            pattern,
            path,
            include,
        }): Parameters<GrepParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);
        match self.resolve_sandbox(&identity, sandbox_id.as_deref()).await {
            Err(e) => e,
            Ok(s) => s.grep(&pattern, path, include).await,
        }
    }

    #[tool(
        description = "Run a shell command in the sandbox. dir defaults to the sandbox work directory if not specified."
    )]
    async fn run_command(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(RunCommandParams {
            sandbox_id,
            command,
            dir,
        }): Parameters<RunCommandParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);
        match self.resolve_sandbox(&identity, sandbox_id.as_deref()).await {
            Err(e) => e,
            Ok(s) => s.run_command(&command, dir).await,
        }
    }

    #[tool(
        description = "Commit all changes in a cloned repo, push to a new branch, and open a GitHub PR"
    )]
    async fn create_pr(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(CreatePrParams {
            sandbox_id,
            repo,
            branch,
            commit_message,
            pr_title,
            pr_body,
        }): Parameters<CreatePrParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);
        let Some(octocrab) = &self.octocrab else {
            return Self::github_disabled_message("create_pr");
        };
        let sandbox = match self.resolve_sandbox(&identity, sandbox_id.as_deref()).await {
            Ok(s) => s,
            Err(e) => return e,
        };

        // Git work → sandbox
        let result = sandbox
            .git_commit_and_push(&repo, &branch, &commit_message)
            .await;
        if result != "ok" {
            return result;
        }

        // GitHub API → handler (needs octocrab)
        let parts: Vec<&str> = repo.splitn(2, '/').collect();
        if parts.len() != 2 {
            return format!("Invalid repo format (expected owner/repo): {repo}");
        }
        let (owner, repo_name) = (parts[0], parts[1]);

        match octocrab
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
                When a client manages multiple sandboxes or loses session continuity, pass sandbox_id explicitly to sandbox tools. \
                list_repositories and list_providers are available before creating a sandbox. \
                \n\nSandbox isolation: read_file, write_file, and edit_file are restricted to paths \
                within the selected sandbox directory. Always use paths under the sandbox work_dir \
                (returned by create_sandbox). This applies to ALL file operations including plan \
                files — when asked to write or read a plan file, write it to a path inside the \
                sandbox (e.g. <sandbox_work_dir>/plan.md) and read it back from there.\
                \n\nTool reference:\
                \n- create_sandbox(provider, name): create a sandbox; when calling, choose a short descriptive name that reflects the current task (e.g. \"fix-login-bug\", \"add-export-feature\"). If no obvious name exists, ask the user before proceeding.\
                \n- sandbox tools accept an optional sandbox_id; provide it explicitly for multi-sandbox workflows\
                \n- read_file(path, offset?, limit?): read a file within the sandbox; offset/limit for line ranges with line numbers\
                \n- write_file(path, content): create or overwrite a file within the sandbox\
                \n- edit_file(path, old_string, new_string): targeted search-replace within a sandbox file\
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
        let tools = self
            .tool_router
            .list_all()
            .into_iter()
            .filter(|tool| {
                self.github_enabled()
                    || !matches!(
                        tool.name.as_ref(),
                        "list_repositories" | "clone_repository" | "create_pr"
                    )
            })
            .collect::<Vec<_>>();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_ref()).collect();
        tracing::info!(tools = ?names, "list_tools");
        Ok(ListToolsResult {
            tools,
            meta: None,
            next_cursor: None,
        })
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
