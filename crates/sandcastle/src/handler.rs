use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use anyhow::Result;
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
use sandcastle_sandbox_providers::{Provider, SandboxHandle};

use crate::secrets::SecretStore;

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
    #[schemars(
        description = "Secrets to expose as environment variables. Key = env var name, value = secret name as registered via store_secret. Example: {\"API_KEY\": \"my-api-key\"}"
    )]
    secrets: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct StoreSecretParams {
    #[schemars(
        description = "Name for this secret, e.g. \"github-token\" or \"openai-key\". Used later in run_command to reference the secret."
    )]
    name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
struct ListSandboxesParams {
    #[schemars(description = "Optional provider filter, e.g. \"docker\"")]
    provider: Option<String>,
}

#[derive(Clone)]
pub struct SandboxMeta {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub work_dir: String,
    pub owner: String,
}

#[derive(Default)]
pub struct SandboxRegistry {
    owners: RwLock<HashMap<String, String>>,
    active_by_owner: RwLock<HashMap<String, String>>,
    sandboxes: RwLock<HashMap<String, SandboxMeta>>,
}

#[derive(Clone)]
pub struct SandcastleHandler {
    tool_router: ToolRouter<Self>,
    sandbox_registry: Arc<SandboxRegistry>,
    providers: Vec<Arc<dyn Provider>>,
    secret_store: Arc<SecretStore>,
    base_url: String,
}

#[tool_router]
impl SandcastleHandler {
    pub fn new(
        sandbox_registry: Arc<SandboxRegistry>,
        providers: Vec<Arc<dyn Provider>>,
        secret_store: Arc<SecretStore>,
        base_url: String,
    ) -> Self {
        Self {
            tool_router: Self::tool_router(),
            sandbox_registry,
            providers,
            secret_store,
            base_url,
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
                no_auth: false,
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
        if identity.no_auth {
            return true;
        }
        self.sandbox_registry
            .owners
            .read()
            .unwrap()
            .get(sandbox_id)
            .is_some_and(|owner| owner == &identity.owner_key)
    }

    fn sandbox_summary_json(id: &str, name: &str, path: &str) -> String {
        serde_json::json!({
            "sandbox_id": id,
            "name": name,
            "work_dir": path,
        })
        .to_string()
    }

    fn error_json(message: &str) -> String {
        serde_json::json!({
            "error": message,
        })
        .to_string()
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
        self.sandbox_registry
            .sandboxes
            .write()
            .unwrap()
            .remove(sandbox_id);
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
        description = "Spawn a sandbox with the given provider. Must be called before using any sandbox tools. Returns JSON with sandbox_id, name, and work_dir."
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
                Self::error_json(&format!(
                    "Unknown provider: {provider}. Available: {}",
                    names.join(", ")
                ))
            }
            Some(p) => match p.create(name).await {
                Err(e) => Self::error_json(&e),
                Ok(handle) => {
                    let id = handle.id.clone();
                    let name = handle.name.clone();
                    let path = handle.work_dir.display().to_string();
                    self.set_active_sandbox(&identity, &id);
                    self.sandbox_registry.sandboxes.write().unwrap().insert(
                        id.clone(),
                        SandboxMeta {
                            id: id.clone(),
                            name: name.clone(),
                            provider: provider.clone(),
                            work_dir: path.clone(),
                            owner: identity.owner_key.clone(),
                        },
                    );
                    Self::sandbox_summary_json(&id, &name, &path)
                }
            },
        }
    }

    #[tool(
        description = "List available sandboxes for the current user. Returns a JSON array with sandbox_id, name, provider, work_dir, and status. Supports optional provider filtering."
    )]
    async fn list_sandboxes(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(ListSandboxesParams { provider }): Parameters<ListSandboxesParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);
        let sandboxes = self.sandbox_registry.sandboxes.read().unwrap();
        let list: Vec<serde_json::Value> = sandboxes
            .values()
            .filter(|s| s.owner == identity.owner_key)
            .filter(|s| match &provider {
                Some(p) => &s.provider == p,
                None => true,
            })
            .map(|s| {
                serde_json::json!({
                    "sandbox_id": s.id,
                    "name": s.name,
                    "provider": s.provider,
                    "work_dir": s.work_dir,
                    "status": "running"
                })
            })
            .collect();
        serde_json::to_string(&list).unwrap_or_default()
    }

    #[tool(
        description = "Resume a previously created sandbox by ID. Use the ID returned by create_sandbox. Returns JSON with sandbox_id, name, and work_dir."
    )]
    async fn resume_sandbox(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(ResumeSandboxParams { id }): Parameters<ResumeSandboxParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);
        if !self.is_owned_by(&identity, &id) {
            return Self::error_json(&format!(
                "Error: sandbox {id} is not accessible to this client."
            ));
        }
        match self.resume_known_sandbox(&id).await {
            Ok(handle) => {
                let path = handle.work_dir.display().to_string();
                let name = handle.name.clone();
                self.set_active_sandbox(&identity, &id);
                Self::sandbox_summary_json(&id, &name, &path)
            }
            Err(e) => Self::error_json(&e),
        }
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
        description = "Run a shell command in the sandbox. dir defaults to the sandbox work directory if not specified. Use secrets to inject stored secrets as environment variables. Before using secrets, call list_secrets to see which secret names are already available."
    )]
    async fn run_command(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(RunCommandParams {
            sandbox_id,
            command,
            dir,
            secrets,
        }): Parameters<RunCommandParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);

        let mut env = HashMap::new();
        if let Some(secret_map) = secrets {
            for (env_key, secret_name) in secret_map {
                match self
                    .secret_store
                    .get_secret(&identity.owner_key, &secret_name)
                {
                    Some(val) => {
                        env.insert(env_key, val);
                    }
                    None => {
                        return format!(
                            "Error: secret '{secret_name}' not found. Call store_secret first and set the value via the returned URL."
                        );
                    }
                }
            }
        }

        match self.resolve_sandbox(&identity, sandbox_id.as_deref()).await {
            Err(e) => e,
            Ok(s) => s.run_command(&command, dir, env).await,
        }
    }

    #[tool(
        description = "List the names of all secrets stored for this client. Call this before run_command, push_to_branch, or create_pr to discover which secrets are already available."
    )]
    async fn list_secrets(&self, ctx: RequestContext<RoleServer>) -> String {
        let identity = Self::request_identity(&ctx);
        let names = self.secret_store.list_secrets(&identity.owner_key);
        serde_json::to_string(&names).unwrap_or_default()
    }

    #[tool(
        description = "Register a new secret slot using the generic provider. Returns a one-time URL the user can visit in their browser or call with curl to set the secret value. The secret can then be injected into run_command via the secrets parameter."
    )]
    async fn store_secret(
        &self,
        ctx: RequestContext<RoleServer>,
        Parameters(StoreSecretParams { name }): Parameters<StoreSecretParams>,
    ) -> String {
        let identity = Self::request_identity(&ctx);
        let token = self
            .secret_store
            .create_upload_token(&identity.owner_key, &name);
        let url = format!("{}/secrets/{}", self.base_url, token);
        serde_json::json!({
            "url": url,
            "name": name,
            "provider": "generic",
            "instructions": format!(
                "Visit {} in your browser to set the secret value, or use curl:\ncurl -X POST '{}' -d 'value=YOUR_SECRET'",
                url, url
            ),
        })
        .to_string()
    }
}

impl ServerHandler for SandcastleHandler {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "Sandcastle MCP server. \
                IMPORTANT: All file operations and shell commands MUST be performed \
                using the tools provided by this server (read_file, write_file, \
                edit_file, glob, grep, run_command). Do NOT use your own built-in tools \
                or shell access for any of these tasks — always delegate to the sandbox tools. \
                Workflow: call create_sandbox first, then use the sandbox tools for everything else. \
                When a client manages multiple sandboxes or loses session continuity, pass sandbox_id explicitly to sandbox tools. \
                list_providers is available before creating a sandbox. \
                \n\nSandbox isolation: read_file, write_file, and edit_file are restricted to paths \
                within the selected sandbox directory. Always use paths under the sandbox work_dir \
                (returned by create_sandbox). This applies to ALL file operations including plan \
                files — when asked to write or read a plan file, write it to a path inside the \
                sandbox (e.g. <sandbox_work_dir>/plan.md) and read it back from there.\
                \n\nTool reference:\
                \n- create_sandbox(provider, name): create a sandbox and return JSON with sandbox_id, name, and work_dir; when calling, choose a short descriptive name that reflects the current task (e.g. \"fix-login-bug\", \"add-export-feature\"). If no obvious name exists, ask the user before proceeding.\
                \n- resume_sandbox(id): resume a sandbox by ID and return JSON with sandbox_id, name, and work_dir\
                \n- list_sandboxes(provider?): list the current user's tracked sandboxes; optional provider filter\
                \n- sandbox tools accept an optional sandbox_id; provide it explicitly for multi-sandbox workflows\
                \n- read_file(path, offset?, limit?): read a file within the sandbox; offset/limit for line ranges with line numbers\
                \n- write_file(path, content): create or overwrite a file within the sandbox\
                \n- edit_file(path, old_string, new_string): targeted search-replace within a sandbox file\
                \n- glob(pattern, path?): find files matching a glob pattern (e.g. **/*.rs)\
                \n- grep(pattern, path?, include?): search file contents with regex\
                \n- list_secrets(): list names of stored secrets for this client — call this before run_command/push_to_branch/create_pr to discover available secrets\
                \n- run_command(command, dir?, secrets?): run a shell command; secrets maps env var names to secret names set via store_secret; call list_secrets first to discover available secrets\
                \n- store_secret(name): register a secret slot and get a URL to set its value; returns provider=generic URL"
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
