use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use regex::Regex;
use tokio::process::Command;
use tokio::sync::{RwLock, mpsc};
use walkdir::WalkDir;

use crate::auth::generate_token;

use super::{Provider, SandboxHandle, SandboxMessage};

// ── LocalSandbox ──────────────────────────────────────────────────────────────

pub struct LocalSandbox {
    pub id: String,
    pub work_dir: PathBuf,
}

impl LocalSandbox {
    fn ensure_in_sandbox(&self, path: &str) -> Result<(), String> {
        let canonical_root =
            std::fs::canonicalize(&self.work_dir).unwrap_or_else(|_| self.work_dir.clone());

        // Lexically collapse `.` / `..` first, then canonicalize as far as the
        // filesystem allows (walking up to the first existing ancestor so that
        // paths for not-yet-created files are handled correctly).
        let normalized = lexical_normalize(Path::new(path));
        let canonical_path = canonicalize_best_effort(&normalized);

        if !canonical_path.starts_with(&canonical_root) {
            return Err(format!(
                "Error: path {path} is outside the sandbox ({}). \
                 File operations are restricted to the sandbox directory.",
                self.work_dir.display()
            ));
        }
        Ok(())
    }

    #[tracing::instrument(skip(self), fields(sandbox = %self.id))]
    async fn read_file(&self, path: &str, offset: Option<u32>, limit: Option<u32>) -> String {
        if let Err(e) = self.ensure_in_sandbox(path) {
            return e;
        }
        let content = match tokio::fs::read_to_string(path).await {
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

    #[tracing::instrument(skip(self, content), fields(sandbox = %self.id, bytes = content.len()))]
    async fn write_file(&self, path: &str, content: &str) -> String {
        if let Err(e) = self.ensure_in_sandbox(path) {
            return e;
        }
        let p = Path::new(path);
        if let Some(parent) = p.parent()
            && let Err(e) = tokio::fs::create_dir_all(parent).await
        {
            return format!("Failed to create parent dirs: {e}");
        }
        match tokio::fs::write(path, content).await {
            Ok(()) => format!("Written {} bytes to {path}", content.len()),
            Err(e) => format!("Error writing {path}: {e}"),
        }
    }

    #[tracing::instrument(skip(self, old_string, new_string), fields(sandbox = %self.id))]
    async fn edit_file(&self, path: &str, old_string: &str, new_string: &str) -> String {
        if let Err(e) = self.ensure_in_sandbox(path) {
            return e;
        }
        let content = match tokio::fs::read_to_string(path).await {
            Ok(c) => c,
            Err(e) => return format!("Error reading {path}: {e}"),
        };
        let count = content.matches(old_string).count();
        match count {
            0 => format!("Error: old_string not found in {path}"),
            1 => {
                let new_content = content.replacen(old_string, new_string, 1);
                match tokio::fs::write(path, &new_content).await {
                    Ok(()) => format!("Edited {path}: replaced 1 occurrence"),
                    Err(e) => format!("Error writing {path}: {e}"),
                }
            }
            n => format!("Error: old_string matches {n} times in {path} — make it more specific"),
        }
    }

    #[tracing::instrument(skip(self), fields(sandbox = %self.id))]
    async fn glob(&self, pattern: &str, base_path: Option<String>) -> String {
        let base = base_path.unwrap_or_else(|| self.work_dir.display().to_string());
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

    #[tracing::instrument(skip(self), fields(sandbox = %self.id))]
    async fn grep(&self, pattern: &str, path: Option<String>, include: Option<String>) -> String {
        let re = match Regex::new(pattern) {
            Ok(r) => r,
            Err(e) => return format!("Error: invalid regex pattern: {e}"),
        };

        let search_path_str = path.unwrap_or_else(|| self.work_dir.display().to_string());
        let search_path = Path::new(&search_path_str);

        let files: Vec<PathBuf> = if search_path.is_file() {
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
            let content = match tokio::fs::read_to_string(file).await {
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

    #[tracing::instrument(skip(self), fields(sandbox = %self.id))]
    async fn run_command(&self, command: &str, dir: Option<String>) -> String {
        let work_dir = dir.unwrap_or_else(|| self.work_dir.display().to_string());
        if let Err(e) = self.ensure_in_sandbox(&work_dir) {
            return e;
        }
        match Command::new("sh")
            .arg("-c")
            .arg(command)
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

    #[tracing::instrument(skip(self, url), fields(sandbox = %self.id))]
    async fn clone_repository(&self, repo: &str, url: &str) -> String {
        let dest = self.work_dir.join(repo);

        if dest.exists() {
            return format!("Already cloned at {}", dest.display());
        }

        if let Some(parent) = dest.parent()
            && let Err(e) = tokio::fs::create_dir_all(parent).await
        {
            return format!("Failed to create directory: {e}");
        }

        match Command::new("git")
            .args(["clone", url, dest.to_str().unwrap()])
            .output()
            .await
        {
            Ok(o) if o.status.success() => format!("Cloned to {}", dest.display()),
            Ok(o) => format!("git clone failed: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => format!("Failed to run git: {e}"),
        }
    }

    #[tracing::instrument(skip(self), fields(sandbox = %self.id))]
    async fn git_commit_and_push(&self, repo: &str, branch: &str, commit_message: &str) -> String {
        let repo_dir = self.work_dir.join(repo);

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
            .args(["checkout", "-b", branch])
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
            .args(["commit", "-m", commit_message])
            .current_dir(&repo_dir)
            .output()
            .await
        {
            Ok(o) if !o.status.success() => {
                return format!("git commit failed: {}", String::from_utf8_lossy(&o.stderr));
            }
            Err(e) => return format!("Failed to run git commit: {e}"),
            _ => {}
        }

        match Command::new("git")
            .args(["push", "origin", branch])
            .current_dir(&repo_dir)
            .output()
            .await
        {
            Ok(o) if !o.status.success() => {
                return format!("git push failed: {}", String::from_utf8_lossy(&o.stderr));
            }
            Err(e) => return format!("Failed to run git push: {e}"),
            _ => {}
        }

        "ok".to_string()
    }

    pub async fn run(self, mut rx: mpsc::Receiver<SandboxMessage>) {
        while let Some(msg) = rx.recv().await {
            match msg {
                SandboxMessage::ReadFile {
                    path,
                    offset,
                    limit,
                    reply,
                } => {
                    let _ = reply.send(self.read_file(&path, offset, limit).await);
                }
                SandboxMessage::WriteFile {
                    path,
                    content,
                    reply,
                } => {
                    let _ = reply.send(self.write_file(&path, &content).await);
                }
                SandboxMessage::EditFile {
                    path,
                    old_string,
                    new_string,
                    reply,
                } => {
                    let _ = reply.send(self.edit_file(&path, &old_string, &new_string).await);
                }
                SandboxMessage::Glob {
                    pattern,
                    base_path,
                    reply,
                } => {
                    let _ = reply.send(self.glob(&pattern, base_path).await);
                }
                SandboxMessage::Grep {
                    pattern,
                    path,
                    include,
                    reply,
                } => {
                    let _ = reply.send(self.grep(&pattern, path, include).await);
                }
                SandboxMessage::RunCommand {
                    command,
                    dir,
                    reply,
                } => {
                    let _ = reply.send(self.run_command(&command, dir).await);
                }
                SandboxMessage::CloneRepository { repo, url, reply } => {
                    let _ = reply.send(self.clone_repository(&repo, &url).await);
                }
                SandboxMessage::GitCommitAndPush {
                    repo,
                    branch,
                    commit_message,
                    reply,
                } => {
                    let _ = reply.send(
                        self.git_commit_and_push(&repo, &branch, &commit_message)
                            .await,
                    );
                }
            }
        }
    }
}

/// Resolve `.` and `..` components lexically (no I/O) so that paths like
/// `/sandbox/foo/../../etc/passwd` are caught before reaching the filesystem.
fn lexical_normalize(path: &Path) -> PathBuf {
    let mut out: Vec<std::path::Component> = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                // Only pop a normal component; preserve leading RootDir/Prefix.
                if matches!(out.last(), Some(std::path::Component::Normal(_))) {
                    out.pop();
                }
            }
            c => out.push(c),
        }
    }
    out.iter().collect()
}

/// Canonicalize a path, walking up to the first existing ancestor when the
/// path itself doesn't exist yet (e.g. a file about to be written).  This
/// ensures that symlinks in the path prefix (e.g. `/tmp` → `/private/tmp` on
/// macOS) are resolved consistently with how the sandbox root is resolved.
fn canonicalize_best_effort(path: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(path) {
        return c;
    }
    // Walk upward until we find an existing ancestor.
    let mut current = path.to_path_buf();
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    while let Some(parent) = current.parent() {
        if let Some(name) = current.file_name() {
            suffix.push(name.to_os_string());
        }
        current = parent.to_path_buf();
        if let Ok(canonical) = std::fs::canonicalize(&current) {
            let mut result = canonical;
            for component in suffix.into_iter().rev() {
                result.push(component);
            }
            return result;
        }
    }
    // Fallback: return the lexically normalized path as-is.
    path.to_path_buf()
}

// ── LocalProvider ─────────────────────────────────────────────────────────────

struct SandboxRecord {
    handle: SandboxHandle,
    created_at: Instant,
}

pub struct LocalProvider {
    sandboxes: Arc<RwLock<HashMap<String, SandboxRecord>>>,
    ttl: Duration,
}

impl LocalProvider {
    pub fn new(ttl: Duration) -> Arc<Self> {
        Arc::new(Self {
            sandboxes: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        })
    }

    pub fn start_cleanup_task(self: &Arc<Self>) {
        let provider = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                let expired: Vec<(String, PathBuf)> = {
                    let map = provider.sandboxes.read().await;
                    map.iter()
                        .filter(|(_, r)| r.created_at.elapsed() >= provider.ttl)
                        .map(|(id, r)| (id.clone(), r.handle.work_dir.clone()))
                        .collect()
                };
                for (id, work_dir) in expired {
                    let _ = tokio::fs::remove_dir_all(&work_dir).await;
                    provider.sandboxes.write().await.remove(&id);
                    tracing::info!("sandbox {id} expired and removed");
                }
            }
        });
    }
}

#[async_trait::async_trait]
impl Provider for LocalProvider {
    fn name(&self) -> &'static str {
        "local"
    }

    fn description(&self) -> &'static str {
        "Local filesystem sandbox — files live on this server"
    }

    async fn create(&self, name: String) -> Result<SandboxHandle, String> {
        let id = generate_token()[..16].to_string();
        let work_dir = PathBuf::from(format!("/tmp/sandcastle/sessions/{id}"));
        tokio::fs::create_dir_all(&work_dir)
            .await
            .map_err(|e| format!("Failed to create sandbox: {e}"))?;
        let (tx, rx) = mpsc::channel(32);
        let handle = SandboxHandle::new(id.clone(), name, work_dir.clone(), tx);
        tokio::spawn(
            LocalSandbox {
                id: id.clone(),
                work_dir,
            }
            .run(rx),
        );
        self.sandboxes.write().await.insert(
            id,
            SandboxRecord {
                handle: handle.clone(),
                created_at: Instant::now(),
            },
        );
        Ok(handle)
    }

    async fn resume(&self, id: &str) -> Result<SandboxHandle, String> {
        let map = self.sandboxes.read().await;
        match map.get(id) {
            None => Err(format!("Sandbox {id} not found")),
            Some(r) if r.created_at.elapsed() >= self.ttl => {
                Err(format!("Sandbox {id} has expired"))
            }
            Some(r) => Ok(r.handle.clone()),
        }
    }
}
