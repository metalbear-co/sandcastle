use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use regex::Regex;
use tokio::process::Command;
use tokio::sync::RwLock;
use walkdir::WalkDir;

use crate::auth::generate_token;

use super::{Provider, Sandbox};

// ── LocalSandbox ──────────────────────────────────────────────────────────────

pub struct LocalSandbox {
    pub id: String,
    pub work_dir: PathBuf,
}

impl LocalSandbox {
    fn ensure_in_sandbox(&self, path: &str) -> Result<(), String> {
        let p = Path::new(path);
        if !p.starts_with(&self.work_dir) {
            return Err(format!(
                "Error: path {path} is outside the sandbox ({}). \
                 File operations are restricted to the sandbox directory.",
                self.work_dir.display()
            ));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Sandbox for LocalSandbox {
    fn id(&self) -> &str {
        &self.id
    }

    fn work_dir(&self) -> &Path {
        &self.work_dir
    }

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

    async fn run_command(&self, command: &str, dir: Option<String>) -> String {
        let work_dir = dir.unwrap_or_else(|| self.work_dir.display().to_string());
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

    async fn clone_repository(&self, repo: &str, auth_url: &str) -> String {
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
            .args(["clone", auth_url, dest.to_str().unwrap()])
            .output()
            .await
        {
            Ok(o) if o.status.success() => format!("Cloned to {}", dest.display()),
            Ok(o) => format!("git clone failed: {}", String::from_utf8_lossy(&o.stderr)),
            Err(e) => format!("Failed to run git: {e}"),
        }
    }

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
                return format!(
                    "git commit failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                );
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
                return format!(
                    "git push failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                );
            }
            Err(e) => return format!("Failed to run git push: {e}"),
            _ => {}
        }

        "ok".to_string()
    }
}

// ── LocalProvider ─────────────────────────────────────────────────────────────

struct SandboxRecord {
    work_dir: PathBuf,
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
                        .map(|(id, r)| (id.clone(), r.work_dir.clone()))
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

    async fn create(&self) -> Result<Arc<dyn Sandbox>, String> {
        let id = generate_token()[..16].to_string();
        let work_dir = PathBuf::from(format!("/tmp/sandcastle/sessions/{id}"));
        tokio::fs::create_dir_all(&work_dir)
            .await
            .map_err(|e| format!("Failed to create sandbox: {e}"))?;
        self.sandboxes.write().await.insert(
            id.clone(),
            SandboxRecord { work_dir: work_dir.clone(), created_at: Instant::now() },
        );
        Ok(Arc::new(LocalSandbox { id, work_dir }))
    }

    async fn resume(&self, id: &str) -> Result<Arc<dyn Sandbox>, String> {
        let map = self.sandboxes.read().await;
        match map.get(id) {
            None => Err(format!("Sandbox {id} not found")),
            Some(r) if r.created_at.elapsed() >= self.ttl => {
                Err(format!("Sandbox {id} has expired"))
            }
            Some(r) => Ok(Arc::new(LocalSandbox {
                id: id.to_string(),
                work_dir: r.work_dir.clone(),
            })),
        }
    }
}
