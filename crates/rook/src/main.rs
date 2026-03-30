use std::collections::HashMap;
use std::process::Stdio;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use sandcastle_rook_proto::{RookCommand, RookResponse};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio_tungstenite::tungstenite::Message;

const WORK_DIR: &str = "/workspace";

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("rook=info")),
        )
        .init();

    let url = std::env::var("SANDCASTLE_ROOK_URL")
        .expect("SANDCASTLE_ROOK_URL environment variable is required");
    let sandbox_id =
        std::env::var("SANDBOX_ID").expect("SANDBOX_ID environment variable is required");

    tokio::fs::create_dir_all(WORK_DIR)
        .await
        .expect("failed to create /workspace");

    let ws = connect_with_retry(&url).await;
    let (mut write, mut read) = ws.split();

    let hello = serde_json::to_string(&RookResponse::Hello {
        sandbox_id: sandbox_id.clone(),
    })
    .expect("serialization failed");
    write
        .send(Message::Text(hello.into()))
        .await
        .expect("failed to send hello");

    tracing::info!(sandbox_id, "connected to sandcastle");

    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let cmd = match serde_json::from_str::<RookCommand>(&text) {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!("unrecognised message: {e}");
                        continue;
                    }
                };
                let responses = dispatch(cmd).await;
                for resp in responses {
                    let json = match serde_json::to_string(&resp) {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::error!("failed to serialise response: {e}");
                            continue;
                        }
                    };
                    if write.send(Message::Text(json.into())).await.is_err() {
                        tracing::info!("sandcastle closed connection");
                        return;
                    }
                }
            }
            Ok(Message::Close(_)) => {
                tracing::info!("sandcastle closed connection");
                return;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!("websocket error: {e}");
                return;
            }
        }
    }
}

async fn connect_with_retry(
    url: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        match tokio_tungstenite::connect_async(url).await {
            Ok((ws, _)) => return ws,
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!("failed to connect to sandcastle at {url}: {e}");
                }
                tracing::debug!("connect failed ({e}), retrying in 2s");
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}

async fn dispatch(cmd: RookCommand) -> Vec<RookResponse> {
    match cmd {
        RookCommand::ReadFile {
            req_id,
            path,
            offset,
            limit,
        } => vec![read_file(req_id, &path, offset, limit).await],

        RookCommand::WriteFile {
            req_id,
            path,
            content,
        } => vec![write_file(req_id, &path, &content).await],

        RookCommand::EditFile {
            req_id,
            path,
            old_string,
            new_string,
        } => vec![edit_file(req_id, &path, &old_string, &new_string).await],

        RookCommand::Glob {
            req_id,
            pattern,
            base_path,
        } => vec![glob(req_id, &pattern, base_path.as_deref()).await],

        RookCommand::Grep {
            req_id,
            pattern,
            path,
            include,
        } => vec![grep(req_id, &pattern, path.as_deref(), include.as_deref()).await],

        RookCommand::RunCommand {
            req_id,
            command,
            dir,
            env,
        } => run_command(req_id, &command, dir.as_deref(), &env).await,
    }
}

async fn read_file(
    req_id: u64,
    path: &str,
    offset: Option<u32>,
    limit: Option<u32>,
) -> RookResponse {
    match tokio::fs::read_to_string(path).await {
        Err(e) => RookResponse::Error {
            req_id,
            message: format!("failed to read {path}: {e}"),
        },
        Ok(content) => {
            let output = if offset.is_none() && limit.is_none() {
                content
                    .lines()
                    .enumerate()
                    .map(|(i, l)| format!("{:6}\t{l}\n", i + 1))
                    .collect()
            } else {
                let start = offset.unwrap_or(1) as usize;
                let end = limit.map(|n| start + n as usize - 1).unwrap_or(usize::MAX);
                content
                    .lines()
                    .enumerate()
                    .filter(|(i, _)| {
                        let n = i + 1;
                        n >= start && n <= end
                    })
                    .map(|(i, l)| format!("{:6}\t{l}\n", i + 1))
                    .collect()
            };
            RookResponse::Result { req_id, output }
        }
    }
}

async fn write_file(req_id: u64, path: &str, content: &str) -> RookResponse {
    let parent = std::path::Path::new(path).parent();
    if let Some(dir) = parent {
        if !dir.as_os_str().is_empty() {
            if let Err(e) = tokio::fs::create_dir_all(dir).await {
                return RookResponse::Error {
                    req_id,
                    message: format!("failed to create directories for {path}: {e}"),
                };
            }
        }
    }
    match tokio::fs::write(path, content).await {
        Ok(_) => RookResponse::Result {
            req_id,
            output: format!("Written {} bytes to {path}", content.len()),
        },
        Err(e) => RookResponse::Error {
            req_id,
            message: format!("failed to write {path}: {e}"),
        },
    }
}

async fn edit_file(req_id: u64, path: &str, old_string: &str, new_string: &str) -> RookResponse {
    let content = match tokio::fs::read_to_string(path).await {
        Ok(c) => c,
        Err(e) => {
            return RookResponse::Error {
                req_id,
                message: format!("failed to read {path}: {e}"),
            };
        }
    };
    let count = content.matches(old_string).count();
    match count {
        0 => RookResponse::Error {
            req_id,
            message: format!("old_string not found in {path}"),
        },
        1 => {
            let new_content = content.replacen(old_string, new_string, 1);
            match tokio::fs::write(path, &new_content).await {
                Ok(_) => RookResponse::Result {
                    req_id,
                    output: format!("Edited {path}: replaced 1 occurrence"),
                },
                Err(e) => RookResponse::Error {
                    req_id,
                    message: format!("failed to write {path}: {e}"),
                },
            }
        }
        n => RookResponse::Error {
            req_id,
            message: format!("old_string matches {n} times in {path} — make it more specific"),
        },
    }
}

async fn glob(req_id: u64, pattern: &str, base_path: Option<&str>) -> RookResponse {
    let base = base_path.unwrap_or(WORK_DIR);
    let recursive = pattern.contains("**");
    let name = pattern.split('/').next_back().unwrap_or(pattern);
    let prefix = pattern
        .split("**/")
        .next()
        .unwrap_or("")
        .trim_end_matches('/');
    let search_base = if prefix.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{prefix}")
    };
    let depth_flag = if recursive { "" } else { "-maxdepth 1 " };
    let cmd = format!(
        "find '{search_base}' {depth_flag}-name '{name}' -type f 2>/dev/null | sort | head -1000"
    );
    match run_sh(req_id, &cmd).await {
        Ok(stdout) => {
            let matches: Vec<&str> = stdout.lines().filter(|l| !l.is_empty()).collect();
            RookResponse::Result {
                req_id,
                output: serde_json::to_string(&matches).unwrap_or_default(),
            }
        }
        Err(e) => RookResponse::Error { req_id, message: e },
    }
}

async fn grep(
    req_id: u64,
    pattern: &str,
    path: Option<&str>,
    include: Option<&str>,
) -> RookResponse {
    let search_path = path.unwrap_or(WORK_DIR);
    let include_flag = include
        .map(|i| format!("--include='{i}' "))
        .unwrap_or_default();
    let cmd =
        format!("grep -rn -E {include_flag}-- '{pattern}' '{search_path}' 2>/dev/null | head -101");
    match run_sh(req_id, &cmd).await {
        Ok(stdout) => RookResponse::Result {
            req_id,
            output: stdout,
        },
        Err(e) => RookResponse::Error { req_id, message: e },
    }
}

async fn run_sh(req_id: u64, cmd: &str) -> Result<String, String> {
    let out = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .await
        .map_err(|e| format!("failed to run command (req_id={req_id}): {e}"))?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

async fn run_command(
    req_id: u64,
    command: &str,
    dir: Option<&str>,
    env: &HashMap<String, String>,
) -> Vec<RookResponse> {
    let work_dir = dir.unwrap_or(WORK_DIR);
    let mut child = match Command::new("sh")
        .arg("-c")
        .arg(command)
        .current_dir(work_dir)
        .envs(env)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return vec![
                RookResponse::Error {
                    req_id,
                    message: format!("failed to spawn: {e}"),
                },
                RookResponse::Done {
                    req_id,
                    exit_code: -1,
                },
            ];
        }
    };

    let stdout = child.stdout.take().map(BufReader::new);
    let stderr = child.stderr.take().map(BufReader::new);

    let mut responses = Vec::new();

    if let Some(mut reader) = stdout {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
                    responses.push(RookResponse::Output {
                        req_id,
                        line: trimmed.to_string(),
                    });
                }
                Err(_) => break,
            }
        }
    }

    if let Some(mut reader) = stderr {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let trimmed = line.trim_end_matches('\n').trim_end_matches('\r');
                    responses.push(RookResponse::Output {
                        req_id,
                        line: trimmed.to_string(),
                    });
                }
                Err(_) => break,
            }
        }
    }

    let exit_code = match child.wait().await {
        Ok(status) => status.code().unwrap_or(-1),
        Err(_) => -1,
    };

    responses.push(RookResponse::Done { req_id, exit_code });
    responses
}
