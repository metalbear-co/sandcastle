use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{
    Extension,
    extract::Path,
    http::{StatusCode, header},
    response::IntoResponse,
};

pub enum AuthStatus {
    Pending {
        verification_uri: String,
        user_code: String,
    },
    Complete {
        secret_name: String,
    },
    Expired,
    Error(String),
}

pub struct PendingAuth {
    pub status: AuthStatus,
}

pub type GitHubAuthPendingStore = Arc<Mutex<HashMap<String, PendingAuth>>>;

pub async fn get_github_auth_page(
    Path(token): Path<String>,
    Extension(store): Extension<GitHubAuthPendingStore>,
) -> impl IntoResponse {
    let (verification_uri, user_code) = {
        let guard = store.lock().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = guard.get(&token) else {
            return (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                "<h2>Not found</h2><p>This link is invalid or has expired.</p>".to_string(),
            );
        };
        match &entry.status {
            AuthStatus::Pending {
                verification_uri,
                user_code,
            } => (verification_uri.clone(), user_code.clone()),
            AuthStatus::Complete { secret_name } => {
                let name = html_escape(secret_name);
                return (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    format!(
                        r#"<!doctype html><html><head><meta charset="utf-8"><title>Authorized</title></head>
<body style="font-family:system-ui;max-width:480px;margin:60px auto;padding:0 16px">
<h2>GitHub access authorized</h2>
<p>Token stored as secret <code>{name}</code>. You can close this tab.</p>
</body></html>"#
                    ),
                );
            }
            AuthStatus::Expired => {
                return (
                    StatusCode::GONE,
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    "<h2>Expired</h2><p>This authorization link has expired. Please request a new one.</p>".to_string(),
                );
            }
            AuthStatus::Error(e) => {
                let msg = html_escape(e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    format!("<h2>Error</h2><p>{msg}</p>"),
                );
            }
        }
    };

    let uri_escaped = html_escape(&verification_uri);
    let code_escaped = html_escape(&user_code);
    let token_escaped = html_escape(&token);

    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Authorize GitHub Access</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 520px; margin: 60px auto; padding: 0 16px; }}
    .code {{ font-size: 2rem; font-weight: 700; letter-spacing: 0.15em; background: #f4f4f4;
             padding: 12px 24px; border-radius: 8px; display: inline-block; margin: 12px 0; }}
    .btn {{ display: inline-block; margin-top: 16px; padding: 10px 24px; background: #238636;
            color: #fff; text-decoration: none; border-radius: 6px; font-size: 1rem; }}
    .status {{ margin-top: 24px; padding: 12px; border-radius: 6px; background: #f4f4f4; }}
    .done {{ background: #d4edda; color: #155724; }}
    .error {{ background: #f8d7da; color: #721c24; }}
  </style>
</head>
<body>
  <h2>Authorize GitHub Access</h2>
  <ol>
    <li>Click the button below to open GitHub</li>
    <li>Enter this code when prompted:</li>
  </ol>
  <div class="code" id="code">{code_escaped}</div>
  <br>
  <a class="btn" href="{uri_escaped}" target="_blank">Open GitHub &rarr;</a>
  <div class="status" id="status">Waiting for authorization&hellip;</div>
  <script>
    (function poll() {{
      fetch('/github-auth/{token_escaped}/status')
        .then(r => r.json())
        .then(data => {{
          const el = document.getElementById('status');
          if (data.status === 'complete') {{
            el.className = 'status done';
            el.textContent = 'Authorized! Token stored as secret "' + data.secret_name + '". You can close this tab.';
          }} else if (data.status === 'expired' || data.status === 'error') {{
            el.className = 'status error';
            el.textContent = data.message || 'Authorization failed. Please request a new link.';
          }} else {{
            setTimeout(poll, 5000);
          }}
        }})
        .catch(() => setTimeout(poll, 5000));
    }})();
  </script>
</body>
</html>"#
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

pub async fn get_github_auth_status(
    Path(token): Path<String>,
    Extension(store): Extension<GitHubAuthPendingStore>,
) -> impl IntoResponse {
    let guard = store.lock().unwrap_or_else(|e| e.into_inner());
    let json = match guard.get(&token) {
        None => r#"{"status":"error","message":"not found"}"#.to_string(),
        Some(entry) => match &entry.status {
            AuthStatus::Pending { .. } => r#"{"status":"pending"}"#.to_string(),
            AuthStatus::Complete { secret_name } => {
                format!(
                    r#"{{"status":"complete","secret_name":"{}"}}"#,
                    json_escape(secret_name)
                )
            }
            AuthStatus::Expired => {
                r#"{"status":"expired","message":"Authorization expired."}"#.to_string()
            }
            AuthStatus::Error(e) => {
                format!(r#"{{"status":"error","message":"{}"}}"#, json_escape(e))
            }
        },
    };
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        json,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn json_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}
