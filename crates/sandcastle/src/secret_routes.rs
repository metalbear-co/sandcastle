use std::sync::Arc;

use axum::{
    Extension,
    body::Bytes,
    extract::Path,
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};

use crate::secrets::SecretStore;

#[derive(Clone)]
pub struct BaseUrl(pub String);

pub async fn get_secret_page(
    Path(token): Path<String>,
    Extension(store): Extension<Arc<SecretStore>>,
    Extension(BaseUrl(base_url)): Extension<BaseUrl>,
) -> impl IntoResponse {
    let Some((_, name)) = store.get_token_info(&token) else {
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            "<h2>Not found</h2><p>This secret link is invalid or has already been used.</p>"
                .to_string(),
        );
    };

    let secret_url = format!("{base_url}/secrets/{token}");
    let html = format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Set secret: {name}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 480px; margin: 60px auto; padding: 0 16px; }}
    label {{ display: block; margin-bottom: 6px; font-weight: 600; }}
    input[type=password] {{ width: 100%; padding: 8px; font-size: 1rem; box-sizing: border-box; }}
    button {{ margin-top: 12px; padding: 8px 20px; font-size: 1rem; cursor: pointer; }}
    pre {{ background: #f4f4f4; padding: 12px; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; }}
  </style>
</head>
<body>
  <h2>Set secret: <code>{name_escaped}</code></h2>
  <form method="POST">
    <label for="value">Secret value</label>
    <input type="password" id="value" name="value" autofocus required>
    <button type="submit">Save secret</button>
  </form>
  <hr>
  <p>Or set via curl:</p>
  <pre>curl -X POST '{url_escaped}' \
     -d 'value=YOUR_SECRET_VALUE'</pre>
</body>
</html>"#,
        name_escaped = html_escape(&name),
        url_escaped = html_escape(&secret_url),
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
}

pub async fn post_secret_value(
    Path(token): Path<String>,
    Extension(store): Extension<Arc<SecretStore>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let value = if content_type.contains("application/json") {
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) else {
            return (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "application/json")],
                r#"{"error":"invalid JSON body"}"#.to_string(),
            );
        };
        v["value"].as_str().unwrap_or("").to_string()
    } else if content_type.contains("application/x-www-form-urlencoded") {
        form_value(&body)
    } else {
        // Plain text fallback
        String::from_utf8_lossy(&body).trim().to_string()
    };

    if value.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            [(header::CONTENT_TYPE, "application/json")],
            r#"{"error":"value must not be empty"}"#.to_string(),
        );
    }

    match store.consume_token_and_store(&token, &value) {
        Ok(name) => {
            let wants_html = headers
                .get(header::ACCEPT)
                .and_then(|v| v.to_str().ok())
                .map(|a| a.contains("text/html"))
                .unwrap_or(false);

            if wants_html {
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                    format!(
                        r#"<!doctype html><html><head><meta charset="utf-8"><title>Secret saved</title></head>
<body style="font-family:system-ui;max-width:480px;margin:60px auto;padding:0 16px">
<h2>Secret <code>{}</code> saved</h2>
<p>You can close this tab. The secret is now available in your sandbox.</p>
</body></html>"#,
                        html_escape(&name)
                    ),
                )
            } else {
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    format!(r#"{{"ok":true,"name":"{}"}}"#, json_escape(&name)),
                )
            }
        }
        Err(e) => (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "application/json")],
            format!(r#"{{"error":"{}"}}"#, json_escape(&e)),
        ),
    }
}

fn form_value(body: &[u8]) -> String {
    let s = String::from_utf8_lossy(body);
    for pair in s.split('&') {
        let mut parts = pair.splitn(2, '=');
        if let (Some(k), Some(v)) = (parts.next(), parts.next())
            && url_decode(k) == "value"
        {
            return url_decode(v);
        }
    }
    String::new()
}

fn url_decode(s: &str) -> String {
    let s = s.replace('+', " ");
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(hex) = std::str::from_utf8(&bytes[i + 1..i + 3])
            && let Ok(byte) = u8::from_str_radix(hex, 16)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
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
