use axum::{
    Json,
    extract::{Extension, Form, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tracing::debug;

use sandcastle_store::types::now_secs;
use sandcastle_util::generate_token;

use super::{PendingAuthRecord, PendingCodeRecord, SharedAuthState};

#[derive(Deserialize)]
pub struct AuthorizeParams {
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    #[allow(dead_code)]
    pub response_type: Option<String>,
    #[allow(dead_code)]
    pub code_challenge: Option<String>,
    #[allow(dead_code)]
    pub code_challenge_method: Option<String>,
}

#[derive(Deserialize)]
pub struct ApproveForm {
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub state: Option<String>,
    pub password: Option<String>,
}

#[derive(Deserialize)]
pub struct CallbackParams {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Option<Vec<String>>,
}

#[derive(Deserialize)]
pub struct TokenRequest {
    #[allow(dead_code)]
    pub grant_type: Option<String>,
    pub code: String,
    #[allow(dead_code)]
    pub redirect_uri: Option<String>,
    #[allow(dead_code)]
    pub client_id: Option<String>,
    #[allow(dead_code)]
    pub code_verifier: Option<String>,
}

pub fn approval_html(
    client_id: &str,
    redirect_uri: &str,
    state: &str,
    needs_password: bool,
    error: Option<&str>,
) -> String {
    let password_field = if needs_password {
        r#"<input type="password" name="password" placeholder="Password" required
             style="display:block;width:100%;padding:8px 10px;margin-bottom:12px;
                    font-size:15px;border:1px solid #ccc;border-radius:6px;box-sizing:border-box;">"#
    } else {
        ""
    };
    let error_html = if let Some(msg) = error {
        format!(r#"<p style="color:#c00;margin-bottom:16px;">{msg}</p>"#)
    } else {
        String::new()
    };
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
  <title>Sandcastle — MCP Access Request</title>
  <style>
    body {{ font-family: system-ui, sans-serif; max-width: 480px; margin: 80px auto; padding: 0 16px; }}
    h2 {{ margin-bottom: 8px; }}
    p {{ color: #555; margin-bottom: 24px; }}
    button {{ background: #1a1a1a; color: #fff; border: none; padding: 10px 20px;
              font-size: 15px; border-radius: 6px; cursor: pointer; width: 100%; }}
    button:hover {{ background: #333; }}
    code {{ background: #f4f4f4; padding: 2px 6px; border-radius: 4px; font-size: 13px; }}
  </style>
</head>
<body>
  <h2>MCP Access Request</h2>
  <p>Client <code>{client_id}</code> is requesting access to this Sandcastle MCP server.</p>
  {error_html}
  <form method="POST" action="/authorize/approve">
    <input type="hidden" name="client_id" value="{client_id}">
    <input type="hidden" name="redirect_uri" value="{redirect_uri}">
    <input type="hidden" name="state" value="{state}">
    {password_field}
    <button type="submit">Approve Access</button>
  </form>
</body>
</html>"#
    )
}

pub async fn oauth_protected_resource(
    Extension(auth): Extension<SharedAuthState>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "resource": auth.base_url,
        "authorization_servers": [auth.base_url]
    }))
}

pub async fn oauth_authorization_server(
    Extension(auth): Extension<SharedAuthState>,
) -> impl IntoResponse {
    Json(serde_json::json!({
        "issuer": auth.base_url,
        "authorization_endpoint": format!("{}/authorize", auth.base_url),
        "token_endpoint": format!("{}/token", auth.base_url),
        "registration_endpoint": format!("{}/register", auth.base_url),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "client_id_metadata_document_supported": true
    }))
}

pub async fn authorize_page(
    Extension(auth): Extension<SharedAuthState>,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    let client_id = params.client_id.unwrap_or_default();
    let redirect_uri = params.redirect_uri.unwrap_or_default();
    let client_state = params.state.unwrap_or_default();

    // Generate a server-side state to correlate the IdP callback with this request.
    let server_state = generate_token();
    let callback_url = format!("{}/auth/callback", auth.base_url);

    if let Some(idp_url) = auth.provider.redirect_url(&callback_url, &server_state) {
        let record = PendingAuthRecord {
            client_id,
            redirect_uri: if redirect_uri.is_empty() {
                None
            } else {
                Some(redirect_uri)
            },
            client_state: if client_state.is_empty() {
                None
            } else {
                Some(client_state)
            },
            expire_at: now_secs() + 600,
        };
        if let Err(e) = auth
            .store
            .set_pending_auth_request(&server_state, &record)
            .await
        {
            tracing::warn!("authorize_page: failed to store pending auth: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
        return (StatusCode::FOUND, [("Location", idp_url)]).into_response();
    }

    // Local provider: show approval form.
    let html = approval_html(
        &client_id,
        &redirect_uri,
        &client_state,
        auth.provider.needs_password(),
        None,
    );
    (StatusCode::OK, [("Content-Type", "text/html")], html).into_response()
}

pub async fn authorize_approve(
    Extension(auth): Extension<SharedAuthState>,
    Form(form): Form<ApproveForm>,
) -> Response {
    let provided = form.password.as_deref().unwrap_or("");
    if !auth.provider.check_password(provided) {
        debug!("approve: wrong password");
        let client_id = form.client_id.as_deref().unwrap_or("");
        let redirect_uri = form.redirect_uri.as_deref().unwrap_or("");
        let state = form.state.as_deref().unwrap_or("");
        let html = approval_html(
            client_id,
            redirect_uri,
            state,
            true,
            Some("Incorrect password."),
        );
        return (
            StatusCode::UNAUTHORIZED,
            [("Content-Type", "text/html")],
            html,
        )
            .into_response();
    }

    let code = generate_token();
    let client_id = form.client_id.clone().unwrap_or_default();
    let redirect_uri = form.redirect_uri.clone();
    let owner_key = format!("client:{client_id}");

    let record = PendingCodeRecord {
        expire_at: now_secs() + 300,
        redirect_uri: redirect_uri.clone(),
        client_id: client_id.clone(),
        owner_key,
    };
    if let Err(e) = auth.store.set_pending_code(&code, &record).await {
        tracing::warn!("authorize_approve: failed to store pending code: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
    }

    let base_redirect = redirect_uri.unwrap_or_else(|| format!("{}/", auth.base_url));
    let sep = if base_redirect.contains('?') {
        '&'
    } else {
        '?'
    };
    let location = if let Some(s) = &form.state {
        format!("{base_redirect}{sep}code={code}&state={s}")
    } else {
        format!("{base_redirect}{sep}code={code}")
    };

    debug!("approve: client_id={client_id:.8}... -> redirecting to {location:.60}...");
    (StatusCode::FOUND, [("Location", location)]).into_response()
}

pub async fn auth_callback(
    Extension(auth): Extension<SharedAuthState>,
    Query(params): Query<CallbackParams>,
) -> Response {
    if let Some(error) = params.error {
        return (
            StatusCode::BAD_REQUEST,
            format!("IdP returned an error: {error}"),
        )
            .into_response();
    }

    let code = match params.code {
        Some(c) => c,
        None => {
            return (StatusCode::BAD_REQUEST, "Missing code parameter").into_response();
        }
    };
    let state = match params.state {
        Some(s) => s,
        None => {
            return (StatusCode::BAD_REQUEST, "Missing state parameter").into_response();
        }
    };

    let pending = match auth.store.take_pending_auth_request(&state).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                "Unknown or expired authorization state",
            )
                .into_response();
        }
        Err(e) => {
            tracing::warn!("auth_callback: store error: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
        }
    };

    let callback_url = format!("{}/auth/callback", auth.base_url);
    let owner_key = match auth.provider.exchange_code(&code, &callback_url).await {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("auth_callback: exchange_code failed: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Authentication failed: {e}"),
            )
                .into_response();
        }
    };

    let auth_code = generate_token();
    let code_record = PendingCodeRecord {
        expire_at: now_secs() + 300,
        redirect_uri: pending.redirect_uri.clone(),
        client_id: pending.client_id.clone(),
        owner_key: owner_key.clone(),
    };
    if let Err(e) = auth.store.set_pending_code(&auth_code, &code_record).await {
        tracing::warn!("auth_callback: failed to store pending code: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Internal error").into_response();
    }

    let base_redirect = pending
        .redirect_uri
        .unwrap_or_else(|| format!("{}/", auth.base_url));
    let sep = if base_redirect.contains('?') {
        '&'
    } else {
        '?'
    };
    let location = if let Some(s) = pending.client_state {
        format!("{base_redirect}{sep}code={auth_code}&state={s}")
    } else {
        format!("{base_redirect}{sep}code={auth_code}")
    };

    debug!("auth_callback: owner={owner_key:.16}... -> redirecting to {location:.60}...");
    (StatusCode::FOUND, [("Location", location)]).into_response()
}

pub async fn token_endpoint(
    Extension(auth): Extension<SharedAuthState>,
    Form(req): Form<TokenRequest>,
) -> impl IntoResponse {
    let code_data = match auth.store.take_pending_code(&req.code).await {
        Ok(data) => data,
        Err(e) => {
            tracing::warn!("token_endpoint: store error: {e}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": "server_error",
                    "error_description": "Internal error"
                })),
            );
        }
    };

    match code_data {
        None => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Code not found or already used"
            })),
        ),
        Some(c) => {
            let token = generate_token();
            if let Err(e) = auth.store.set_token(&token, &c.owner_key).await {
                tracing::warn!("token_endpoint: failed to store token: {e}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": "server_error",
                        "error_description": "Internal error"
                    })),
                );
            }
            auth.on_tokens_changed().await;
            debug!(
                "token: issued {token:.8}... for owner {:.16}...",
                c.owner_key
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "access_token": token,
                    "token_type": "Bearer"
                })),
            )
        }
    }
}

pub async fn register_client(
    axum::extract::Json(req): axum::extract::Json<RegisterRequest>,
) -> impl IntoResponse {
    let client_id = generate_token();
    let name = req.client_name.unwrap_or_else(|| "MCP Client".to_string());
    let uris = req.redirect_uris.unwrap_or_default();
    debug!("register: client_name={name:?} redirect_uris={uris:?} -> client_id={client_id:.8}...");
    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "client_id": client_id,
            "client_name": name,
            "redirect_uris": uris,
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none"
        })),
    )
}
