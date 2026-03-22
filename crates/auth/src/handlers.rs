use axum::{
    Json,
    extract::{Extension, Form, Query},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tracing::debug;

use sandcastle_util::generate_token;

use super::{PendingCode, SharedAuthState, persist_tokens};

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
) -> impl IntoResponse {
    let client_id = params.client_id.unwrap_or_default();
    let redirect_uri = params.redirect_uri.unwrap_or_default();
    let state = params.state.unwrap_or_default();
    let html = approval_html(
        &client_id,
        &redirect_uri,
        &state,
        auth.password.is_some(),
        None,
    );
    (StatusCode::OK, [("Content-Type", "text/html")], html)
}

pub async fn authorize_approve(
    Extension(auth): Extension<SharedAuthState>,
    Form(form): Form<ApproveForm>,
) -> Response {
    if let Some(expected) = &auth.password {
        let provided = form.password.as_deref().unwrap_or("");
        if provided != expected.as_str() {
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
    }

    let code = generate_token();
    let client_id = form.client_id.clone().unwrap_or_default();
    let redirect_uri = form.redirect_uri.clone();

    {
        let mut codes = auth.pending_codes.write().unwrap();
        codes.insert(
            code.clone(),
            PendingCode {
                created_at: std::time::Instant::now(),
                redirect_uri: redirect_uri.clone(),
                client_id: client_id.clone(),
            },
        );
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

pub async fn token_endpoint(
    Extension(auth): Extension<SharedAuthState>,
    Form(req): Form<TokenRequest>,
) -> impl IntoResponse {
    let code_data = {
        let mut codes = auth.pending_codes.write().unwrap();
        codes.remove(&req.code)
    };

    match code_data {
        None => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Code not found or already used"
            })),
        ),
        Some(c) if c.created_at.elapsed() > std::time::Duration::from_secs(300) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Code expired"
            })),
        ),
        Some(c) => {
            let token = generate_token();
            {
                let mut tokens = auth.valid_tokens.write().unwrap();
                tokens.insert(token.clone(), c.client_id.clone());
                persist_tokens(&tokens);
            }
            debug!(
                "token: issued {token:.8}... for client {:.8}...",
                c.client_id
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

#[cfg(test)]
mod tests {
    use axum::{
        Extension, Router,
        body::Body,
        http::{Request, StatusCode},
        routing::{get, post},
    };
    use http_body_util::BodyExt;
    use std::{
        collections::HashMap,
        sync::{Arc, RwLock},
    };
    use tower::ServiceExt;

    use crate::{AuthState, SharedAuthState};

    fn make_auth(password: Option<&str>) -> SharedAuthState {
        Arc::new(AuthState {
            pending_codes: RwLock::new(HashMap::new()),
            valid_tokens: RwLock::new(HashMap::new()),
            base_url: "http://localhost".to_string(),
            no_auth: false,
            password: password.map(|s| s.to_string()),
        })
    }

    fn app(auth: SharedAuthState) -> Router {
        Router::new()
            .route(
                "/.well-known/oauth-protected-resource",
                get(super::oauth_protected_resource),
            )
            .route(
                "/.well-known/oauth-authorization-server",
                get(super::oauth_authorization_server),
            )
            .route("/authorize", get(super::authorize_page))
            .route("/authorize/approve", post(super::authorize_approve))
            .route("/token", post(super::token_endpoint))
            .route("/register", post(super::register_client))
            .layer(Extension(auth))
    }

    async fn body_str(body: axum::body::Body) -> String {
        let bytes = body.collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn protected_resource_returns_json() {
        let resp = app(make_auth(None))
            .oneshot(
                Request::get("/.well-known/oauth-protected-resource")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&body_str(resp.into_body()).await).unwrap();
        assert!(body["resource"].is_string());
        assert!(body["authorization_servers"].is_array());
    }

    #[tokio::test]
    async fn authorization_server_metadata() {
        let resp = app(make_auth(None))
            .oneshot(
                Request::get("/.well-known/oauth-authorization-server")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&body_str(resp.into_body()).await).unwrap();
        assert_eq!(body["issuer"], "http://localhost");
        assert!(body["authorization_endpoint"].is_string());
        assert!(body["token_endpoint"].is_string());
    }

    #[tokio::test]
    async fn authorize_page_returns_html() {
        let resp = app(make_auth(None))
            .oneshot(
                Request::get("/authorize?client_id=test-client&redirect_uri=http://cb&state=abc")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_str(resp.into_body()).await;
        assert!(body.contains("test-client"));
        assert!(body.contains("Approve Access"));
    }

    #[tokio::test]
    async fn register_client_returns_client_id() {
        let resp = app(make_auth(None))
            .oneshot(
                Request::post("/register")
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        r#"{"client_name":"TestApp","redirect_uris":["http://cb"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body: serde_json::Value =
            serde_json::from_str(&body_str(resp.into_body()).await).unwrap();
        assert!(body["client_id"].is_string());
        assert_eq!(body["client_name"], "TestApp");
    }

    #[tokio::test]
    async fn approve_then_exchange_token() {
        let auth = make_auth(None);
        let router = app(auth.clone());

        let resp = router
            .oneshot(
                Request::post("/authorize/approve")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "client_id=c1&redirect_uri=http%3A%2F%2Fcb&state=s1",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers()["location"].to_str().unwrap().to_string();
        assert!(location.contains("code="));

        let code = location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        let resp2 = app(auth)
            .oneshot(
                Request::post("/token")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "grant_type=authorization_code&code={code}"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&body_str(resp2.into_body()).await).unwrap();
        assert_eq!(body["token_type"], "Bearer");
        assert!(body["access_token"].is_string());
    }

    #[tokio::test]
    async fn token_with_bad_code_returns_400() {
        let resp = app(make_auth(None))
            .oneshot(
                Request::post("/token")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=authorization_code&code=notacode"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn approve_wrong_password_returns_401() {
        let resp = app(make_auth(Some("secret")))
            .oneshot(
                Request::post("/authorize/approve")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "client_id=c1&redirect_uri=http%3A%2F%2Fcb&state=s1&password=wrong",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn approve_correct_password_redirects() {
        let resp = app(make_auth(Some("secret")))
            .oneshot(
                Request::post("/authorize/approve")
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .body(Body::from(
                        "client_id=c1&redirect_uri=http%3A%2F%2Fcb&state=s1&password=secret",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
    }
}
