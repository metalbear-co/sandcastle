#[cfg(test)]
mod tests {
    use axum::{
        Extension, Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        response::IntoResponse,
        routing::get,
    };
    use std::{
        collections::HashMap,
        sync::{Arc, RwLock},
    };
    use tower::ServiceExt;

    use crate::{AuthState, SharedAuthState};

    fn make_auth(no_auth: bool, token: Option<&str>) -> SharedAuthState {
        let mut tokens = HashMap::new();
        if let Some(t) = token {
            tokens.insert(t.to_string(), "client".to_string());
        }
        Arc::new(AuthState {
            pending_codes: RwLock::new(HashMap::new()),
            valid_tokens: RwLock::new(tokens),
            base_url: "http://localhost".to_string(),
            no_auth,
            password: None,
        })
    }

    fn app(auth: SharedAuthState) -> Router {
        Router::new()
            .route("/protected", get(|| async { "ok".into_response() }))
            .route_layer(middleware::from_fn(super::require_auth))
            .layer(Extension(auth))
    }

    #[tokio::test]
    async fn no_token_returns_401() {
        let resp = app(make_auth(false, None))
            .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn invalid_token_returns_401() {
        let resp = app(make_auth(false, Some("good-token")))
            .oneshot(
                Request::get("/protected")
                    .header("Authorization", "Bearer bad-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_token_passes() {
        let resp = app(make_auth(false, Some("good-token")))
            .oneshot(
                Request::get("/protected")
                    .header("Authorization", "Bearer good-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn no_auth_mode_bypasses_check() {
        let resp = app(make_auth(true, None))
            .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn www_authenticate_header_present_on_401() {
        let resp = app(make_auth(false, None))
            .oneshot(Request::get("/protected").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert!(resp.headers().contains_key("www-authenticate"));
    }
}

use axum::{
    extract::Extension,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use tracing::debug;

use super::{RequestIdentity, SharedAuthState};

pub async fn require_auth(
    Extension(auth): Extension<SharedAuthState>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let token = request
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    let session_id = request
        .headers()
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("stateless")
        .to_string();

    if auth.no_auth {
        request.extensions_mut().insert(RequestIdentity {
            owner_key: format!("no-auth:{session_id}"),
            client_id: None,
            no_auth: true,
        });
        return next.run(request).await;
    }

    match token {
        Some(t) => {
            let client_id = auth.valid_tokens.read().unwrap().get(t).cloned();
            if let Some(client_id) = client_id {
                request.extensions_mut().insert(RequestIdentity {
                    owner_key: format!("client:{client_id}"),
                    client_id: Some(client_id),
                    no_auth: false,
                });
                debug!("auth: token accepted");
                next.run(request).await
            } else {
                debug!("auth: unknown token {t:.8}...");
                (StatusCode::UNAUTHORIZED, [("WWW-Authenticate",
                    format!("Bearer realm=\"{base}\", resource_metadata=\"{base}/.well-known/oauth-protected-resource\"",
                        base = auth.base_url))]).into_response()
            }
        }
        None => {
            debug!("auth: no token");
            (StatusCode::UNAUTHORIZED, [("WWW-Authenticate",
                format!("Bearer realm=\"{base}\", resource_metadata=\"{base}/.well-known/oauth-protected-resource\"",
                    base = auth.base_url))]).into_response()
        }
    }
}
