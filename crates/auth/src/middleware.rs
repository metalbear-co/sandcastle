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
            let raw = auth.valid_tokens.read().unwrap().get(t).cloned();
            if let Some(raw) = raw {
                // Legacy migration: tokens persisted before the owner_key change
                // had plain client_id values without a "prefix:" scheme.
                let owner_key = if raw.contains(':') {
                    raw
                } else {
                    format!("client:{raw}")
                };
                request.extensions_mut().insert(RequestIdentity {
                    owner_key,
                    client_id: None,
                    no_auth: false,
                });
                debug!("auth: token accepted");
                next.run(request).await
            } else {
                debug!("auth: unknown token {t:.8}...");
                (
                    StatusCode::UNAUTHORIZED,
                    [(
                        "WWW-Authenticate",
                        format!(
                            "Bearer realm=\"{base}\", resource_metadata=\"{base}/.well-known/oauth-protected-resource\"",
                            base = auth.base_url
                        ),
                    )],
                )
                    .into_response()
            }
        }
        None => {
            debug!("auth: no token");
            (
                StatusCode::UNAUTHORIZED,
                [(
                    "WWW-Authenticate",
                    format!(
                        "Bearer realm=\"{base}\", resource_metadata=\"{base}/.well-known/oauth-protected-resource\"",
                        base = auth.base_url
                    ),
                )],
            )
                .into_response()
        }
    }
}

