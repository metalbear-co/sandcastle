use std::sync::Arc;

use axum::{
    Extension,
    extract::ws::{Message, WebSocket, WebSocketUpgrade},
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use sandcastle_sandbox_providers::{RookConnection, RookRegistry};
use tokio::sync::mpsc;

pub async fn rook_ws_handler(
    ws: WebSocketUpgrade,
    Extension(registry): Extension<Option<Arc<RookRegistry>>>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, registry))
}

async fn handle_socket(socket: WebSocket, registry: Option<Arc<RookRegistry>>) {
    let registry = match registry {
        Some(r) => r,
        None => {
            tracing::warn!("rook connected but no k8s provider is active");
            return;
        }
    };

    let (mut ws_tx, mut ws_rx) = socket.split();

    let sandbox_id = loop {
        match ws_rx.next().await {
            Some(Ok(Message::Text(text))) => {
                match serde_json::from_str::<sandcastle_rook_proto::RookResponse>(&text) {
                    Ok(sandcastle_rook_proto::RookResponse::Hello { sandbox_id }) => {
                        break sandbox_id;
                    }
                    _ => {
                        tracing::warn!("rook sent unexpected first message: {text}");
                        return;
                    }
                }
            }
            Some(Ok(Message::Close(_))) | None => return,
            Some(Err(e)) => {
                tracing::warn!("rook ws error before hello: {e}");
                return;
            }
            _ => continue,
        }
    };

    tracing::info!(sandbox_id, "rook hello received");

    let (to_rook_tx, mut to_rook_rx) = mpsc::unbounded_channel::<String>();
    let (from_rook_tx, from_rook_rx) = mpsc::unbounded_channel::<String>();

    if !registry.fulfill(
        &sandbox_id,
        RookConnection {
            sender: to_rook_tx,
            receiver: from_rook_rx,
        },
    ) {
        tracing::warn!(sandbox_id, "rook connected but no pending slot found");
        return;
    }

    let send_task = tokio::spawn(async move {
        while let Some(msg) = to_rook_rx.recv().await {
            if ws_tx.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });

    let recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Text(text) => {
                    if from_rook_tx.send(text.to_string()).is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
    });

    tokio::select! {
        _ = send_task => {}
        _ = recv_task => {}
    }
}
