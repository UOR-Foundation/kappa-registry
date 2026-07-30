//! WebSocket event streaming endpoint.
//!
//! GET /v2/{*ns}/_ws -- bidirectional namespace event stream.
//! Subprotocol: kappa-events.v1
//!
//! Clients receive events and can send commands:
//! - filter: subscribe to specific event types
//! - replay: request events since a given sequence ID
//! - awareness: broadcast ephemeral presence state

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use topcoat::context::{try_app_context, Cx};
use topcoat::router::FromRequest;
use topcoat::router::websocket::{Message, WebSocketUpgrade};
use topcoat::router::{Body, RouteFuture};

use kappa_core::events::EventLog;

use crate::path_param;

/// Client-to-server command protocol.
#[derive(serde::Deserialize)]
#[serde(tag = "type")]
enum ClientCommand {
    #[serde(rename = "filter")]
    Filter { event_types: Vec<String> },
    #[serde(rename = "replay")]
    Replay { since_id: u64 },
}

pub fn ws_events_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let ns = path_param(cx, "ns").to_string();
        let event_log = try_app_context::<Arc<dyn EventLog>>(cx).cloned();
        let upgrade = WebSocketUpgrade::from_request(cx, body).await?;

        upgrade
            .protocols(["kappa-events.v1"])
            .max_message_size(65536)
            .on_upgrade(move |mut socket| async move {
                let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
                let mut event_filter: Option<Vec<String>> = None;
                let mut last_seq: u64 = 0;

                loop {
                    tokio::select! {
                        msg = socket.recv() => {
                            match msg {
                                Some(Ok(Message::Text(text))) => {
                                    if let Ok(cmd) = serde_json::from_str::<ClientCommand>(text.as_str()) {
                                        match cmd {
                                            ClientCommand::Filter { event_types } => {
                                                event_filter = Some(event_types);
                                            }
                                            ClientCommand::Replay { since_id } => {
                                                if let Some(ref log) = event_log {
                                                    let events = log.since_sequence(&ns, since_id);
                                                    for event in events {
                                                        let json = serde_json::to_string(&event).unwrap_or_default();
                                                        if socket.send(Message::text(json)).await.is_err() {
                                                            return;
                                                        }
                                                        last_seq = event.sequence;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                Some(Ok(Message::Close(_))) | None => return,
                                _ => {}
                            }
                        }
                        _ = heartbeat.tick() => {
                            if socket.send(Message::Ping(Bytes::new())).await.is_err() {
                                return;
                            }
                            // Poll for new events since last seen
                            if let Some(ref log) = event_log {
                                let events = log.since_sequence(&ns, last_seq);
                                for event in events {
                                    if let Some(ref filter) = event_filter {
                                        if !filter.iter().any(|f| event.operation.as_str() == f.as_str()) {
                                            last_seq = event.sequence;
                                            continue;
                                        }
                                    }
                                    let json = serde_json::to_string(&event).unwrap_or_default();
                                    if socket.send(Message::text(json)).await.is_err() {
                                        return;
                                    }
                                    last_seq = event.sequence;
                                }
                            }
                        }
                    }
                }
            })
    })
}
