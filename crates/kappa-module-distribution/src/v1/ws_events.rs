//! WebSocket mutation events resumable from authenticated history.
//!
//! The connection subscribes to the namespace before reading it, then
//! sends `hello` with `after`, the history position it starts from (after
//! the current head). Every event is sent as
//! `{"type":"event","id":...,"event":{...}}`; `id` is the position after
//! the event (`epoch.consumed.root`). Commands:
//!
//! - `{"type":"filter","event_types":[...]}` delivers only those
//!   operations; others still advance the position;
//! - `{"type":"replay","after":"<id>"}` continues from `<id>`, or from the
//!   namespace's first epoch for `"0"`.
//!
//! A position history cannot continue from is answered with one
//! `{"type":"resync","reason":...,"after":...}` (`ahead`, `diverged` or
//! `unavailable`); delivery then waits for a `replay` command. Catch-up and
//! live delivery are one path, so nothing is delivered twice or skipped.

use std::sync::Arc;
use std::time::Duration;

use topcoat::context::Cx;
use topcoat::router::content::websocket::{Message, WebSocket, WebSocketUpgrade};
use topcoat::router::request::FromRequest;
use topcoat::router::{Body, RouterBuilder};

use kappa_handler::{
    Delivery, EventStream, HandlerError, MutationEventOp, Position, PublicationFeed, blocking,
    head_position, resolve_ns_read, store,
};

/// WebSocket write buffer cap in bytes. When the buffer is full,
/// `socket.send()` returns Err and the handler closes the connection; this
/// is the backpressure mechanism, set at upgrade time.
const MAX_WRITE_BUFFER_BYTES: usize = 1024 * 1024;

/// Event type names a subscriber may filter on: the `as_str` value of every
/// `MutationEventOp`, in declaration order.
pub const KNOWN_EVENT_TYPES: [&str; 16] = [
    MutationEventOp::TagSet.as_str(),
    MutationEventOp::TagDelete.as_str(),
    MutationEventOp::EdgePut.as_str(),
    MutationEventOp::EdgeDelete.as_str(),
    MutationEventOp::AssertionPublish.as_str(),
    MutationEventOp::RevocationPublish.as_str(),
    MutationEventOp::AnchorOrigin.as_str(),
    MutationEventOp::OperationPublish.as_str(),
    MutationEventOp::NamespaceUpdate.as_str(),
    MutationEventOp::SequenceUpdate.as_str(),
    MutationEventOp::MetadataUpdate.as_str(),
    MutationEventOp::ContentPublish.as_str(),
    MutationEventOp::ContentAlias.as_str(),
    MutationEventOp::ContentCompose.as_str(),
    MutationEventOp::ContentRetire.as_str(),
    MutationEventOp::RecordPublish.as_str(),
];

#[derive(serde::Deserialize)]
#[serde(tag = "type")]
enum ClientCommand {
    #[serde(rename = "filter")]
    Filter { event_types: Vec<String> },
    #[serde(rename = "replay")]
    Replay { after: String },
}

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder.route(dist_route!(
        topcoat::router::Method::GET,
        "/v2/{*ns}/_events/_ws",
        handler
    ))
}

fn json(value: &serde_json::Value) -> Message {
    Message::text(value.to_string())
}

/// The message for one delivery.
fn delivery_message(delivery: &Delivery) -> Message {
    match delivery {
        Delivery::Event(event) => json(&serde_json::json!({
            "type": "event",
            "id": event.id(),
            "event": event,
        })),
        Delivery::Gap { gap, after } => json(&serde_json::json!({
            "type": "resync",
            "reason": gap.as_str(),
            "after": after.id(),
        })),
    }
}

async fn handler(cx: &Cx, body: Body) -> Result<topcoat::router::response::Response, HandlerError> {
    let namespace = resolve_ns_read(cx)?;
    let feed = kappa_handler::try_service::<Arc<PublicationFeed>>(cx)
        .cloned()
        .ok_or_else(|| HandlerError::internal("event WebSocket requires PublicationFeed"))?;
    let store = store(cx);
    // Subscribe before the head is read, so a publication between the read
    // and the first wait is delivered.
    let mut stream = EventStream::new(store.clone(), &feed, namespace.clone(), Position::start());
    let head = blocking(move || head_position(&*store, &namespace)).await?;
    stream.reposition(head);

    let upgrade = WebSocketUpgrade::from_request(cx, body)
        .await
        .map_err(|e| HandlerError::bad_request(e.to_string()))?;
    upgrade
        .max_write_buffer_size(MAX_WRITE_BUFFER_BYTES)
        .protocols(["kappa-events.v1"])
        .max_message_size(65536)
        .on_upgrade(move |socket| serve(socket, stream))
        .map_err(|e| HandlerError::internal(e.to_string()))
}

async fn serve(mut socket: WebSocket, mut stream: EventStream) {
    let hello = json(&serde_json::json!({
        "type": "hello",
        "after": stream.position().id(),
    }));
    if socket.send(hello).await.is_err() {
        return;
    }
    let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
    heartbeat.tick().await;
    loop {
        tokio::select! {
            message = socket.recv() => match message {
                Some(Ok(Message::Text(text))) => {
                    if !command(&text, &mut stream, &mut socket).await {
                        return;
                    }
                }
                Some(Ok(Message::Close(_)) | Err(_)) | None => return,
                Some(Ok(_)) => {}
            },
            // Cancel-safe: the position advances only when an event is
            // returned, so a command arriving mid-read loses nothing.
            delivery = stream.next() => {
                if socket.send(delivery_message(&delivery)).await.is_err() {
                    return;
                }
            }
            _ = heartbeat.tick() => {
                if socket.send(Message::Ping(bytes::Bytes::new())).await.is_err() {
                    return;
                }
            }
        }
    }
}

/// Apply one client command; `false` when the connection must close.
async fn command(text: &str, stream: &mut EventStream, socket: &mut WebSocket) -> bool {
    let reply = match serde_json::from_str::<ClientCommand>(text) {
        Ok(ClientCommand::Filter { event_types }) => {
            let invalid: Vec<String> = event_types
                .iter()
                .filter(|name| !KNOWN_EVENT_TYPES.contains(&name.as_str()))
                .cloned()
                .collect();
            if invalid.is_empty() {
                stream.set_filter(move |event| {
                    event_types
                        .iter()
                        .any(|name| name == event.operation.as_str())
                });
                return true;
            }
            serde_json::json!({
                "error": "unknown_event_type",
                "invalid": invalid,
                "valid": KNOWN_EVENT_TYPES,
            })
        }
        Ok(ClientCommand::Replay { after }) => match Position::parse(&after) {
            Ok(position) => {
                stream.reposition(position);
                return true;
            }
            Err(message) => serde_json::json!({
                "error": "invalid_cursor",
                "message": message,
            }),
        },
        Err(error) => serde_json::json!({
            "error": "invalid_command",
            "message": error.to_string(),
        }),
    };
    socket.send(json(&reply)).await.is_ok()
}
