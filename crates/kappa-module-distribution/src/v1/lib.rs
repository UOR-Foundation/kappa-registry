use std::borrow::Cow;

use topcoat::router::{Path, RouterBuilder};

pub fn p(s: &'static str) -> Cow<'static, Path> {
    Cow::Borrowed(Path::new(s))
}

/// Returns `{"errors": [{"code": ..., "message": "..."}]}` with the error's
/// HTTP status. A protocol error carries its own code; any other error is
/// identified by its status number.
/// Takes &HandlerError for handler_route! macro compatibility.
/// Returns a minimal 500 if response construction fails.
pub fn dist_error(e: &kappa_handler::HandlerError) -> topcoat::router::response::Response {
    let status = e.status();
    let body = match e {
        kappa_handler::HandlerError::Protocol { code, message, .. } => {
            serde_json::json!({"errors": [{"code": code, "message": message}]})
        }
        other => serde_json::json!({
            "errors": [{"code": status.as_u16().to_string(), "message": other.to_string()}]
        }),
    };
    kappa_handler::binary_response(
        status,
        "application/json",
        serde_json::to_vec(&body).expect("serde_json::Value serialization is infallible"),
    )
    .unwrap_or_else(|_| kappa_handler::empty_response(status))
}

/// Distribution protocol route macro via shared handler_route! infrastructure.
macro_rules! dist_route {
    ($method:expr, $path:expr, $handler:ident) => {
        kappa_handler::handler_route!($method, $crate::p($path), $handler, $crate::dist_error)
    };
}

use kappa_types::ProtocolId;
use std::sync::LazyLock;

static PROTOCOL_ID: LazyLock<ProtocolId> =
    LazyLock::new(|| ProtocolId::new("distribution").expect("valid protocol id"));

/// kappa-distribution extension protocol surface identifier.
pub fn protocol_id() -> &'static ProtocolId {
    &PROTOCOL_ID
}

pub mod bundle;
pub mod cascade;
pub mod compose;
mod delegation;
pub mod detect;
pub mod edge;
pub mod events_sse;
pub mod filter;
pub mod gc;
mod listing;
pub mod namespace;
pub mod reconcile;
pub mod schema;
pub mod sequence;
pub mod transaction;
pub mod ws_crdt;
pub mod ws_events;

pub use ws_crdt::CrdtManager;

/// Register all kappa-distribution extension routes.
pub fn register(builder: RouterBuilder) -> RouterBuilder {
    let builder = edge::register(builder);
    let builder = compose::register(builder);
    let builder = bundle::register(builder);
    let builder = filter::register(builder);
    let builder = schema::register(builder);
    let builder = gc::register(builder);
    let builder = reconcile::register(builder);
    let builder = transaction::register(builder);
    let builder = sequence::register(builder);
    let builder = namespace::register(builder);
    let builder = cascade::register(builder);
    let builder = events_sse::register(builder);
    let builder = ws_crdt::register(builder);
    ws_events::register(builder)
}
