#![forbid(unsafe_code)]

use std::borrow::Cow;

use topcoat::router::{Path, StatusCode};

fn p(s: &'static str) -> Cow<'static, Path> {
    Cow::Borrowed(Path::new(s))
}

/// Convert HandlerError to XRPC JSON error envelope.
/// Takes &HandlerError for handler_route! macro compatibility.
/// Returns a minimal 500 if JSON serialization fails.
///
/// Protocol-specific error codes (HandleNotFound, InvalidSwap,
/// RepoNotFound, etc.) are carried in HandlerError::Protocol.
/// Generic errors map from HandlerError variants to XRPC error
/// names per the AT Protocol convention.
fn xrpc_error(e: &kappa_handler::HandlerError) -> topcoat::router::response::Response {
    use kappa_handler::HandlerError;
    let status = e.status();
    let (code, message) = match e {
        HandlerError::Protocol { code, message, .. } => {
            (code.as_str().to_string(), message.clone())
        }
        HandlerError::NotFound { reason } => ("NotFound".into(), reason.clone()),
        HandlerError::BadRequest { reason } => ("InvalidRequest".into(), reason.clone()),
        HandlerError::Unauthorized { reason } => ("AuthenticationRequired".into(), reason.clone()),
        HandlerError::Forbidden { reason } => ("Forbidden".into(), reason.clone()),
        HandlerError::Conflict { reason } => ("Conflict".into(), reason.clone()),
        HandlerError::BodyTooLarge { limit } => (
            "PayloadTooLarge".into(),
            format!("body exceeds {limit} byte limit"),
        ),
        HandlerError::Timeout { deadline_ms } => (
            "Timeout".into(),
            format!("operation exceeded {deadline_ms}ms"),
        ),
        _ => ("InternalServerError".into(), e.to_string()),
    };
    let body = serde_json::json!({
        "error": code,
        "message": message,
    });
    kappa_handler::json_response(status, &body)
        .unwrap_or_else(|_| kappa_handler::empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

/// XRPC route macro. Wraps async handlers with XRPC JSON error
/// conversion via the shared handler_route! infrastructure.
macro_rules! xrpc_route {
    ($method:expr, $path:expr, $handler:path) => {
        kappa_handler::handler_route!($method, $crate::p($path), $handler, $crate::xrpc_error)
    };
}

pub mod car;
pub mod cid;
pub mod commit;
pub mod dag_cbor;
pub mod detect;
pub mod handlers;
pub mod identity;
pub mod mst;
pub mod mst_node;
pub mod repo;
pub mod server;
pub mod session;
pub mod sync;
pub mod tid;

pub use detect::XrpcDetector;
pub use handlers::register;
pub use session::SessionStore;

use std::sync::LazyLock;

static PROTOCOL_ID: LazyLock<kappa_store::ProtocolId> =
    LazyLock::new(|| kappa_store::ProtocolId::new("atproto").expect("valid protocol id"));

/// AT Protocol surface identifier for namespace and handle scoping.
pub fn protocol_id() -> &'static kappa_store::ProtocolId {
    &PROTOCOL_ID
}
