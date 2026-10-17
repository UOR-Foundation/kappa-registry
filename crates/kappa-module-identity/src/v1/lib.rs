//! Identity HTTP protocol module.
//!
//! Endpoints for assertions, resolution, revocation, watermarks,
//! absence proofs, anchors, identity bindings, succession chains,
//! and handle registry.

use std::borrow::Cow;

use topcoat::router::{Path, StatusCode};

use kappa_store::Kappa;

fn p(s: &'static str) -> Cow<'static, Path> {
    Cow::Borrowed(Path::new(s))
}

/// Convert HandlerError to a JSON identity error response.
/// Takes &HandlerError for handler_route! macro compatibility.
fn identity_error(e: &kappa_handler::HandlerError) -> topcoat::router::response::Response {
    let status = e.status();
    let body = serde_json::json!({
        "error": e.to_string(),
    });
    kappa_handler::json_response(status, &body)
        .unwrap_or_else(|_| kappa_handler::empty_response(StatusCode::INTERNAL_SERVER_ERROR))
}

/// Identity route macro via the shared handler_route! infrastructure,
/// which logs every handler failure before formatting it.
macro_rules! identity_route {
    ($method:expr, $path:expr, $handler:path) => {
        kappa_handler::handler_route!($method, $crate::p($path), $handler, $crate::identity_error)
    };
}

use kappa_types::ProtocolId;
use std::sync::LazyLock;

static IDENTITY_PROTOCOL: LazyLock<ProtocolId> =
    LazyLock::new(|| ProtocolId::new("identity").expect("valid protocol id"));
static EMAIL_PROTOCOL: LazyLock<ProtocolId> =
    LazyLock::new(|| ProtocolId::new("email").expect("valid protocol id"));
static DNS_PROTOCOL: LazyLock<ProtocolId> =
    LazyLock::new(|| ProtocolId::new("dns").expect("valid protocol id"));
static DID_PROTOCOL: LazyLock<ProtocolId> =
    LazyLock::new(|| ProtocolId::new("did").expect("valid protocol id"));
static FEDIVERSE_PROTOCOL: LazyLock<ProtocolId> =
    LazyLock::new(|| ProtocolId::new("fediverse").expect("valid protocol id"));

/// Identity HTTP protocol surface identifier.
pub fn protocol_id() -> &'static ProtocolId {
    &IDENTITY_PROTOCOL
}
/// Email handle verification protocol surface.
pub fn email_protocol() -> &'static ProtocolId {
    &EMAIL_PROTOCOL
}
/// DNS TXT handle verification protocol surface.
pub fn dns_protocol() -> &'static ProtocolId {
    &DNS_PROTOCOL
}
/// DID resolution handle verification protocol surface.
pub fn did_protocol() -> &'static ProtocolId {
    &DID_PROTOCOL
}
/// Fediverse WebFinger handle verification protocol surface.
pub fn fediverse_protocol() -> &'static ProtocolId {
    &FEDIVERSE_PROTOCOL
}

pub mod binding;
pub mod directory;
pub mod handle;
pub mod handlers;
pub mod succession;

/// Asserter filter registered in app context by the server.
/// The resolve handler reads this to filter resolution results
/// by asserter anchor.
pub struct AsserterFilter(pub Box<dyn Fn(&Kappa) -> bool + Send + Sync>);

pub use handlers::register;
