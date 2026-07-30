//! Kappa-distribution protocol extension handlers.
//!
//! Implements the kappa-distribution spec endpoints beyond OCI:
//! - Edge CRUD with typed EdgeRelation enum
//! - Composition operations (g2/f4/e6/e7/e8) with witness creation
//! - Bundle create/ingest (KBND wire format)
//! - Filter registration and management
//! - Schema registration with evolution tracking
//! - GC pin/unpin/sweep/status
//! - Reconciliation protocol (fingerprint exchange, item sync)
//! - Transaction begin/put/commit/abort
//! - Sequence next/current
//! - Namespace root and Merkle proof
//! - Cascade delete (inverse GC)
//! - SSE event streaming

pub mod bundle;
pub mod cascade;
pub mod compose;
pub mod edge;
pub mod events_sse;
pub mod filter;
pub mod gc;
pub mod namespace;
pub mod reconcile;
pub mod schema;
pub mod sequence;
pub mod transaction;
pub mod ws_crdt;
pub mod ws_events;

use std::sync::Arc;

use topcoat::context::{app_context, request_context, try_app_context, Cx};
use topcoat::router::error::bad_request;
use topcoat::router::{to_bytes, Body, Response, RouterBuilder, StatusCode};

use kappa_core::identity::node::NodeIdentity;
use kappa_core::store::KappaStore;

/// Register all kappa-distribution extension routes.
pub fn register(builder: RouterBuilder) -> RouterBuilder {
    use std::borrow::Cow;
    use topcoat::router::{Method, Path, RouteFn};

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

    // WebSocket endpoints
    builder
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/_ws")),
            ws_events::ws_events_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/_crdt/{doc}/_ws")),
            ws_crdt::ws_crdt_route,
        ))
}

pub use ws_crdt::CrdtManager;

/// Get the store from app context.
pub(crate) fn store(cx: &Cx) -> &Arc<dyn KappaStore> {
    app_context::<Arc<dyn KappaStore>>(cx)
}

/// Extract a path parameter by name from the matched route.
pub(crate) fn path_param<'a>(cx: &'a Cx, key: &str) -> &'a str {
    use topcoat::router::RawPathParams;
    let params: &RawPathParams = request_context(cx);
    params
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
        .unwrap_or("")
}

/// Extract a query parameter by name.
pub(crate) fn query_param(cx: &Cx, key: &str) -> Option<String> {
    let query = topcoat::router::uri(cx).query()?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(percent_decode(v));
            }
        }
    }
    None
}

/// Read request body.
pub(crate) async fn read_body(body: Body) -> topcoat::Result<Vec<u8>> {
    let bytes = to_bytes(body, usize::MAX)
        .await
        .map_err(|e| bad_request(format!("failed to read request body: {e}")))?;
    Ok(bytes.to_vec())
}

/// Get the registry's own anchor for edge asserter field.
pub(crate) fn registry_anchor(cx: &Cx) -> String {
    match try_app_context::<Arc<NodeIdentity>>(cx) {
        Some(ni) => ni.anchor().as_str().to_string(),
        None => "kappa-distribution".to_string(),
    }
}

/// Convert StoreError to topcoat error.
pub(crate) fn store_err(e: kappa_core::StoreError) -> topcoat::Error {
    use kappa_core::StoreError;
    match &e {
        StoreError::NotFound(_) => topcoat::router::error::not_found().into(),
        StoreError::Conflict(_) => bad_request(e.to_string()).into(),
        StoreError::Rejected(msg) => bad_request(msg.clone()).into(),
        _ => bad_request(e.to_string()).into(),
    }
}

/// Build a JSON error envelope response.
pub(crate) fn error_response(
    status: StatusCode,
    code: &str,
    message: &str,
) -> topcoat::Result<Response> {
    let body = serde_json::json!({
        "errors": [{
            "code": code,
            "message": message,
        }]
    });
    let json = serde_json::to_string(&body).unwrap_or_default();
    let mut response = Response::new(Body::from(json));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
    Ok(response)
}

fn percent_decode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let hi = bytes.next().and_then(hex_val);
            let lo = bytes.next().and_then(hex_val);
            if let (Some(h), Some(l)) = (hi, lo) {
                result.push((h << 4 | l) as char);
            } else {
                result.push('%');
            }
        } else if b == b'+' {
            result.push(' ');
        } else {
            result.push(b as char);
        }
    }
    result
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
