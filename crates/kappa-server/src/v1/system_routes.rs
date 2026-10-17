//! System routes: server status, the registry version check, health
//! probes, node authority, and the OpenAPI document with its Scalar
//! reference.
//!
//! `GET /v2/` is the OCI distribution-spec base endpoint: a 200 answer is
//! how clients and the conformance suite detect a registry. The readiness
//! probe answers 503 while the disk-pressure monitor reports the store
//! volume below its threshold, while the node's authority is not fully
//! established (see [`authority_routes::ready`]), or when the store cannot
//! answer a read.

use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, Method, Path, RouteFn, RouterBuilder, StatusCode};

use kappa_handler::{
    HandlerError, binary_response, blocking, empty_response, json_response, path_param, store,
    try_service,
};
use kappa_store::kappa::Kappa;

use crate::node_authority::NodeAuthority;
use crate::tasks::disk_pressure::DiskPressure;
use crate::{authority_routes, detect, docs, openapi};

/// Protocol version reported by the version check.
const DISTRIBUTION_VERSION: &str = "2.0.0";

fn p(s: &'static str) -> Cow<'static, Path> {
    Cow::Borrowed(Path::new(s))
}

macro_rules! system_route {
    ($method:expr, $path:expr, $handler:path) => {
        kappa_handler::handler_route!($method, p($path), $handler, kappa_handler::error_response)
    };
}

// GET /_status. Body: not consumed.
async fn status(_cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    binary_response(StatusCode::OK, "text/plain; charset=utf-8", b"ok".to_vec())
}

// GET /v2/. Body: not consumed.
async fn version(_cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    json_response(
        StatusCode::OK,
        &serde_json::json!({ "kappa-distribution": DISTRIBUTION_VERSION }),
    )
}

// GET /v2/_health/{probe}. Body: not consumed. `ready` reports whether the
// node can serve; every other probe is liveness and answers 200.
async fn health(cx: &Cx, _body: Body) -> Result<Response, HandlerError> {
    if path_param(cx, "probe")? != "ready" {
        return Ok(empty_response(StatusCode::OK));
    }
    if try_service::<Arc<DiskPressure>>(cx)
        .is_some_and(|pressure| pressure.0.load(Ordering::Relaxed))
    {
        return Ok(empty_response(StatusCode::SERVICE_UNAVAILABLE));
    }
    if let Some(authority) = try_service::<Arc<NodeAuthority>>(cx)
        && !authority_routes::ready(authority, cx).await
    {
        return Ok(empty_response(StatusCode::SERVICE_UNAVAILABLE));
    }
    let s = store(cx);
    // A registry read through the settled catalog: the probe answers
    // whether the registry database serves, not whether content exists.
    match blocking(move || s.blob_exists(&Kappa::sha256(b""))).await {
        Ok(_) => Ok(empty_response(StatusCode::OK)),
        // An unreadable store is exactly what the probe reports: not ready.
        Err(error) => {
            tracing::warn!(%error, "readiness probe: store read failed");
            Ok(empty_response(StatusCode::SERVICE_UNAVAILABLE))
        }
    }
}

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(system_route!(
            Method::POST,
            detect::NODE_ROTATE_PATH,
            authority_routes::rotate_authority
        ))
        .route(system_route!(
            Method::GET,
            detect::NODE_AUTHORITY_PATH,
            authority_routes::authority_status
        ))
        .route(system_route!(Method::GET, "/_status", status))
        .route(system_route!(Method::GET, "/v2/", version))
        .route(system_route!(Method::GET, "/v2/_health/{probe}", health))
        .route(RouteFn::new(
            Method::GET,
            p(openapi::DOCUMENT_PATH),
            openapi::openapi_json_handler,
        ))
        .route(system_route!(
            Method::GET,
            docs::DOCS_PATH,
            docs::page_handler
        ))
        .route(system_route!(
            Method::GET,
            docs::SCALAR_ASSET_PATH,
            docs::asset_handler
        ))
}
