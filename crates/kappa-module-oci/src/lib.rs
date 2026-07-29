//! OCI distribution protocol module for kappa-registry.
//!
//! Implements the OCI distribution spec v1.1 plus kappa tag extensions:
//! - Blob upload (monolithic + chunked), download, head, delete
//! - Manifest put/get/head/delete with schema/filter validation
//! - Tag list with full pagination (n, last, order, after, before)
//! - Tag batch, prefix delete, CRUD, get/put by path with CAS
//! - Referrers API

pub mod blob;
pub mod manifests;
pub mod referrers;
pub mod tags;
pub mod upload;

use std::borrow::Cow;
use std::sync::Arc;

use topcoat::context::{app_context, request_context, try_app_context, Cx};
use topcoat::router::error::bad_request;
use topcoat::router::{to_bytes, Body, Method, Path, Response, RouteFn, RouterBuilder, StatusCode};

use kappa_core::identity::node::NodeIdentity;
use kappa_core::store::KappaStore;

// MaxBlobSize is defined in kappa-core::types and re-exported here
// so both kappa-server and this module use the same type.
pub use kappa_core::types::MaxBlobSize;

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

/// Extract all values for a repeated query parameter (e.g. ?tag=a&tag=b).
pub(crate) fn query_params_multi(cx: &Cx, key: &str) -> Vec<String> {
    let Some(query) = topcoat::router::uri(cx).query() else {
        return Vec::new();
    };
    query
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k == key {
                Some(percent_decode(v))
            } else {
                None
            }
        })
        .collect()
}

/// Get the store from app context.
pub(crate) fn store(cx: &Cx) -> &Arc<dyn KappaStore> {
    app_context::<Arc<dyn KappaStore>>(cx)
}

/// Get the registry's own anchor kappa for use as edge asserter.
pub(crate) fn registry_anchor(cx: &Cx) -> String {
    match try_app_context::<Arc<NodeIdentity>>(cx) {
        Some(ni) => ni.anchor().to_string(),
        None => "oci-distribution".to_string(),
    }
}

/// Convert StoreError to topcoat error with appropriate HTTP status.
pub(crate) fn store_err(e: kappa_core::StoreError) -> topcoat::Error {
    use kappa_core::StoreError;
    match &e {
        StoreError::NotFound(_) => topcoat::router::error::not_found().into(),
        StoreError::Conflict(_) => bad_request(e.to_string()).into(),
        StoreError::Rejected(msg) => bad_request(msg.clone()).into(),
        _ => bad_request(e.to_string()).into(),
    }
}

/// Build an OCI error envelope response.
/// Format: {"errors":[{"code":"CODE","message":"message"}]}
pub(crate) fn oci_error(
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

/// Read request body.
pub(crate) async fn read_body(body: Body) -> topcoat::Result<topcoat::router::Bytes> {
    to_bytes(body, usize::MAX)
        .await
        .map_err(|e| bad_request(format!("failed to read request body: {e}")).into())
}

/// Evaluate registered filters against content.
///
/// Filters are stored as blobs with _filter/{scope} internal tags.
/// Each filter blob is JSON with deny: and/or accept_if rules.
/// Must be called BEFORE blob_put -- rejected content is never stored.
/// Returns Ok(None) if all filters pass, Ok(Some(response)) if rejected
/// with a 422 response ready to return.
pub(crate) async fn evaluate_filters(
    s: &Arc<dyn KappaStore>,
    ns: &str,
    content: &[u8],
) -> topcoat::Result<Option<Response>> {
    let n = ns.to_string();
    let c = content.to_vec();
    let result = tokio::task::spawn_blocking({
        let s = s.clone();
        move || -> Result<(), String> {
            let filters = s.tag_prefix(&n, "_filter/").map_err(|e| e.to_string())?;
            for filter_tag in &filters {
                let filter_bytes = match s.blob_get(&filter_tag.kappa) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let rule = String::from_utf8_lossy(&filter_bytes);

                // deny:<bytes> rule: reject if content contains the bytes
                if let Some(needle) = rule.strip_prefix("deny:") {
                    if !needle.is_empty() && c.windows(needle.len()).any(|w| w == needle.as_bytes())
                    {
                        return Err(format!("filter {} rejected content", filter_tag.kappa));
                    }
                }

                // json-match rule: accept_if.contains
                if rule.contains("json-match") || rule.contains("accept_if") {
                    if let Ok(filter_json) = serde_json::from_str::<serde_json::Value>(&rule) {
                        if let Some(needle) = filter_json
                            .get("accept_if")
                            .and_then(|a| a.get("contains"))
                            .and_then(|c| c.as_str())
                        {
                            let content_str = String::from_utf8_lossy(&c);
                            if !content_str.contains(needle) {
                                let reason = filter_json
                                    .get("reason")
                                    .and_then(|r| r.as_str())
                                    .unwrap_or("filter rejected");
                                return Err(format!("filter {}: {reason}", filter_tag.kappa));
                            }
                        }
                    }
                }
            }
            Ok(())
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?;

    match result {
        Ok(()) => Ok(None),
        Err(reason) => oci_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "FILTER_REJECTED",
            &format!("filter rejected: {reason}"),
        )
        .map(Some),
    }
}

/// Validate content against registered schemas.
///
/// Schemas are stored as blobs with _schema/{scope} internal tags.
/// Each schema blob is JSON with format and validation fields.
/// Must be called BEFORE blob_put -- rejected content is never stored.
pub(crate) async fn validate_schemas(
    s: &Arc<dyn KappaStore>,
    ns: &str,
    content: &[u8],
) -> topcoat::Result<Option<Response>> {
    let n = ns.to_string();
    let c = content.to_vec();
    let result = tokio::task::spawn_blocking({
        let s = s.clone();
        move || -> Result<(), String> {
            let schemas = s.tag_prefix(&n, "_schema/").map_err(|e| e.to_string())?;
            for schema_tag in &schemas {
                let schema_bytes = match s.blob_get(&schema_tag.kappa) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let wrapper: serde_json::Value = match serde_json::from_slice(&schema_bytes) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let format = wrapper.get("format").and_then(|f| f.as_str()).unwrap_or("");
                if format == "json-schema" {
                    if let Some(validation) = wrapper.get("validation") {
                        if let Ok(instance) = serde_json::from_slice::<serde_json::Value>(&c) {
                            if !jsonschema::is_valid(validation, &instance) {
                                return Err("content does not match schema".to_string());
                            }
                        }
                    }
                }
            }
            Ok(())
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?;

    match result {
        Ok(()) => Ok(None),
        Err(reason) => oci_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "SCHEMA_VIOLATION",
            &reason,
        )
        .map(Some),
    }
}

/// Register all OCI distribution spec routes on the router builder.
pub fn register(builder: RouterBuilder) -> RouterBuilder {
    let session_store = Arc::new(upload::SessionStore::new());
    let eviction_store = session_store.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            eviction_store.evict_expired(3600);
        }
    });

    builder
        .app_context(session_store)
        .app_context(upload::UploadTimeout(3600))
        // Blob metadata query
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/_meta")),
            blob::meta_list_route,
        ))
        // Blob list
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/")),
            blob::list_route,
        ))
        // Blob operations
        .route(RouteFn::new(
            Method::PUT,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/{kappa}")),
            blob::put_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/{kappa}")),
            blob::get_route,
        ))
        .route(RouteFn::new(
            Method::HEAD,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/{kappa}")),
            blob::head_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/{kappa}")),
            blob::delete_route,
        ))
        // Chunked upload start (namespace-scoped)
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/blobs/uploads/")),
            upload::start_route,
        ))
        // Upload operations (global, not namespace-scoped)
        .route(RouteFn::new(
            Method::PATCH,
            Cow::Borrowed(Path::new("/v2/_uploads/{id}")),
            upload::chunk_route,
        ))
        .route(RouteFn::new(
            Method::PUT,
            Cow::Borrowed(Path::new("/v2/_uploads/{id}")),
            upload::complete_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/_uploads/{id}")),
            upload::recovery_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            Cow::Borrowed(Path::new("/v2/_uploads/{id}")),
            upload::cancel_route,
        ))
        // Manifest operations
        .route(RouteFn::new(
            Method::PUT,
            Cow::Borrowed(Path::new("/v2/{*ns}/manifests/{reference}")),
            manifests::put_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/manifests/{reference}")),
            manifests::get_route,
        ))
        .route(RouteFn::new(
            Method::HEAD,
            Cow::Borrowed(Path::new("/v2/{*ns}/manifests/{reference}")),
            manifests::head_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            Cow::Borrowed(Path::new("/v2/{*ns}/manifests/{reference}")),
            manifests::delete_route,
        ))
        // Tag list
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/list")),
            manifests::tag_list_route,
        ))
        // Tag batch
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/_batch")),
            tags::tag_batch_route,
        ))
        // Tag prefix delete
        .route(RouteFn::new(
            Method::DELETE,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/_prefix")),
            tags::tag_delete_prefix_route,
        ))
        // Tag CRUD
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/")),
            tags::tag_crud_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/")),
            tags::tag_crud_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/")),
            tags::tag_crud_route,
        ))
        // Tag get/put by name
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/{name}")),
            tags::tag_get_route,
        ))
        .route(RouteFn::new(
            Method::PUT,
            Cow::Borrowed(Path::new("/v2/{*ns}/tags/{name}")),
            tags::tag_put_route,
        ))
        // Referrers
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/referrers/{digest}")),
            referrers::list_route,
        ))
}

pub(crate) fn percent_decode(s: &str) -> String {
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
