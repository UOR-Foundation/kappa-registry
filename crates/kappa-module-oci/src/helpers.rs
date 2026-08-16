//! Shared helper functions for OCI module handlers.

use std::sync::Arc;

use topcoat::context::{app_context, try_app_context, try_request_context, Cx};
use topcoat::router::error::bad_request;
use topcoat::router::request::Bytes;
use topcoat::router::response::Response;
use topcoat::router::{to_bytes, raw_path_params, Body, StatusCode};

use kappa_core::identity::node::NodeIdentity;
use kappa_core::store::KappaStore;
use kappa_core::types::NamespaceRef;

pub use kappa_core::types::MaxBlobSize;

/// Extract a path parameter by name from the matched route.
pub fn path_param<'a>(cx: &'a Cx, key: &str) -> &'a str {
    raw_path_params(cx)
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v.as_str())
        .unwrap_or("")
}

/// Extract a query parameter by name.
pub fn query_param(cx: &Cx, key: &str) -> Option<String> {
    let query = topcoat::router::request::uri(cx).query()?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(percent_decode(v));
            }
        }
    }
    None
}

/// Extract all values for a repeated query parameter.
pub fn query_params_multi(cx: &Cx, key: &str) -> Vec<String> {
    let Some(query) = topcoat::router::request::uri(cx).query() else {
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
pub fn store(cx: &Cx) -> &Arc<dyn KappaStore> {
    app_context::<Arc<dyn KappaStore>>(cx)
}

/// Resolve a namespace for write operations (PUT/POST/PATCH/DELETE).
/// Creates the namespace on first use (first-writer-claims).
/// Must be called inside spawn_blocking or from a blocking context.
pub fn resolve_ns_write(store: &dyn KappaStore, name: &str, owner: &str) -> Result<NamespaceRef, kappa_core::StoreError> {
    store.namespace_resolve_or_create(name, owner, Some("oci"))
}

/// Resolve a namespace for read operations (GET/HEAD).
/// Returns NotFound if the namespace does not exist.
/// Does NOT create the namespace -- prevents namespace squatting via pulls.
/// Must be called inside spawn_blocking or from a blocking context.
pub fn resolve_ns_read(store: &dyn KappaStore, name: &str) -> Result<NamespaceRef, kappa_core::StoreError> {
    store.namespace_resolve(name, Some("oci"))
}

/// Resolve a namespace from request context for write paths.
/// Extracts namespace name from path params and asserter from caller identity.
/// Returns the resolved NamespaceRef via spawn_blocking.
pub async fn resolve_ns_write_async(cx: &Cx) -> topcoat::Result<NamespaceRef> {
    let s = store(cx).clone();
    let name = path_param(cx, "ns").to_string();
    let owner = registry_anchor(cx);
    tokio::task::spawn_blocking(move || {
        s.namespace_resolve_or_create(&name, &owner, Some("oci"))
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(store_err)
}

/// Resolve a namespace from request context for read paths.
/// Returns topcoat not_found error if namespace does not exist.
pub async fn resolve_ns_read_async(cx: &Cx) -> topcoat::Result<NamespaceRef> {
    let s = store(cx).clone();
    let name = path_param(cx, "ns").to_string();
    tokio::task::spawn_blocking(move || {
        s.namespace_resolve(&name, Some("oci"))
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(store_err)
}

/// Get the registry's own anchor for edge asserter field.
pub fn registry_anchor(cx: &Cx) -> String {
    // Prefer the authenticated caller's identity from request context.
    // CallerIdentity is defined in kappa_core::types so protocol modules
    // and the server can share the type without circular dependencies.
    if let Some(caller) = try_request_context::<kappa_core::types::CallerIdentity>(cx) {
        if caller.0 != "anonymous" {
            return caller.0.clone();
        }
    }
    // Fall back to node anchor for unauthenticated deployments
    match try_app_context::<Arc<NodeIdentity>>(cx) {
        Some(ni) => ni.anchor().to_string(),
        None => "oci-distribution".to_string(),
    }
}

/// Convert StoreError to topcoat error with appropriate HTTP status.
pub fn store_err(e: kappa_core::StoreError) -> topcoat::Error {
    use kappa_core::StoreError;
    match &e {
        StoreError::NotFound(_) => topcoat::router::error::not_found().into(),
        StoreError::Conflict(_) => bad_request(e.to_string()).into(),
        StoreError::Rejected(msg) => bad_request(msg.clone()).into(),
        _ => bad_request(e.to_string()).into(),
    }
}

/// Build an OCI error envelope response.
pub fn oci_error(
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
pub async fn read_body(body: Body) -> topcoat::Result<Bytes> {
    to_bytes(body, usize::MAX)
        .await
        .map_err(|e| bad_request(format!("failed to read request body: {e}")).into())
}

pub fn percent_decode(s: &str) -> String {
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

/// Evaluate registered filters against content.
/// Must be called BEFORE blob_put -- rejected content is never stored.
/// Returns Ok(None) if all filters pass, Ok(Some(response)) if rejected.
pub async fn evaluate_filters(
    s: &Arc<dyn KappaStore>,
    ns: &NamespaceRef,
    content: &[u8],
) -> topcoat::Result<Option<Response>> {
    let n = ns.clone();
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
                if let Some(needle) = rule.strip_prefix("deny:") {
                    if !needle.is_empty()
                        && c.windows(needle.len()).any(|w| w == needle.as_bytes())
                    {
                        return Err(format!("filter {} rejected content", filter_tag.kappa));
                    }
                }
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
/// Must be called BEFORE blob_put -- rejected content is never stored.
pub async fn validate_schemas(
    s: &Arc<dyn KappaStore>,
    ns: &NamespaceRef,
    content: &[u8],
) -> topcoat::Result<Option<Response>> {
    let n = ns.clone();
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
