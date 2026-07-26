pub mod blob;
pub mod bundle;
pub mod compose;
pub mod edge;
pub mod filter;
pub mod gc;
pub mod reconcile;
pub mod referrers;
pub mod schema;
pub mod tag;
pub mod transaction;
pub mod upload;

use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::{bad_request, not_found};
use topcoat::router::{to_bytes, Body, IntoResponse, Response, RouteFuture, StatusCode};

use crate::store::fs::FsStore;
use crate::store::KappaStore;

/// Extract a path parameter by name from the matched route.
pub fn path_param<'a>(cx: &'a Cx, key: &str) -> &'a str {
    use topcoat::router::RawPathParams;
    let params: &RawPathParams = topcoat::context::request_context(cx);
    params
        .iter()
        .find(|(k, _)| *k == key)
        .map(|(_, v)| v)
        .unwrap_or("")
}

fn query_param(cx: &Cx, key: &str) -> Option<String> {
    let query = topcoat::router::uri(cx).query()?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(tag::percent_decode(v));
            }
        }
    }
    None
}

fn store(cx: &Cx) -> &Arc<FsStore> {
    app_context::<Arc<FsStore>>(cx)
}

/// Read the request body, returning a bad-request error on failure.
pub(crate) async fn read_body(body: Body) -> topcoat::Result<topcoat::router::Bytes> {
    to_bytes(body, usize::MAX)
        .await
        .map_err(|e| bad_request(format!("failed to read request body: {e}")).into())
}

/// Map a StoreError to the correct HTTP status code.
///
/// Used at every `.await?` boundary on store operations. Converts
/// NotFound to 404, Conflict to 409, bundle/delta errors to 400,
/// RangeNotSatisfiable to 400 (the 416 response with Content-Range
/// header is handled explicitly in the blob handler), and Io to 500.
pub(crate) fn store_err(e: crate::store::StoreError) -> topcoat::Error {
    use crate::store::StoreError;
    match e {
        StoreError::NotFound => not_found().into(),
        StoreError::Conflict(msg) => bad_request(format!("conflict: {msg}")).into(),
        StoreError::Io(e) => topcoat::Error::from(e),
        StoreError::RangeNotSatisfiable { size } => {
            bad_request(format!("range not satisfiable: size {size}")).into()
        }
        StoreError::BundleTrailerMismatch
        | StoreError::BundleDecodeLimitExceeded
        | StoreError::BundleDeltaInNoDeltaBundle
        | StoreError::BundleTruncated(_)
        | StoreError::BundleKappaMismatch(_)
        | StoreError::BundleUnsupportedEntryType(_) => bad_request(e.to_string()).into(),
        StoreError::DeltaTruncated(_)
        | StoreError::DeltaReservedOpcode
        | StoreError::DeltaBaseSizeMismatch { .. }
        | StoreError::DeltaResultSizeMismatch { .. }
        | StoreError::DeltaCopyOutOfBounds { .. }
        | StoreError::DeltaVarintOverflow
        | StoreError::DeltaUnresolvableBase(_) => bad_request(e.to_string()).into(),
    }
}

// -- Version check --

pub fn version(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let body = serde_json::json!({"kappa-distribution": "2.0.0"});
        (
            StatusCode::OK,
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response(cx)
    })
}

// -- Health probes --

pub fn health(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let probe = path_param(cx, "probe");
        match probe {
            "ready" => {
                let s = store(cx).clone();
                let root = s.root().to_path_buf();
                match tokio::task::spawn_blocking(move || tempfile::NamedTempFile::new_in(root))
                    .await
                {
                    Ok(Ok(_)) => StatusCode::OK.into_response(cx),
                    _ => StatusCode::SERVICE_UNAVAILABLE.into_response(cx),
                }
            }
            _ => StatusCode::OK.into_response(cx),
        }
    })
}

// -- Cascade delete --

pub fn cascade_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = path_param(cx, "ns");
        cascade(cx, ns, &bytes).await
    })
}

async fn cascade(cx: &Cx, ns: &str, body: &[u8]) -> topcoat::Result<Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))?;
    let prefix = v["prefix"].as_str().map(String::from);
    let roots: Vec<String> = v["roots"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let rels: Vec<String> = v["relations"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let s = store(cx).clone();
    let n = ns.to_string();
    let report = tokio::task::spawn_blocking(move || {
        let rel_refs: Vec<&str> = rels.iter().map(|s| s.as_str()).collect();
        if let Some(ref pfx) = prefix {
            s.remove_reachable_from_prefix(&n, pfx, &rel_refs)
        } else {
            s.remove_reachable(&n, &roots, &rel_refs)
        }
    })
    .await?
    .map_err(store_err)?;

    (
        StatusCode::OK,
        serde_json::to_string(&report).unwrap_or_default(),
    )
        .into_response(cx)
}

// -- Sequences --

pub fn sequence_next_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let name = path_param(cx, "name");
        let s = store(cx).clone();
        let n = ns.to_string();
        let nm = name.to_string();
        let val = tokio::task::spawn_blocking(move || s.sequence_next(&n, &nm))
            .await?
            .map_err(store_err)?;
        let body = serde_json::json!({"name": name, "value": val});
        (
            StatusCode::OK,
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response(cx)
    })
}

pub fn sequence_current_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let name = path_param(cx, "name");
        let s = store(cx).clone();
        let n = ns.to_string();
        let nm = name.to_string();
        let val = tokio::task::spawn_blocking(move || s.sequence_current(&n, &nm))
            .await?
            .map_err(store_err)?;
        let body = serde_json::json!({"name": name, "value": val});
        (
            StatusCode::OK,
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response(cx)
    })
}

// -- Namespace root --

pub fn namespace_root_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let s = store(cx).clone();
        let ns_str = ns.to_string();
        let (root, count) = tokio::task::spawn_blocking(move || s.namespace_root(&ns_str))
            .await?
            .map_err(store_err)?;

        let want_signed = query_param(cx, "signed").as_deref() == Some("true");
        if want_signed {
            if let Some(ref root_kappa) = root {
                if let Some(signer) = app_context::<crate::SignerHolder>(cx).0.as_ref() {
                    let timestamp = chrono::Utc::now().to_rfc3339();
                    let message = format!("{ns}\n{root_kappa}\n{timestamp}");
                    let sig = signer.sign(message.as_bytes()).unwrap_or_default();
                    let signed = crate::crypto::SignedRoot {
                        namespace: ns.to_string(),
                        root: root_kappa.clone(),
                        timestamp,
                        algorithm: signer.algorithm().to_string(),
                        public_key: signer.public_key_bytes(),
                        signature: sig,
                        attestation: None,
                    };
                    return (
                        StatusCode::OK,
                        serde_json::to_string(&signed).unwrap_or_default(),
                    )
                        .into_response(cx);
                }
            }
        }

        let body = serde_json::json!({"root": root, "count": count});
        (
            StatusCode::OK,
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response(cx)
    })
}

pub fn namespace_proof_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let name = path_param(cx, "name");
        let s = store(cx).clone();
        let ns_str = ns.to_string();
        let n = name.to_string();
        let proof = tokio::task::spawn_blocking(move || s.namespace_proof(&ns_str, &n))
            .await?
            .map_err(store_err)?;
        match proof {
            Some(p) => (
                StatusCode::OK,
                serde_json::to_string(&p).unwrap_or_default(),
            )
                .into_response(cx),
            None => Err(not_found().into()),
        }
    })
}
