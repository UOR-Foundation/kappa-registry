//! OCI chunked upload handlers: start, chunk, recovery, complete, cancel.
//!
//! Upload state is managed via KappaStore trait methods:
//! upload_begin, upload_put_part, upload_complete, upload_abort,
//! upload_bytes_received. The store owns staging files, eviction,
//! and encryption.

use topcoat::context::{app_context, Cx};
use topcoat::router::error::{bad_request, not_found};
use topcoat::router::{headers, Body, IntoResponse, Response, RouteFuture, StatusCode};

use kappa_core::kappa::KappaLabel;
use kappa_core::store::blob_put_computed;
use kappa_core::types::{MaxBlobSize, NamespaceRef};

use crate::{path_param, query_param, read_body, store};

pub struct UploadTimeout(pub u64);

fn max_blob_size(cx: &Cx) -> u64 {
    app_context::<MaxBlobSize>(cx).0 as u64
}

// -- Route handlers -----------------------------------------------------------

pub fn start_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = NamespaceRef::from(path_param(cx, "ns"));
        let digest = query_param(cx, "digest");
        let mount = query_param(cx, "mount");

        if let Some(ref digest) = digest {
            if !bytes.is_empty() {
                return crate::blob::put(cx, &ns, digest, &bytes).await;
            }
        }

        start(cx, &ns, mount.as_deref()).await
    })
}

pub fn chunk_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let id = path_param(cx, "id");
        let range_start = headers(cx)
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_range_start);
        chunk(cx, id, range_start, &bytes).await
    })
}

pub fn recovery_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let id = path_param(cx, "id");
        recovery(cx, id).await
    })
}

pub fn complete_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let id = path_param(cx, "id");
        let client_digest = query_param(cx, "kappa")
            .or_else(|| query_param(cx, "digest"))
            .unwrap_or_default();
        let content_type = headers(cx)
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let range_start = headers(cx)
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_range_start);
        complete(
            cx,
            id,
            &client_digest,
            content_type.as_deref(),
            range_start,
            &bytes,
        )
        .await
    })
}

pub fn cancel_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let id = path_param(cx, "id");
        release_upload_pin(cx, id).await;
        let s = store(cx).clone();
        let upload_id = id.to_string();
        let _ = tokio::task::spawn_blocking(move || s.upload_abort(&upload_id)).await;
        StatusCode::NO_CONTENT.into_response(cx)
    })
}

// -- Handlers -----------------------------------------------------------------

async fn start(cx: &Cx, ns: &NamespaceRef, mount_kappa: Option<&str>) -> topcoat::Result<Response> {
    let s = store(cx).clone();

    if let Some(kappa) = mount_kappa {
        let k = kappa.to_string();
        let exists = tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.blob_exists(&k)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;
        if exists {
            return (
                StatusCode::CREATED,
                [
                    ("location", format!("/v2/{}/blobs/{}", ns.as_str(), kappa)),
                    ("content-length", "0".to_string()),
                    ("docker-content-digest", kappa.to_string()),
                ],
            )
                .into_response(cx);
        }
    }

    let max_size = max_blob_size(cx);
    let n = ns.clone();
    let id = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.upload_begin(&n, max_size)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    // Pin the upload in the namespace so GC does not sweep in-flight content
    let pin_ns = ns.clone();
    let pin_id = id.clone();
    tokio::task::spawn_blocking({
        let s = s.clone();
        move || {
            let pin_kappa = blob_put_computed(&*s, b"upload-session-pin")?;
            s.tag_set(&pin_ns, &format!("_upload/{}", pin_id), &pin_kappa)
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    (
        StatusCode::ACCEPTED,
        [
            ("location", format!("/v2/_uploads/{}", id)),
            ("x-kappa-upload-session", id.clone()),
            ("x-kappa-chunk-min-length", "0".to_string()),
            ("oci-chunk-min-length", "0".to_string()),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

async fn chunk(
    cx: &Cx,
    id: &str,
    range_start: Option<usize>,
    body: &[u8],
) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let upload_id = id.to_string();

    // Determine offset: from Content-Range header or from bytes received
    let received = s.upload_bytes_received(&upload_id)
        .ok_or_else(not_found)?;
    let offset = match range_start {
        Some(start) => start as u64,
        None => received,
    };

    let data = body.to_vec();
    let result = tokio::task::spawn_blocking({
        let s = s.clone();
        let uid = upload_id.clone();
        move || s.upload_put_part(&uid, offset, &data)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?;

    match result {
        Ok(total) => {
            let range = format!("0-{}", total.saturating_sub(1));
            (
                StatusCode::ACCEPTED,
                [
                    ("range", range),
                    ("location", format!("/v2/_uploads/{}", id)),
                    ("content-length", "0".to_string()),
                ],
            )
                .into_response(cx)
        }
        Err(kappa_core::types::StoreError::NotFound(_)) => Err(not_found().into()),
        Err(kappa_core::types::StoreError::Conflict(_)) => {
            (StatusCode::RANGE_NOT_SATISFIABLE, "out-of-order chunk").into_response(cx)
        }
        Err(kappa_core::types::StoreError::Rejected(msg)) => {
            crate::oci_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "SIZE_EXCEEDED",
                &msg,
            )
        }
        Err(e) => Err(bad_request(e.to_string()).into()),
    }
}

async fn recovery(cx: &Cx, id: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let received = s.upload_bytes_received(id).ok_or_else(not_found)?;
    let range = format!("0-{}", received.saturating_sub(1));
    (
        StatusCode::NO_CONTENT,
        [
            ("range", range),
            ("location", format!("/v2/_uploads/{}", id)),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

async fn complete(
    cx: &Cx,
    id: &str,
    client_digest: &str,
    content_type: Option<&str>,
    range_start: Option<usize>,
    final_body: &[u8],
) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let upload_id = id.to_string();

    // Check upload exists
    if s.upload_bytes_received(&upload_id).is_none() {
        return Err(not_found().into());
    }

    // Validate digest format
    let _label = KappaLabel::parse(client_digest).map_err(|e| bad_request(e.to_string()))?;

    // Append final chunk if present
    if !final_body.is_empty() {
        let offset = match range_start {
            Some(start) => start as u64,
            None => s.upload_bytes_received(&upload_id).unwrap_or(0),
        };
        let data = final_body.to_vec();
        let uid = upload_id.clone();
        let result = tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.upload_put_part(&uid, offset, &data)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?;

        match result {
            Ok(_) => {}
            Err(kappa_core::types::StoreError::Conflict(_)) => {
                return (StatusCode::RANGE_NOT_SATISFIABLE, "out-of-order chunk")
                    .into_response(cx);
            }
            Err(kappa_core::types::StoreError::Rejected(msg)) => {
                return crate::oci_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "SIZE_EXCEEDED",
                    &msg,
                );
            }
            Err(kappa_core::types::StoreError::NotFound(_)) => {
                return Err(not_found().into());
            }
            Err(e) => return Err(bad_request(e.to_string()).into()),
        }
    }

    // Streaming hash verification + store
    let digest = client_digest.to_string();
    let uid = upload_id.clone();
    let result = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.upload_complete(&uid, Some(digest.as_str()))
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?;

    let ingest_result = match result {
        Ok(r) => r,
        Err(kappa_core::types::StoreError::Rejected(msg)) => {
            return crate::oci_error(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                &msg,
            );
        }
        Err(e) => return Err(bad_request(e.to_string()).into()),
    };

    let result_kappa = ingest_result.kappa.clone();

    // Store content-type metadata
    if let Some(ct) = content_type {
        let ct_bytes = ct.as_bytes().to_vec();
        let d = result_kappa.clone();
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.blob_put_meta(&d, "content-type", &ct_bytes)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;
    }

    release_upload_pin(cx, id).await;

    let ns = path_param(cx, "ns");

    (
        StatusCode::CREATED,
        [
            ("x-kappa-label", result_kappa.clone()),
            ("docker-content-digest", result_kappa.clone()),
            ("location", format!("/v2/{}/blobs/{}", ns, result_kappa)),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

// -- Helpers ------------------------------------------------------------------

async fn release_upload_pin(cx: &Cx, id: &str) {
    let s = store(cx).clone();
    let upload_id = id.to_string();
    let _ = tokio::task::spawn_blocking(move || {
        if let Some(ns_str) = s.upload_namespace(&upload_id) {
            let ns = NamespaceRef::from(ns_str);
            let tag_name = format!("_upload/{}", upload_id);
            let _ = s.tag_delete(&ns, &tag_name);
        }
    })
    .await;
}

pub fn parse_range_start(v: &str) -> Option<usize> {
    let v = v.trim();
    let v = v.strip_prefix("bytes").map(str::trim).unwrap_or(v);
    let range = v.split('/').next().unwrap_or(v);
    range.split('-').next()?.trim().parse().ok()
}
