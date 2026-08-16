//! OCI blob handlers: PUT, GET, HEAD, DELETE, range, meta query, list.
//!
//! Each handler: verify -> filter -> schema -> blob_put(client_digest, content)
//! -> blob_put_meta("content-type") -> response.
//! Content-type is per-blob metadata via blob_put_meta/blob_get_meta.
//! No _ct/ tags. No _also/ tags. Every digest algorithm is first-class.

use std::sync::Arc;

use futures_util::StreamExt;
use http_body::Frame;
use http_body_util::StreamBody;
use topcoat::context::{try_app_context, Cx};
use topcoat::router::error::bad_request;
use topcoat::router::{headers, Body, IntoResponse, Response, RouteFuture, StatusCode};

use kappa_core::kappa::verify_kappa;
use kappa_core::types::NamespaceRef;

use crate::{path_param, query_param, read_body, store, MaxBlobSize};

/// Chunk size for streaming blob downloads: 64 KiB per frame.
pub(crate) const STREAM_CHUNK_SIZE: usize = 65536;

/// Disk pressure flag set by periodic background check.
/// When true, blob writes are rejected with 507.
pub struct DiskPressure(pub std::sync::atomic::AtomicBool);

pub fn put_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = NamespaceRef::from(path_param(cx, "ns"));
        let client_digest = path_param(cx, "kappa");
        put(cx, &ns, client_digest, &bytes).await
    })
}

pub fn get_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = NamespaceRef::from(path_param(cx, "ns"));
        let kappa = path_param(cx, "kappa");
        get(cx, &ns, kappa).await
    })
}

pub fn head_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = NamespaceRef::from(path_param(cx, "ns"));
        let kappa = path_param(cx, "kappa");
        head(cx, &ns, kappa).await
    })
}

pub fn delete_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let kappa = path_param(cx, "kappa");
        delete(cx, kappa).await
    })
}

pub fn meta_list_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = NamespaceRef::from(path_param(cx, "ns"));
        meta_list(cx, &ns).await
    })
}

pub fn list_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        blob_list(cx).await
    })
}

// -- PUT ----------------------------------------------------------------------

pub(crate) async fn put(
    cx: &Cx,
    ns: &NamespaceRef,
    client_digest: &str,
    content: &[u8],
) -> topcoat::Result<Response> {
    let s = store(cx).clone();

    // MaxBlobSize enforcement
    if let Some(max) = try_app_context::<MaxBlobSize>(cx) {
        if content.len() > max.0 {
            return crate::oci_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "SIZE_EXCEEDED",
                &format!("body exceeds max blob size {}", max.0),
            );
        }
    }

    // Disk pressure check -- reject writes when disk below threshold
    if let Some(pressure) = try_app_context::<Arc<DiskPressure>>(cx) {
        if pressure.0.load(std::sync::atomic::Ordering::Relaxed) {
            return crate::oci_error(
                StatusCode::from_u16(507).unwrap(),
                "INSUFFICIENT_STORAGE",
                "disk pressure: insufficient space for write",
            );
        }
    }

    // Verify digest matches content -- BEFORE any store call
    let d = client_digest.to_string();
    let c = content.to_vec();
    let valid = tokio::task::spawn_blocking({
        let d = d.clone();
        let c = c.clone();
        move || verify_kappa(&d, &c)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(|e| bad_request(e.to_string()))?;

    if !valid {
        return crate::oci_error(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            &format!("computed digest does not match {}", client_digest),
        );
    }

    // Filter evaluation BEFORE storing
    if let Some(rejection) = crate::evaluate_filters(&s, ns, content).await? {
        return Ok(rejection);
    }

    // Schema validation BEFORE storing
    if let Some(rejection) = crate::validate_schemas(&s, ns, content).await? {
        return Ok(rejection);
    }

    // Also parameter: verify alternate axis digest
    if let Some(also) = query_param(cx, "also") {
        let also_d = also.clone();
        let also_c = c.clone();
        let also_valid = tokio::task::spawn_blocking(move || verify_kappa(&also_d, &also_c))
            .await
            .map_err(|e| bad_request(e.to_string()))?
            .map_err(|e| bad_request(e.to_string()))?;

        if !also_valid {
            return crate::oci_error(
                StatusCode::BAD_REQUEST,
                "DIGEST_INVALID",
                "also digest mismatch",
            );
        }
    }

    // Store blob at client's address
    let created = tokio::task::spawn_blocking({
        let s = s.clone();
        let d = d.clone();
        let c = c.clone();
        move || s.ingest_verified(&d,&c)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    // Store content-type metadata
    if let Some(ct) = headers(cx)
        .get("content-type")
        .and_then(|v| v.to_str().ok())
    {
        let ct_bytes = ct.as_bytes().to_vec();
        let d = d.clone();
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.blob_put_meta(&d, "content-type", &ct_bytes)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;
    }

    // Also parameter: store under alternate axis too
    if let Some(also) = query_param(cx, "also") {
        let also_k = also;
        let c = c.clone();
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.ingest_verified(&also_k,&c)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;
    }

    let status = if created.newly_stored {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let axis = client_digest.split(':').next().unwrap_or("sha256");

    (
        status,
        [
            ("location", format!("/v2/{}/blobs/{}", ns.as_str(), client_digest)),
            ("docker-content-digest", client_digest.to_string()),
            ("x-kappa-label", client_digest.to_string()),
            ("x-kappa-axis", axis.to_string()),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

// -- GET ----------------------------------------------------------------------

async fn get(cx: &Cx, _ns: &NamespaceRef, kappa: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let k = kappa.to_string();
    let axis = kappa.split(':').next().unwrap_or("sha256").to_string();

    // Content-type from blob metadata
    let ct = tokio::task::spawn_blocking({
        let s = s.clone();
        let k = k.clone();
        move || s.blob_get_meta(&k, "content-type")
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .ok()
    .and_then(|b| String::from_utf8(b).ok())
    .unwrap_or_else(|| "application/octet-stream".to_string());

    // Range request: use blob_size + blob_get_range, never read full blob
    if let Some(range_header) = headers(cx).get("range").and_then(|v| v.to_str().ok()) {
        if let Some(spec) = parse_range_header(range_header) {
            let total = tokio::task::spawn_blocking({
                let s = s.clone();
                let k = k.clone();
                move || s.blob_size(&k)
            })
            .await
            .map_err(|e| bad_request(e.to_string()))?
            .map_err(crate::store_err)?;

            let (offset, length) = resolve_range(&spec, total);
            if offset >= total || length == 0 {
                return (
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    [("content-range", format!("bytes */{total}"))],
                    "range not satisfiable",
                )
                    .into_response(cx);
            }
            let end = offset + length - 1;
            let slice = tokio::task::spawn_blocking({
                let s = s.clone();
                let k = k.clone();
                move || s.blob_get_range(&k, offset, length)
            })
            .await
            .map_err(|e| bad_request(e.to_string()))?
            .map_err(crate::store_err)?;

            return (
                StatusCode::PARTIAL_CONTENT,
                [
                    ("content-type", ct),
                    ("content-length", slice.len().to_string()),
                    ("content-range", format!("bytes {offset}-{end}/{total}")),
                    ("docker-content-digest", k.clone()),
                    ("x-kappa-label", k.clone()),
                    ("x-kappa-axis", axis),
                    ("accept-ranges", "bytes".to_string()),
                ],
                slice,
            )
                .into_response(cx);
        }
    }

    // Full GET -- stream from file, never buffer entire blob in memory
    let size = tokio::task::spawn_blocking({
        let s = s.clone();
        let k = k.clone();
        move || s.blob_size(&k)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let reader = tokio::task::spawn_blocking({
        let s = s.clone();
        let k = k.clone();
        move || s.blob_open(&k)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    // Bridge sync BlobReader to async stream via a bounded channel.
    // The blocking thread reads STREAM_CHUNK_SIZE bytes at a time from the
    // BlobReader (which may be a raw File or a FrameDecryptingReader) and
    // sends Bytes through the channel. Memory bounded: one chunk in flight.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<bytes::Bytes, std::io::Error>>(2);
    tokio::task::spawn_blocking(move || {
        use std::io::Read;
        let mut reader = reader;
        let mut buf = vec![0u8; STREAM_CHUNK_SIZE];
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if tx.blocking_send(Ok(bytes::Bytes::copy_from_slice(&buf[..n]))).is_err() {
                        break; // receiver dropped
                    }
                }
                Err(e) => {
                    let _ = tx.blocking_send(Err(e));
                    break;
                }
            }
        }
    });
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body_stream = StreamBody::new(stream.map(|r| r.map(|b| Frame::data(b)).map_err(|e| {
        Box::new(e) as Box<dyn std::error::Error + Send + Sync>
    })));
    let body = Body::new(body_stream);

    let mut response = Response::new(body);
    *response.status_mut() = StatusCode::OK;
    let h = response.headers_mut();
    h.insert("content-type", ct.parse().unwrap());
    h.insert("content-length", size.to_string().parse().unwrap());
    h.insert("docker-content-digest", k.parse().unwrap());
    h.insert("x-kappa-label", k.parse().unwrap());
    h.insert("x-kappa-axis", axis.parse().unwrap());
    h.insert("accept-ranges", "bytes".parse().unwrap());
    Ok(response)
}

// -- HEAD ---------------------------------------------------------------------

async fn head(cx: &Cx, _ns: &NamespaceRef, kappa: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let k = kappa.to_string();
    let axis = kappa.split(':').next().unwrap_or("sha256").to_string();

    let size = tokio::task::spawn_blocking({
        let s = s.clone();
        let k = k.clone();
        move || s.blob_size(&k)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let ct = tokio::task::spawn_blocking({
        let s = s.clone();
        let k = k.clone();
        move || s.blob_get_meta(&k, "content-type")
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .ok()
    .and_then(|b| String::from_utf8(b).ok())
    .unwrap_or_else(|| "application/octet-stream".to_string());

    (
        StatusCode::OK,
        [
            ("content-type", ct),
            ("content-length", size.to_string()),
            ("docker-content-digest", k.clone()),
            ("x-kappa-label", k.clone()),
            ("x-kappa-axis", axis),
            ("accept-ranges", "bytes".to_string()),
        ],
    )
        .into_response(cx)
}

// -- DELETE -------------------------------------------------------------------

async fn delete(cx: &Cx, kappa: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let k = kappa.to_string();
    tokio::task::spawn_blocking(move || s.blob_delete(&k))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;
    StatusCode::ACCEPTED.into_response(cx)
}

// -- META LIST ----------------------------------------------------------------

/// GET /v2/{ns}/blobs/_meta?key={key}&value={value}
async fn meta_list(cx: &Cx, ns: &NamespaceRef) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let key = query_param(cx, "key").unwrap_or_default();
    let value = query_param(cx, "value").unwrap_or_default();

    let kappas = tokio::task::spawn_blocking({
        let n = ns.clone();
        move || s.meta_query(&n, &key, &value)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let body = serde_json::json!({"kappas": kappas});
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

// -- BLOB LIST ----------------------------------------------------------------

/// GET /v2/{ns}/blobs/?prefix={prefix}
async fn blob_list(cx: &Cx) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let prefix = query_param(cx, "prefix").unwrap_or_default();

    let kappas = tokio::task::spawn_blocking(move || {
        let all = s.blob_list()?;
        if prefix.is_empty() {
            Ok::<Vec<String>, kappa_core::StoreError>(all)
        } else {
            Ok(all.into_iter().filter(|k| k.starts_with(&prefix)).collect())
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let body = serde_json::json!({"kappas": kappas});
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

// -- Range parsing ------------------------------------------------------------

enum RangeSpec {
    Range(u64, Option<u64>),
    Suffix(u64),
}

fn parse_range_header(header: &str) -> Option<RangeSpec> {
    let range = header.strip_prefix("bytes=")?;
    let (start_str, end_str) = range.split_once('-')?;
    if start_str.is_empty() {
        let suffix_len: u64 = end_str.parse().ok()?;
        return Some(RangeSpec::Suffix(suffix_len));
    }
    let start: u64 = start_str.parse().ok()?;
    let end: Option<u64> = if end_str.is_empty() {
        None
    } else {
        Some(end_str.parse().ok()?)
    };
    Some(RangeSpec::Range(start, end))
}

fn resolve_range(spec: &RangeSpec, total: u64) -> (u64, u64) {
    match spec {
        RangeSpec::Range(start, end) => {
            let end = end.map_or(total - 1, |e| std::cmp::min(e, total - 1));
            if end < *start {
                return (*start, 0);
            }
            (*start, end - start + 1)
        }
        RangeSpec::Suffix(n) => {
            let start = total.saturating_sub(*n);
            (start, total - start)
        }
    }
}
