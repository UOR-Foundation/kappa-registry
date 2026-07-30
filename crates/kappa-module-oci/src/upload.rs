//! OCI chunked upload handlers: start, chunk, recovery, complete, cancel.
//!
//! Chunks are written to disk-backed staging files. At complete time,
//! the staging file is verified via streaming digest computation and
//! renamed to the blob path. No in-memory buffering of upload content.

use std::path::PathBuf;
use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::{bad_request, not_found};
use topcoat::router::{headers, Body, IntoResponse, Response, RouteFuture, StatusCode};

use kappa_core::kappa::{KappaLabel, Sha1Policy};
use kappa_core::store::blob_put_computed;

use crate::upload_session::{
    place_blob, verify_staged_digest, AppendError, SessionStore, VerifyError,
};
use crate::{path_param, query_param, read_body, store};

/// Blob root path, registered as app_context by kappa-server.
/// Used by the complete handler to compute blob paths for rename.
pub struct BlobRoot(pub PathBuf);

pub struct UploadTimeout(pub u64);

fn sessions(cx: &Cx) -> &Arc<SessionStore> {
    app_context::<Arc<SessionStore>>(cx)
}

fn upload_timeout(cx: &Cx) -> u64 {
    app_context::<UploadTimeout>(cx).0
}

// -- Route handlers -----------------------------------------------------------

pub fn start_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = path_param(cx, "ns");
        let digest = query_param(cx, "digest");
        let mount = query_param(cx, "mount");

        if let Some(ref digest) = digest {
            if !bytes.is_empty() {
                return crate::blob::put(cx, ns, digest, &bytes).await;
            }
        }

        start(cx, ns, mount.as_deref()).await
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
        sessions(cx).remove(id);
        StatusCode::NO_CONTENT.into_response(cx)
    })
}

// -- Handlers -----------------------------------------------------------------

async fn start(cx: &Cx, ns: &str, mount_kappa: Option<&str>) -> topcoat::Result<Response> {
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
                    ("location", format!("/v2/{}/blobs/{}", ns, kappa)),
                    ("content-length", "0".to_string()),
                    ("docker-content-digest", kappa.to_string()),
                ],
            )
                .into_response(cx);
        }
    }

    let id = sessions(cx).create(ns);

    let pin_ns = ns.to_string();
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
    let timeout = upload_timeout(cx);
    if sessions(cx).is_expired(id, timeout) {
        release_upload_pin(cx, id).await;
        sessions(cx).remove(id);
        return Err(not_found().into());
    }

    let offset = match (range_start, sessions(cx).bytes_received(id)) {
        (Some(start), Some(_)) => start as u64,
        (None, Some(received)) => received,
        (_, None) => return Err(not_found().into()),
    };

    match sessions(cx).append(id, offset, body) {
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
        Err(AppendError::NotFound) => Err(not_found().into()),
        Err(AppendError::OutOfOrder { .. }) => {
            (StatusCode::RANGE_NOT_SATISFIABLE, "out-of-order chunk").into_response(cx)
        }
        Err(AppendError::SizeExceeded(max)) => {
            crate::oci_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "SIZE_EXCEEDED",
                &format!("upload exceeds max size {max}"),
            )
        }
        Err(AppendError::Io(e)) => Err(bad_request(e.to_string()).into()),
    }
}

async fn recovery(cx: &Cx, id: &str) -> topcoat::Result<Response> {
    let timeout = upload_timeout(cx);
    if sessions(cx).is_expired(id, timeout) {
        release_upload_pin(cx, id).await;
        sessions(cx).remove(id);
        return Err(not_found().into());
    }

    let received = sessions(cx).bytes_received(id).ok_or_else(not_found)?;
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
    let timeout = upload_timeout(cx);
    if sessions(cx).is_expired(id, timeout) {
        release_upload_pin(cx, id).await;
        sessions(cx).remove(id);
        return Err(not_found().into());
    }

    // Append final chunk if present
    if !final_body.is_empty() {
        let offset = match (range_start, sessions(cx).bytes_received(id)) {
            (Some(start), Some(_)) => start as u64,
            (None, Some(received)) => received,
            (_, None) => return Err(not_found().into()),
        };
        match sessions(cx).append(id, offset, final_body) {
            Ok(_) => {}
            Err(AppendError::OutOfOrder { .. }) => {
                return (StatusCode::RANGE_NOT_SATISFIABLE, "out-of-order chunk")
                    .into_response(cx);
            }
            Err(AppendError::SizeExceeded(max)) => {
                return crate::oci_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "SIZE_EXCEEDED",
                    &format!("upload exceeds max size {max}"),
                );
            }
            Err(AppendError::NotFound) => return Err(not_found().into()),
            Err(AppendError::Io(e)) => return Err(bad_request(e.to_string()).into()),
        }
    }

    // Validate digest format before taking the staging path
    let _label = KappaLabel::parse(client_digest).map_err(|e| bad_request(e.to_string()))?;

    // Take staging path. Session removed. File NOT deleted.
    let (session_ns, staging_path) = sessions(cx).take(id).ok_or_else(not_found)?;

    let s = store(cx).clone();
    let blob_root = app_context::<BlobRoot>(cx).0.clone();
    let digest = client_digest.to_string();
    let ct = content_type.map(|s| s.to_string());
    let ns = session_ns.clone();

    // Streaming verify + rename in spawn_blocking (filesystem IO)
    let result = tokio::task::spawn_blocking({
        let s = s.clone();
        let digest = digest.clone();
        let staging = staging_path.clone();
        move || -> Result<String, topcoat::Error> {
            // Streaming digest verification. No memory spike.
            let sha1_policy = Sha1Policy::for_namespace(&*s, &ns);
            let verified = verify_staged_digest(&staging, &digest, sha1_policy)
                .map_err(|e| match &e {
                    VerifyError::Mismatch { .. } | VerifyError::Sha1Collision(_) => {
                        let _ = std::fs::remove_file(&staging);
                        bad_request(e.to_string())
                    }
                    VerifyError::AlgorithmDenied(_) => {
                        let _ = std::fs::remove_file(&staging);
                        bad_request(e.to_string())
                    }
                    _ => {
                        let _ = std::fs::remove_file(&staging);
                        bad_request(e.to_string())
                    }
                })?;

            // Rename staging file to blob path. Zero-copy.
            place_blob(&blob_root, &staging, &verified)
                .map_err(|e| bad_request(e.to_string()))?;

            // Store metadata for upgrade digest if present
            if let Some(ref upgrade) = verified.upgrade {
                let _ = s.blob_put_meta(upgrade, "content-type", b"application/octet-stream");
                let _ = s.blob_put_meta(upgrade, "upgrade-from", verified.primary.as_bytes());
            }

            Ok(verified.primary)
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))??;

    // Store content-type metadata
    if let Some(ct) = ct {
        let ct_bytes = ct.as_bytes().to_vec();
        let d = result.clone();
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.blob_put_meta(&d, "content-type", &ct_bytes)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;
    }

    release_upload_pin(cx, id).await;

    (
        StatusCode::CREATED,
        [
            ("x-kappa-label", result.clone()),
            ("docker-content-digest", result.clone()),
            ("location", format!("/v2/{}/blobs/{}", session_ns, result)),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

// -- Helpers ------------------------------------------------------------------

async fn release_upload_pin(cx: &Cx, id: &str) {
    if let Some(ns) = sessions(cx).namespace_for(id) {
        let s = store(cx).clone();
        let tag_name = format!("_upload/{}", id);
        let _ = tokio::task::spawn_blocking(move || s.tag_delete(&ns, &tag_name)).await;
    }
}

pub fn parse_range_start(v: &str) -> Option<usize> {
    let v = v.trim();
    let v = v.strip_prefix("bytes").map(str::trim).unwrap_or(v);
    let range = v.split('/').next().unwrap_or(v);
    range.split('-').next()?.trim().parse().ok()
}
