//! OCI chunked upload handlers: start, chunk, recovery, complete, cancel.
//!
//! Upload complete computes the digest under the client's axis via
//! compute_kappa(label.axis(), &data), verifies, then stores at the
//! client's address via blob_put(client_digest, &data).
//! GC pins use blob_put_computed (sha256 internally).

use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::{bad_request, not_found};
use topcoat::router::{headers, Body, IntoResponse, Response, RouteFuture, StatusCode};

use kappa_core::kappa::{compute_kappa, KappaLabel};
use kappa_core::store::blob_put_computed;

use crate::{path_param, query_param, read_body, store};

const DEFAULT_MAX_UPLOAD_SIZE: usize = 256 * 1024 * 1024;

pub struct SessionStore {
    sessions: RwLock<HashMap<String, UploadSession>>,
    max_upload_size: usize,
}

struct UploadSession {
    namespace: String,
    data: Vec<u8>,
    created_at: Instant,
}

impl SessionStore {
    pub fn new() -> Self {
        SessionStore {
            sessions: RwLock::new(HashMap::new()),
            max_upload_size: DEFAULT_MAX_UPLOAD_SIZE,
        }
    }

    fn create(&self, namespace: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut map = self.sessions.write().unwrap();
        map.insert(
            id.clone(),
            UploadSession {
                namespace: namespace.to_string(),
                data: Vec::new(),
                created_at: Instant::now(),
            },
        );
        id
    }

    fn is_expired(&self, id: &str, timeout_secs: u64) -> bool {
        let map = self.sessions.read().unwrap();
        map.get(id)
            .map(|s| s.created_at.elapsed().as_secs() > timeout_secs)
            .unwrap_or(true)
    }

    fn bytes_received(&self, id: &str) -> Option<usize> {
        self.sessions.read().unwrap().get(id).map(|s| s.data.len())
    }

    fn namespace_for(&self, id: &str) -> Option<String> {
        self.sessions
            .read()
            .unwrap()
            .get(id)
            .map(|s| s.namespace.clone())
    }

    fn append(&self, id: &str, offset: usize, chunk: &[u8]) -> Result<usize, ()> {
        let mut map = self.sessions.write().unwrap();
        let session = map.get_mut(id).ok_or(())?;
        if offset != session.data.len() {
            return Err(());
        }
        if session.data.len() + chunk.len() > self.max_upload_size {
            return Err(());
        }
        session.data.extend_from_slice(chunk);
        Ok(session.data.len())
    }

    fn take(&self, id: &str) -> Option<(String, Vec<u8>)> {
        self.sessions
            .write()
            .unwrap()
            .remove(id)
            .map(|s| (s.namespace, s.data))
    }

    fn remove(&self, id: &str) -> bool {
        self.sessions.write().unwrap().remove(id).is_some()
    }

    pub fn evict_expired(&self, timeout_secs: u64) -> usize {
        let mut map = self.sessions.write().unwrap();
        let before = map.len();
        map.retain(|_, s| s.created_at.elapsed().as_secs() <= timeout_secs);
        before - map.len()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

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

        // Monolithic upload: digest provided with body
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

    // Cross-repository mount: if the blob already exists, return 201
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

    // Create upload session GC pin
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
        (Some(start), Some(_)) => start,
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
        Err(()) => (StatusCode::RANGE_NOT_SATISFIABLE, "out-of-order chunk").into_response(cx),
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
            (Some(start), Some(_)) => start,
            (None, Some(received)) => received,
            (_, None) => return Err(not_found().into()),
        };
        if sessions(cx).append(id, offset, final_body).is_err() {
            return (StatusCode::RANGE_NOT_SATISFIABLE, "out-of-order chunk").into_response(cx);
        }
    }

    let (session_ns, data) = sessions(cx).take(id).ok_or_else(not_found)?;

    // Compute digest under client's axis, verify
    let label = KappaLabel::parse(client_digest).map_err(|e| bad_request(e.to_string()))?;
    let computed = compute_kappa(label.axis(), &data).map_err(|e| bad_request(e.to_string()))?;

    if computed.as_str() != client_digest {
        release_upload_pin(cx, id).await;
        return Err(bad_request(format!(
            "digest invalid: expected {}, got {}",
            client_digest,
            computed.as_str()
        ))
        .into());
    }

    // Store blob at client's address
    let s = store(cx).clone();
    let d = client_digest.to_string();
    let c = data;
    tokio::task::spawn_blocking({
        let s = s.clone();
        let d = d.clone();
        move || s.blob_put(&d, &c)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    // Store content-type metadata
    if let Some(ct) = content_type {
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

    // Release the upload session GC pin
    release_upload_pin(cx, id).await;

    let url_ns = &session_ns;
    (
        StatusCode::CREATED,
        [
            ("x-kappa-label", client_digest.to_string()),
            ("docker-content-digest", client_digest.to_string()),
            (
                "location",
                format!("/v2/{}/blobs/{}", url_ns, client_digest),
            ),
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
