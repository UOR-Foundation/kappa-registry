use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::{bad_request, not_found};
use topcoat::router::{headers, Body, IntoResponse, Response, RouteFuture, StatusCode};

use crate::auth::authorize;
use crate::kappa::KappaLabel;
use crate::ratelimit::OpClass;
use crate::store::fs::FsStore;
use crate::store::KappaStore;
use crate::UploadTimeout;

use super::path_param;

fn query_param(cx: &Cx, key: &str) -> Option<String> {
    let query = topcoat::router::uri(cx).query()?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(super::tag::percent_decode(v));
            }
        }
    }
    None
}

fn store(cx: &Cx) -> &Arc<FsStore> {
    app_context::<Arc<FsStore>>(cx)
}

fn sessions(cx: &Cx) -> &Arc<SessionStore> {
    app_context::<Arc<SessionStore>>(cx)
}

fn upload_timeout(cx: &Cx) -> u64 {
    app_context::<UploadTimeout>(cx).0
}

pub struct SessionStore {
    sessions: RwLock<HashMap<String, UploadSession>>,
}

struct UploadSession {
    path: String,
    data: Vec<u8>,
    created_at: Instant,
}

impl SessionStore {
    pub fn new() -> Self {
        SessionStore {
            sessions: RwLock::new(HashMap::new()),
        }
    }

    fn create(&self, path: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut map = self.sessions.write().unwrap();
        map.insert(
            id.clone(),
            UploadSession {
                path: path.to_string(),
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

    fn append(&self, id: &str, offset: usize, chunk: &[u8]) -> Result<usize, ()> {
        let mut map = self.sessions.write().unwrap();
        let session = map.get_mut(id).ok_or(())?;
        if offset != session.data.len() {
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
            .map(|s| (s.path, s.data))
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

pub fn start_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = super::read_body(body).await?;
        let ns = path_param(cx, "ns");
        let digest = query_param(cx, "digest");
        let mount = query_param(cx, "mount");

        if let Some(ref digest) = digest {
            if !bytes.is_empty() {
                return super::blob::put(cx, ns, digest, &bytes).await;
            }
        }

        start(cx, ns, mount.as_deref()).await
    })
}

pub fn chunk_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = super::read_body(body).await?;
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
        let bytes = super::read_body(body).await?;
        let ns = path_param(cx, "ns");
        let id = path_param(cx, "id");
        let kappa = query_param(cx, "kappa")
            .or_else(|| query_param(cx, "digest"))
            .unwrap_or_default();
        let range_start = headers(cx)
            .get("content-range")
            .and_then(|v| v.to_str().ok())
            .and_then(parse_range_start);
        complete(cx, ns, id, &kappa, range_start, &bytes).await
    })
}

pub fn cancel_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let id = path_param(cx, "id");
        sessions(cx).remove(id);
        StatusCode::NO_CONTENT.into_response(cx)
    })
}

async fn start(cx: &Cx, ns: &str, mount_kappa: Option<&str>) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let a = asserter;
        move || authorize(&*s, &n, OpClass::Write, &a)
    })
    .await??;

    if let Some(kappa) = mount_kappa {
        let k = kappa.to_string();
        let exists = tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.exists(&k)
        })
        .await??;
        if exists {
            return (
                StatusCode::CREATED,
                [
                    ("location", crate::urls::blob_url(ns, kappa)),
                    ("content-length", "0".to_string()),
                ],
            )
                .into_response(cx);
        }
    }

    let id = sessions(cx).create(ns);
    (
        StatusCode::ACCEPTED,
        [
            ("location", crate::urls::upload_url(&id)),
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
                    ("location", crate::urls::upload_url(id)),
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
        sessions(cx).remove(id);
        return Err(not_found().into());
    }

    let received = sessions(cx).bytes_received(id).ok_or_else(not_found)?;
    let range = format!("0-{}", received.saturating_sub(1));
    (
        StatusCode::NO_CONTENT,
        [
            ("range", range),
            ("location", crate::urls::upload_url(id)),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

async fn complete(
    cx: &Cx,
    ns: &str,
    id: &str,
    kappa_str: &str,
    range_start: Option<usize>,
    final_body: &[u8],
) -> topcoat::Result<Response> {
    let timeout = upload_timeout(cx);
    if sessions(cx).is_expired(id, timeout) {
        sessions(cx).remove(id);
        return Err(not_found().into());
    }

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

    let (path, data) = sessions(cx).take(id).ok_or_else(not_found)?;

    let kappa = KappaLabel::parse(kappa_str)?;
    let computed = match kappa.axis() {
        "sha1" => KappaLabel::sha1(&data)?,
        "sha256" => KappaLabel::sha256(&data),
        "blake3" => KappaLabel::blake3(&data),
        "sha512" => KappaLabel::sha512(&data),
        _ => return Err(bad_request("unsupported axis").into()),
    };
    if computed != kappa {
        return Err(bad_request(format!(
            "digest invalid: expected {}, got {}",
            kappa.as_str(),
            computed.as_str()
        ))
        .into());
    }

    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let k = kappa_str.to_string();
    tokio::task::spawn_blocking(move || {
        authorize(&*s, &n, OpClass::Write, &asserter)?;
        s.put(&k, &data)
    })
    .await??;

    (
        StatusCode::CREATED,
        [
            ("x-kappa-label", kappa_str.to_string()),
            ("location", crate::urls::blob_url(&path, kappa_str)),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

pub fn parse_range_start(v: &str) -> Option<usize> {
    let v = v.trim();
    let v = v.strip_prefix("bytes").map(str::trim).unwrap_or(v);
    let range = v.split('/').next().unwrap_or(v);
    range.split('-').next()?.trim().parse().ok()
}
