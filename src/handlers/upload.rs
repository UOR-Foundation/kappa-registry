use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::auth;
use crate::error::AppError;
use crate::kappa::KappaLabel;
use crate::store::KappaStore;
use crate::AppState;

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

pub async fn start(
    state: &AppState,
    ns: &str,
    mount_kappa: Option<&str>,
) -> Result<Response, AppError> {
    auth::authorize(ns, "upload.start")?;

    if let Some(kappa) = mount_kappa {
        let s = state.store.clone();
        let k = kappa.to_string();
        let exists = tokio::task::spawn_blocking(move || s.exists(&k)).await??;
        if exists {
            return Ok((
                StatusCode::CREATED,
                [
                    ("location", crate::routes::segments::blob_url(ns, kappa)),
                    ("content-length", "0".to_string()),
                ],
            )
                .into_response());
        }
    }

    let id = state.sessions.create(ns);
    Ok((
        StatusCode::ACCEPTED,
        [
            ("location", crate::routes::segments::upload_url(&id)),
            ("x-kappa-upload-session", id.clone()),
            ("x-kappa-chunk-min-length", "0".to_string()),
            ("oci-chunk-min-length", "0".to_string()),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response())
}

pub async fn chunk(
    state: &AppState,
    id: &str,
    range_start: Option<usize>,
    body: &[u8],
) -> Result<Response, AppError> {
    if state.sessions.is_expired(id, state.upload_timeout_secs) {
        state.sessions.remove(id);
        return Err(AppError::UploadNotFound);
    }

    let offset = match (range_start, state.sessions.bytes_received(id)) {
        (Some(start), Some(_)) => start,
        (None, Some(received)) => received,
        (_, None) => {
            return Err(AppError::UploadNotFound);
        }
    };

    match state.sessions.append(id, offset, body) {
        Ok(total) => {
            let range = format!("0-{}", total.saturating_sub(1));
            Ok((
                StatusCode::ACCEPTED,
                [
                    ("range", range),
                    ("location", crate::routes::segments::upload_url(id)),
                    ("content-length", "0".to_string()),
                ],
            )
                .into_response())
        }
        Err(()) => Err(AppError::RangeNotSatisfiable),
    }
}

pub async fn recovery(state: &AppState, id: &str) -> Result<Response, AppError> {
    if state.sessions.is_expired(id, state.upload_timeout_secs) {
        state.sessions.remove(id);
        return Err(AppError::UploadNotFound);
    }

    let received = state
        .sessions
        .bytes_received(id)
        .ok_or(AppError::UploadNotFound)?;
    let range = format!("0-{}", received.saturating_sub(1));
    Ok((
        StatusCode::NO_CONTENT,
        [
            ("range", range),
            ("location", crate::routes::segments::upload_url(id)),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response())
}

pub async fn complete(
    state: &AppState,
    id: &str,
    kappa_str: &str,
    range_start: Option<usize>,
    final_body: &[u8],
) -> Result<Response, AppError> {
    if state.sessions.is_expired(id, state.upload_timeout_secs) {
        state.sessions.remove(id);
        return Err(AppError::UploadNotFound);
    }

    if !final_body.is_empty() {
        let offset = match (range_start, state.sessions.bytes_received(id)) {
            (Some(start), Some(_)) => start,
            (None, Some(received)) => received,
            (_, None) => return Err(AppError::UploadNotFound),
        };
        if state.sessions.append(id, offset, final_body).is_err() {
            return Err(AppError::RangeNotSatisfiable);
        }
    }

    let (path, data) = state.sessions.take(id).ok_or(AppError::UploadNotFound)?;

    let kappa = KappaLabel::parse(kappa_str)?;
    let computed = match kappa.axis() {
        "sha1" => KappaLabel::sha1(&data)?,
        "sha256" => KappaLabel::sha256(&data),
        "blake3" => KappaLabel::blake3(&data),
        "sha512" => KappaLabel::sha512(&data),
        _ => return Err(AppError::NameInvalid("unsupported axis".to_string())),
    };
    if computed != kappa {
        return Err(AppError::digest_invalid(kappa.as_str(), computed.as_str()));
    }

    let s = state.store.clone();
    let k = kappa_str.to_string();
    tokio::task::spawn_blocking(move || s.put(&k, &data)).await??;

    Ok((
        StatusCode::CREATED,
        [
            ("x-kappa-label", kappa_str.to_string()),
            (
                "location",
                crate::routes::segments::blob_url(&path, kappa_str),
            ),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response())
}

pub fn cancel(state: &AppState, id: &str) -> Response {
    state.sessions.remove(id);
    StatusCode::NO_CONTENT.into_response()
}

pub fn parse_range_start(v: &str) -> Option<usize> {
    let v = v.trim();
    let v = v.strip_prefix("bytes").map(str::trim).unwrap_or(v);
    let range = v.split('/').next().unwrap_or(v);
    range.split('-').next()?.trim().parse().ok()
}
