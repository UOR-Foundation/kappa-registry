use std::collections::HashMap;

use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::auth;
use crate::error::AppError;
use crate::kappa::{verify_kappa, KappaLabel};
use crate::store::KappaStore;
use crate::AppState;

pub fn version_check() -> Response {
    let body = serde_json::json!({"kappa-distribution": "2.0.0"});
    (StatusCode::OK, Json(body)).into_response()
}

pub async fn put(
    state: &AppState,
    ns: &str,
    kappa_str: &str,
    params: &HashMap<String, String>,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response, AppError> {
    auth::authorize(ns, "blob.put")?;

    if body.len() > state.max_blob_size {
        return Err(AppError::NameInvalid(format!(
            "body exceeds max blob size {}",
            state.max_blob_size
        )));
    }

    KappaLabel::parse(kappa_str)?;

    // Gate 1: admission filters (namespace-scoped)
    let s = state.store.clone();
    let ns_owned = ns.to_string();
    let body_owned = body.to_vec();
    let filter_result = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = ns_owned.clone();
        let b = body_owned.clone();
        move || s.filter_evaluate(&n, &b)
    })
    .await?;
    if let Err(reason) = filter_result {
        return Err(AppError::filter_rejected(&reason));
    }

    // Gate 2: verify-on-put
    match verify_kappa(kappa_str, &body_owned) {
        Ok(true) => {}
        Ok(false) => {
            return Err(AppError::digest_invalid(kappa_str, "content hash mismatch"));
        }
        Err(e) => return Err(AppError::from(e)),
    }

    // Gate 3: multi-label verification
    if let Some(also_str) = params.get("also") {
        match verify_kappa(also_str, &body_owned) {
            Ok(true) => {}
            Ok(false) => {
                return Err(AppError::digest_invalid(also_str, "also kappa mismatch"));
            }
            Err(e) => return Err(AppError::from(e)),
        }
    }

    // Store blob
    let s = state.store.clone();
    let k = kappa_str.to_string();
    let content = body_owned.clone();
    let created = tokio::task::spawn_blocking(move || s.put(&k, &content)).await??;

    // Store Content-Type metadata
    if let Some(ct) = headers.get("content-type") {
        if let Ok(ct_str) = ct.to_str() {
            let s = state.store.clone();
            let k = kappa_str.to_string();
            let ct_bytes = ct_str.as_bytes().to_vec();
            tokio::task::spawn_blocking(move || s.put_meta(&k, "content-type", &ct_bytes))
                .await??;
        }
    }

    // Store multi-label alias
    if let Some(also_str) = params.get("also") {
        let s = state.store.clone();
        let ak = also_str.clone();
        let content = body_owned;
        tokio::task::spawn_blocking(move || s.put(&ak, &content)).await??;
    }

    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        [
            ("x-kappa-label", kappa_str.to_string()),
            ("location", crate::routes::segments::blob_url(ns, kappa_str)),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response())
}

pub async fn get(state: &AppState, ns: &str, kappa: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "blob.get")?;

    let s = state.store.clone();
    let k = kappa.to_string();
    let content = tokio::task::spawn_blocking(move || s.get(&k)).await??;
    let content = content.ok_or(AppError::BlobUnknown)?;

    let s = state.store.clone();
    let k = kappa.to_string();
    let ct = tokio::task::spawn_blocking(move || s.get_meta(&k, "content-type"))
        .await??
        .and_then(|v| String::from_utf8(v).ok())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let axis = kappa.split(':').next().unwrap_or("sha256");

    Ok((
        StatusCode::OK,
        [
            ("content-length", content.len().to_string()),
            ("x-kappa-label", kappa.to_string()),
            ("x-kappa-axis", axis.to_string()),
            ("content-type", ct),
            ("docker-content-digest", kappa.to_string()),
        ],
        content,
    )
        .into_response())
}

pub async fn head(state: &AppState, ns: &str, kappa: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "blob.head")?;

    let s = state.store.clone();
    let k = kappa.to_string();
    let content = tokio::task::spawn_blocking(move || s.get(&k)).await??;
    let content = content.ok_or(AppError::BlobUnknown)?;

    let s = state.store.clone();
    let k = kappa.to_string();
    let ct = tokio::task::spawn_blocking(move || s.get_meta(&k, "content-type"))
        .await??
        .and_then(|v| String::from_utf8(v).ok())
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let axis = kappa.split(':').next().unwrap_or("sha256");

    Ok((
        StatusCode::OK,
        [
            ("content-length", content.len().to_string()),
            ("x-kappa-label", kappa.to_string()),
            ("x-kappa-axis", axis.to_string()),
            ("content-type", ct),
            ("docker-content-digest", kappa.to_string()),
        ],
    )
        .into_response())
}

pub async fn delete(state: &AppState, ns: &str, kappa: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "blob.delete")?;

    let s = state.store.clone();
    let k = kappa.to_string();
    tokio::task::spawn_blocking(move || s.remove(&k)).await??;
    Ok(StatusCode::ACCEPTED.into_response())
}

pub async fn list(state: &AppState, ns: &str, prefix: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "blob.list")?;

    let s = state.store.clone();
    let p = prefix.to_string();
    let kappas = tokio::task::spawn_blocking(move || s.list(&p)).await??;
    let body = serde_json::json!({"kappas": kappas});
    Ok((StatusCode::OK, Json(body)).into_response())
}

pub async fn list_by_meta(
    state: &AppState,
    ns: &str,
    key: &str,
    value: &str,
) -> Result<Response, AppError> {
    auth::authorize(ns, "blob.list_by_meta")?;

    let s = state.store.clone();
    let k = key.to_string();
    let v = value.to_string();
    let kappas = tokio::task::spawn_blocking(move || s.list_by_meta(&k, &v)).await??;
    let body = serde_json::json!({"kappas": kappas});
    Ok((StatusCode::OK, Json(body)).into_response())
}
