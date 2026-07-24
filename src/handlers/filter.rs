use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::auth;
use crate::error::AppError;
use crate::store::KappaStore;
use crate::AppState;

pub async fn register(
    state: &AppState,
    ns: &str,
    scope: &str,
    body: &[u8],
) -> Result<Response, AppError> {
    auth::authorize(ns, "filter.register")?;

    let s = state.store.clone();
    let p = ns.to_string();
    let sc = scope.to_string();
    let content = body.to_vec();
    let kappa = tokio::task::spawn_blocking(move || s.filter_register(&p, &sc, &content)).await??;

    let s = state.store.clone();
    let k = kappa.clone();
    tokio::task::spawn_blocking(move || s.put_meta(&k, "object-type", b"filter")).await??;

    Ok((
        StatusCode::CREATED,
        [
            ("x-kappa-label", kappa),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response())
}

pub async fn list(state: &AppState, ns: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "filter.list")?;

    let s = state.store.clone();
    let p = ns.to_string();
    let records = tokio::task::spawn_blocking(move || s.filter_list(&p)).await??;
    let body = serde_json::json!({"filters": records});
    Ok((StatusCode::OK, Json(body)).into_response())
}

pub async fn delete(state: &AppState, ns: &str, filter_kappa: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "filter.delete")?;

    let s = state.store.clone();
    let fk = filter_kappa.to_string();
    let removed = tokio::task::spawn_blocking(move || s.filter_remove(&fk)).await??;
    if removed {
        Ok(StatusCode::ACCEPTED.into_response())
    } else {
        Err(AppError::BlobUnknown)
    }
}
