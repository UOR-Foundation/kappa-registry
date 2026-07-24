//! HTTP handlers for bundle create and ingest.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::auth;
use crate::error::AppError;
use crate::store::KappaStore;
use crate::AppState;

pub async fn create(state: &AppState, ns: &str, body: &[u8]) -> Result<Response, AppError> {
    auth::authorize(ns, "bundle.create")?;

    let v: serde_json::Value = serde_json::from_slice(body)?;
    let kappas: Vec<String> = v["kappas"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let delta = v["delta"].as_bool().unwrap_or(false);

    if kappas.is_empty() {
        return Err(AppError::NameInvalid("empty kappas list".to_string()));
    }

    let s = state.store.clone();
    let bundle = tokio::task::spawn_blocking(move || s.bundle_create(&kappas, delta)).await??;

    Ok((
        StatusCode::OK,
        [("content-type", "application/x-kappa-bundle".to_string())],
        bundle,
    )
        .into_response())
}

pub async fn ingest(state: &AppState, ns: &str, body: &[u8]) -> Result<Response, AppError> {
    auth::authorize(ns, "bundle.ingest")?;

    let s = state.store.clone();
    let data = body.to_vec();
    let ingested = tokio::task::spawn_blocking(move || s.bundle_ingest(&data)).await??;

    let resp = serde_json::json!({"ingested": ingested});
    Ok((StatusCode::OK, Json(resp)).into_response())
}
