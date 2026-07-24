use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::auth;
use crate::error::AppError;
use crate::kappa::{axis_of, compute_kappa};
use crate::store::KappaStore;
use crate::AppState;

pub async fn register(
    state: &AppState,
    ns: &str,
    scope: &str,
    body: &[u8],
) -> Result<Response, AppError> {
    auth::authorize(ns, "schema.register")?;

    // B32: check for existing schema before registering
    let s = state.store.clone();
    let p = ns.to_string();
    let sc = scope.to_string();
    let old_schema = tokio::task::spawn_blocking({
        let s = s.clone();
        let p = p.clone();
        let sc = sc.clone();
        move || s.schema_get(&p, &sc)
    })
    .await??;
    let old_kappa = old_schema.map(|(k, _)| k);

    let content = body.to_vec();
    let kappa = tokio::task::spawn_blocking({
        let s = s.clone();
        let p = p.clone();
        let sc = sc.clone();
        let c = content.clone();
        move || s.schema_register(&p, &sc, &c)
    })
    .await??;

    let s = state.store.clone();
    let k = kappa.clone();
    tokio::task::spawn_blocking(move || s.put_meta(&k, "object-type", b"schema")).await??;

    // B32: create derives-from edge if schema content changed
    if let Some(ref old_k) = old_kappa {
        if *old_k != kappa {
            let axis = axis_of(&kappa).unwrap_or("sha256");
            let metadata = vec![0xA0u8];
            let canonical = super::edge::edge_canonical_pub(
                kappa.as_bytes(),
                "derives-from",
                old_k.as_bytes(),
                &metadata,
            );
            let edge_kappa = compute_kappa(axis, &canonical)?;
            let s = state.store.clone();
            let ek = edge_kappa.as_str().to_string();
            let canon = canonical.clone();
            tokio::task::spawn_blocking({
                let s = s.clone();
                let ek = ek.clone();
                move || s.put(&ek, &canon)
            })
            .await??;
            let new_k = kappa.clone();
            let old = old_k.clone();
            let n = ns.to_string();
            tokio::task::spawn_blocking(move || {
                s.edge_put(
                    &n,
                    &ek,
                    &new_k,
                    "derives-from",
                    &old,
                    &canonical,
                    serde_json::Value::Object(serde_json::Map::new()),
                )
            })
            .await??;
        }
    }

    Ok((
        StatusCode::CREATED,
        [
            ("x-kappa-label", kappa),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response())
}

pub async fn get(state: &AppState, ns: &str, scope: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "schema.get")?;

    let s = state.store.clone();
    let p = ns.to_string();
    let sc = scope.to_string();
    let result = tokio::task::spawn_blocking(move || s.schema_get(&p, &sc)).await??;
    let (kappa, content) = result.ok_or(AppError::BlobUnknown)?;

    Ok((
        StatusCode::OK,
        [
            ("content-length", content.len().to_string()),
            ("x-kappa-label", kappa),
            ("content-type", "application/octet-stream".to_string()),
        ],
        content,
    )
        .into_response())
}

pub async fn list(state: &AppState, ns: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "schema.list")?;

    let s = state.store.clone();
    let p = ns.to_string();
    let records = tokio::task::spawn_blocking(move || s.schema_list(&p)).await??;
    let body = serde_json::json!({"schemas": records});
    Ok((StatusCode::OK, Json(body)).into_response())
}
