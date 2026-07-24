//! Multi-object transaction HTTP handlers (P3).
//!
//! POST   /v2/{ns}/_transaction/begin          Begin a new transaction
//! PUT    /v2/{ns}/_transaction/{id}/{kappa}    Stage a blob in the transaction
//! POST   /v2/{ns}/_transaction/{id}/commit     Commit (promote all staged objects)
//! DELETE /v2/{ns}/_transaction/{id}            Abort (discard all staged objects)

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::auth;
use crate::error::AppError;
use crate::AppState;

pub async fn begin(state: &AppState, ns: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "transaction.begin")?;

    let txn_id = state
        .transactions
        .begin(ns)
        .map_err(|e| AppError::Internal(e.to_string()))?;

    let body = serde_json::json!({"transaction_id": txn_id});
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

pub async fn put(
    state: &AppState,
    ns: &str,
    txn_id: &str,
    kappa: &str,
    body: &[u8],
) -> Result<Response, AppError> {
    auth::authorize(ns, "transaction.put")?;

    let txn = txn_id.to_string();
    let k = kappa.to_string();
    let content = body.to_vec();
    let txns = state.transactions.clone();
    let created = tokio::task::spawn_blocking(move || txns.put(&txn, &k, &content)).await??;

    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        [
            ("x-kappa-label", kappa.to_string()),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response())
}

pub async fn commit(state: &AppState, ns: &str, txn_id: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "transaction.commit")?;

    let txn = txn_id.to_string();
    let txns = state.transactions.clone();
    let store = state.store.clone();
    let result = tokio::task::spawn_blocking(move || txns.commit(&txn, &*store)).await??;

    let body = serde_json::json!({"promoted": result.promoted});
    Ok((StatusCode::OK, Json(body)).into_response())
}

pub async fn abort(state: &AppState, ns: &str, txn_id: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "transaction.abort")?;

    let txn = txn_id.to_string();
    let txns = state.transactions.clone();
    tokio::task::spawn_blocking(move || txns.abort(&txn)).await??;

    Ok(StatusCode::NO_CONTENT.into_response())
}
