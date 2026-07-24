use std::collections::HashMap;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::auth;
use crate::error::AppError;
use crate::kappa::{axis_of, compute_kappa};
use crate::store::{Direction, KappaStore};
use crate::AppState;

pub async fn put(state: &AppState, ns: &str, body: &[u8]) -> Result<Response, AppError> {
    auth::authorize(ns, "edge.put")?;

    let v: serde_json::Value = serde_json::from_slice(body)?;
    let source = v["source"]
        .as_str()
        .ok_or_else(|| AppError::NameInvalid("missing source".to_string()))?;
    let relation = v["relation"]
        .as_str()
        .ok_or_else(|| AppError::NameInvalid("missing relation".to_string()))?;
    let target = v["target"]
        .as_str()
        .ok_or_else(|| AppError::NameInvalid("missing target".to_string()))?;

    let s = state.store.clone();
    let src = source.to_string();
    let exists = tokio::task::spawn_blocking(move || s.exists(&src)).await??;
    if !exists {
        return Err(AppError::EdgeSourceAbsent);
    }

    let metadata = vec![0xA0u8];
    let canonical = edge_canonical(source.as_bytes(), relation, target.as_bytes(), &metadata);

    let axis = axis_of(source).unwrap_or("sha256");
    let edge_kappa = compute_kappa(axis, &canonical)?;

    let s = state.store.clone();
    let ek = edge_kappa.as_str().to_string();
    let canon = canonical.clone();
    tokio::task::spawn_blocking(move || s.put(&ek, &canon)).await??;

    let s = state.store.clone();
    let k = edge_kappa.as_str().to_string();
    tokio::task::spawn_blocking(move || s.put_meta(&k, "object-type", b"edge")).await??;

    let s = state.store.clone();
    let ek = edge_kappa.as_str().to_string();
    let src = source.to_string();
    let rel = relation.to_string();
    let tgt = target.to_string();
    let canon = canonical;
    let meta = serde_json::json!({});
    let n = ns.to_string();
    let is_new =
        tokio::task::spawn_blocking(move || s.edge_put(&n, &ek, &src, &rel, &tgt, &canon, meta))
            .await??;

    let status = if is_new {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    Ok((
        status,
        [
            ("x-kappa-label", edge_kappa.as_str().to_string()),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response())
}

pub async fn query(
    state: &AppState,
    ns: &str,
    node: &str,
    direction: &str,
    relation: Option<&str>,
    params: &HashMap<String, String>,
) -> Result<Response, AppError> {
    auth::authorize(ns, "edge.query")?;

    let dir = Direction::parse(direction);
    let n: Option<usize> = params.get("n").and_then(|s| s.parse().ok());
    let last = params.get("last").map(|s| s.as_str());

    let s = state.store.clone();
    let node_owned = node.to_string();
    let rel = relation.map(String::from);
    let last_owned = last.map(String::from);
    let ns_owned = ns.to_string();
    let edges = tokio::task::spawn_blocking(move || {
        s.edge_query(
            &ns_owned,
            &node_owned,
            dir,
            rel.as_deref(),
            n,
            last_owned.as_deref(),
        )
    })
    .await??;

    let body = serde_json::json!({"edges": edges});
    Ok((StatusCode::OK, Json(body)).into_response())
}

pub async fn delete(state: &AppState, ns: &str, edge_kappa: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "edge.delete")?;

    let s = state.store.clone();
    let ek = edge_kappa.to_string();
    let n = ns.to_string();
    let removed = tokio::task::spawn_blocking(move || s.edge_remove(&n, &ek)).await??;
    if removed {
        Ok(StatusCode::ACCEPTED.into_response())
    } else {
        Err(AppError::EdgeUnknown)
    }
}

pub async fn diff(state: &AppState, ns: &str, body: &[u8]) -> Result<Response, AppError> {
    auth::authorize(ns, "edge.diff")?;

    let v: serde_json::Value = serde_json::from_slice(body)?;
    let have: Vec<String> = v["have"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let want: Vec<String> = v["want"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let rels: Vec<String> = v["relations"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let s = state.store.clone();
    let n = ns.to_string();
    let result = tokio::task::spawn_blocking(move || {
        let rel_refs: Vec<&str> = rels.iter().map(|s| s.as_str()).collect();
        s.edge_diff(&n, &have, &want, &rel_refs)
    })
    .await??;

    let body = serde_json::json!({"diff": result});
    Ok((StatusCode::OK, Json(body)).into_response())
}

pub fn edge_canonical_pub(
    source: &[u8],
    relation: &str,
    target: &[u8],
    metadata: &[u8],
) -> Vec<u8> {
    edge_canonical(source, relation, target, metadata)
}

fn edge_canonical(source: &[u8], relation: &str, target: &[u8], metadata: &[u8]) -> Vec<u8> {
    let rel = relation.as_bytes();
    let meta_len = (metadata.len() as u32).to_be_bytes();
    let mut out = Vec::with_capacity(
        source.len() + 1 + rel.len() + 1 + target.len() + 1 + 4 + metadata.len(),
    );
    out.extend_from_slice(source);
    out.push(0x00);
    out.extend_from_slice(rel);
    out.push(0x00);
    out.extend_from_slice(target);
    out.push(0x00);
    out.extend_from_slice(&meta_len);
    out.extend_from_slice(metadata);
    out
}
