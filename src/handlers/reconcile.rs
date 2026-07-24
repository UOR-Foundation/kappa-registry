//! Range-based set reconciliation (RBSR) handler.
//!
//! Implements the Meyer (2023) protocol: peers exchange fingerprints over
//! ranges of their ordered kappa-label namespace. Matching fingerprints
//! mean the range is reconciled. Mismatched fingerprints trigger either
//! subdivision (large ranges) or payload exchange (small ranges).
//!
//! POST /v2/{ns}/_reconcile accepts a JSON body with one of:
//!   - {"type":"fingerprint","lower":"...","upper":"...","fingerprint":"hex"}
//!   - {"type":"items_request","lower":"...","upper":"..."}
//!   - {"type":"items","lower":"...","upper":"...","items":["..."]}
//!
//! Responses carry the same message types. The caller drives the protocol
//! by sending messages and processing responses until convergence.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::auth;
use crate::error::AppError;
use crate::store::KappaStore;
use crate::AppState;

pub async fn handle(state: &AppState, ns: &str, body: &[u8]) -> Result<Response, AppError> {
    auth::authorize(ns, "reconcile")?;

    let v: serde_json::Value = serde_json::from_slice(body)?;
    let msg_type = v["type"]
        .as_str()
        .ok_or_else(|| AppError::NameInvalid("missing type field".to_string()))?;

    match msg_type {
        "fingerprint" => handle_fingerprint(state, ns, &v).await,
        "items_request" => handle_items_request(state, ns, &v).await,
        "items" => handle_items(state, ns, &v).await,
        _ => Err(AppError::NameInvalid(format!(
            "unknown reconcile message type: {msg_type}"
        ))),
    }
}

/// Handle an incoming fingerprint message. Compare the peer's fingerprint
/// for [lower, upper) against our own. If they match, respond with "done".
/// If they differ and the range is small, respond with our items. If they
/// differ and the range is large, subdivide into sub-range fingerprints.
async fn handle_fingerprint(
    state: &AppState,
    ns: &str,
    v: &serde_json::Value,
) -> Result<Response, AppError> {
    let lower = v["lower"]
        .as_str()
        .ok_or_else(|| AppError::NameInvalid("missing lower".to_string()))?;
    let upper = v["upper"]
        .as_str()
        .ok_or_else(|| AppError::NameInvalid("missing upper".to_string()))?;
    let peer_fp_hex = v["fingerprint"]
        .as_str()
        .ok_or_else(|| AppError::NameInvalid("missing fingerprint".to_string()))?;

    let peer_fp = hex::decode(peer_fp_hex)
        .map_err(|_| AppError::NameInvalid("invalid fingerprint hex".to_string()))?;

    let s = state.store.clone();
    let ns_owned = ns.to_string();
    let lower_owned = lower.to_string();
    let upper_owned = upper.to_string();
    let our = tokio::task::spawn_blocking(move || {
        s.range_fingerprint(&ns_owned, &lower_owned, &upper_owned)
    })
    .await??;

    // Compare fingerprints
    if peer_fp.len() == 32 && our.fingerprint[..] == peer_fp[..] {
        let resp = serde_json::json!({
            "type": "done",
            "lower": lower,
            "upper": upper,
        });
        return Ok((StatusCode::OK, Json(resp)).into_response());
    }

    // Fingerprints differ. If range is small, send items directly.
    const PAYLOAD_THRESHOLD: usize = 32;
    if our.count <= PAYLOAD_THRESHOLD {
        let s = state.store.clone();
        let ns_owned = ns.to_string();
        let lower_owned = lower.to_string();
        let upper_owned = upper.to_string();
        let items = tokio::task::spawn_blocking(move || {
            s.range_items(&ns_owned, &lower_owned, &upper_owned)
        })
        .await??;

        let resp = serde_json::json!({
            "type": "items",
            "lower": lower,
            "upper": upper,
            "items": items,
        });
        return Ok((StatusCode::OK, Json(resp)).into_response());
    }

    // Range is large. Subdivide into sub-ranges and send fingerprints.
    let s = state.store.clone();
    let ns_owned = ns.to_string();
    let lower_owned = lower.to_string();
    let upper_owned = upper.to_string();
    let items =
        tokio::task::spawn_blocking(move || s.range_items(&ns_owned, &lower_owned, &upper_owned))
            .await??;

    const RANGE_DIVISION: usize = 4;
    let chunk_size = items.len().div_ceil(RANGE_DIVISION);
    let mut sub_ranges = Vec::new();

    for chunk in items.chunks(chunk_size) {
        if chunk.is_empty() {
            continue;
        }
        let sub_lower = chunk.first().unwrap().clone();
        // Upper bound is the first item of the next chunk, or the original upper
        let sub_upper = upper.to_string();

        let s = state.store.clone();
        let ns_owned = ns.to_string();
        let sl = sub_lower.clone();
        let su = sub_upper.clone();
        let sub_fp =
            tokio::task::spawn_blocking(move || s.range_fingerprint(&ns_owned, &sl, &su)).await??;

        sub_ranges.push(serde_json::json!({
            "type": "fingerprint",
            "lower": sub_lower,
            "upper": sub_upper,
            "fingerprint": hex::encode(sub_fp.fingerprint),
            "count": sub_fp.count,
        }));
    }

    // Fix up sub-range upper bounds: each sub-range's upper is the next's lower
    for i in 0..sub_ranges.len() {
        if i + 1 < sub_ranges.len() {
            let next_lower = sub_ranges[i + 1]["lower"]
                .as_str()
                .unwrap_or("")
                .to_string();
            sub_ranges[i]["upper"] = serde_json::json!(next_lower);
        } else {
            sub_ranges[i]["upper"] = serde_json::json!(upper);
        }
    }

    // Recompute fingerprints with corrected bounds
    let mut corrected = Vec::new();
    for sr in &sub_ranges {
        let sl = sr["lower"].as_str().unwrap_or("").to_string();
        let su = sr["upper"].as_str().unwrap_or("").to_string();
        let s = state.store.clone();
        let ns_owned = ns.to_string();
        let fp =
            tokio::task::spawn_blocking(move || s.range_fingerprint(&ns_owned, &sl, &su)).await??;
        corrected.push(serde_json::json!({
            "type": "fingerprint",
            "lower": sr["lower"],
            "upper": sr["upper"],
            "fingerprint": hex::encode(fp.fingerprint),
            "count": fp.count,
        }));
    }

    let resp = serde_json::json!({
        "type": "subdivide",
        "ranges": corrected,
    });
    Ok((StatusCode::OK, Json(resp)).into_response())
}

/// Handle an items request: peer wants all our items in [lower, upper).
async fn handle_items_request(
    state: &AppState,
    ns: &str,
    v: &serde_json::Value,
) -> Result<Response, AppError> {
    let lower = v["lower"]
        .as_str()
        .ok_or_else(|| AppError::NameInvalid("missing lower".to_string()))?;
    let upper = v["upper"]
        .as_str()
        .ok_or_else(|| AppError::NameInvalid("missing upper".to_string()))?;

    let s = state.store.clone();
    let ns_owned = ns.to_string();
    let lower_owned = lower.to_string();
    let upper_owned = upper.to_string();
    let items =
        tokio::task::spawn_blocking(move || s.range_items(&ns_owned, &lower_owned, &upper_owned))
            .await??;

    let resp = serde_json::json!({
        "type": "items",
        "lower": lower,
        "upper": upper,
        "items": items,
    });
    Ok((StatusCode::OK, Json(resp)).into_response())
}

/// Handle incoming items: peer is sending us items we may not have.
/// Insert any items we do not already have into our fingerprint set.
/// Respond with our items in the same range that the peer does not have.
async fn handle_items(
    state: &AppState,
    ns: &str,
    v: &serde_json::Value,
) -> Result<Response, AppError> {
    let lower = v["lower"]
        .as_str()
        .ok_or_else(|| AppError::NameInvalid("missing lower".to_string()))?;
    let upper = v["upper"]
        .as_str()
        .ok_or_else(|| AppError::NameInvalid("missing upper".to_string()))?;
    let peer_items: Vec<String> = v["items"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Insert peer items into our fingerprint set
    let s = state.store.clone();
    let ns_owned = ns.to_string();
    let peer_items_clone = peer_items.clone();
    tokio::task::spawn_blocking(move || {
        for item in &peer_items_clone {
            let _ = crate::store::fs::fingerprint::insert(s.root(), &ns_owned, item);
        }
    })
    .await?;

    // Get our items in this range
    let s = state.store.clone();
    let ns_owned = ns.to_string();
    let lower_owned = lower.to_string();
    let upper_owned = upper.to_string();
    let our_items =
        tokio::task::spawn_blocking(move || s.range_items(&ns_owned, &lower_owned, &upper_owned))
            .await??;

    // Filter out items the peer already has
    let peer_set: std::collections::HashSet<&str> = peer_items.iter().map(|s| s.as_str()).collect();
    let new_for_peer: Vec<&str> = our_items
        .iter()
        .filter(|k| !peer_set.contains(k.as_str()))
        .map(|s| s.as_str())
        .collect();

    let resp = serde_json::json!({
        "type": "items",
        "lower": lower,
        "upper": upper,
        "items": new_for_peer,
    });
    Ok((StatusCode::OK, Json(resp)).into_response())
}
