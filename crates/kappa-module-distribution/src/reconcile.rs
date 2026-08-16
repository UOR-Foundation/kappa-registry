//! Reconciliation HTTP handler.
//!
//! POST /v2/{ns}/_reconcile -- message-based reconciliation protocol
//!
//! Supports three message types:
//! - fingerprint: exchange MST root hashes, subdivide on mismatch
//! - items_request: request items in a key range
//! - items: receive items and upsert locally

use std::borrow::Cow;

use topcoat::context::Cx;
use topcoat::router::error::bad_request;
use topcoat::router::{
    Body, IntoResponse, Method, Path, Response, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use kappa_core::types::NamespaceRef;

use crate::{read_body, store};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder.route(RouteFn::new(
        Method::POST,
        Cow::Borrowed(Path::new("/v2/{*ns}/_reconcile")),
        handle_route,
    ))
}

fn handle_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = crate::resolve_ns_write_async(cx).await?;
        handle(cx, &ns, &bytes).await
    })
}

async fn handle(cx: &Cx, ns: &NamespaceRef, body: &[u8]) -> topcoat::Result<Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))?;
    let msg_type = v["type"]
        .as_str()
        .ok_or_else(|| bad_request("missing type field"))?;

    match msg_type {
        "fingerprint" => handle_fingerprint(cx, ns, &v).await,
        "items_request" => handle_items_request(cx, ns, &v).await,
        "items" => handle_items(cx, ns, &v).await,
        _ => Err(bad_request(format!("unknown reconcile message type: {msg_type}")).into()),
    }
}

async fn handle_fingerprint(cx: &Cx, ns: &NamespaceRef, v: &serde_json::Value) -> topcoat::Result<Response> {
    let lower = v["lower"]
        .as_str()
        .ok_or_else(|| bad_request("missing lower"))?;
    let upper = v["upper"]
        .as_str()
        .ok_or_else(|| bad_request("missing upper"))?;
    let peer_fp_hex = v["fingerprint"]
        .as_str()
        .ok_or_else(|| bad_request("missing fingerprint"))?;

    let s = store(cx).clone();
    let n = ns.clone();
    let lo = lower.to_string();
    let up = upper.to_string();

    // Compute our fingerprint for the range
    let (our_fp, items) = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let lo = lo.clone();
        let up = up.clone();
        move || {
            let tags = s.tag_list(&n)?;
            let in_range: Vec<String> = tags
                .iter()
                .filter(|t| {
                    !t.name.starts_with('_')
                        && t.name.as_str() >= lo.as_str()
                        && t.name.as_str() < up.as_str()
                })
                .map(|t| t.kappa.clone())
                .collect();
            let fp = blake3::hash(in_range.join(",").as_bytes());
            Ok::<([u8; 32], Vec<String>), kappa_core::StoreError>((*fp.as_bytes(), in_range))
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let peer_fp = hex::decode(peer_fp_hex).map_err(|_| bad_request("invalid fingerprint hex"))?;

    // If fingerprints match, we're in sync for this range
    if peer_fp.len() == 32 && our_fp[..] == peer_fp[..] {
        let resp = serde_json::json!({"type": "done", "lower": lower, "upper": upper});
        return (
            StatusCode::OK,
            [("content-type", "application/json".to_string())],
            serde_json::to_string(&resp).unwrap_or_default(),
        )
            .into_response(cx);
    }

    // If small enough, send items directly
    const PAYLOAD_THRESHOLD: usize = 32;
    if items.len() <= PAYLOAD_THRESHOLD {
        let resp = serde_json::json!({
            "type": "items",
            "lower": lower,
            "upper": upper,
            "items": items,
        });
        return (
            StatusCode::OK,
            [("content-type", "application/json".to_string())],
            serde_json::to_string(&resp).unwrap_or_default(),
        )
            .into_response(cx);
    }

    // Subdivide into smaller ranges
    let chunk_size = items.len().div_ceil(4);
    let mut sub_ranges = Vec::new();
    for (i, chunk) in items.chunks(chunk_size).enumerate() {
        if chunk.is_empty() {
            continue;
        }
        let sub_lower = if i == 0 {
            lower.to_string()
        } else {
            chunk[0].clone()
        };
        let sub_upper = if i + 1 >= items.chunks(chunk_size).count() {
            upper.to_string()
        } else {
            items
                .chunks(chunk_size)
                .nth(i + 1)
                .and_then(|c| c.first().cloned())
                .unwrap_or_else(|| upper.to_string())
        };
        let sub_fp = blake3::hash(chunk.join(",").as_bytes());
        sub_ranges.push(serde_json::json!({
            "type": "fingerprint",
            "lower": sub_lower,
            "upper": sub_upper,
            "fingerprint": hex::encode(sub_fp.as_bytes()),
            "count": chunk.len(),
        }));
    }

    let resp = serde_json::json!({"type": "subdivide", "ranges": sub_ranges});
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&resp).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn handle_items_request(
    cx: &Cx,
    ns: &NamespaceRef,
    v: &serde_json::Value,
) -> topcoat::Result<Response> {
    let lower = v["lower"]
        .as_str()
        .ok_or_else(|| bad_request("missing lower"))?;
    let upper = v["upper"]
        .as_str()
        .ok_or_else(|| bad_request("missing upper"))?;

    let s = store(cx).clone();
    let n = ns.clone();
    let lo = lower.to_string();
    let up = upper.to_string();

    let items = tokio::task::spawn_blocking(move || {
        let tags = s.tag_list(&n)?;
        let in_range: Vec<String> = tags
            .iter()
            .filter(|t| {
                !t.name.starts_with('_')
                    && t.name.as_str() >= lo.as_str()
                    && t.name.as_str() < up.as_str()
            })
            .map(|t| t.kappa.clone())
            .collect();
        Ok::<Vec<String>, kappa_core::StoreError>(in_range)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let resp = serde_json::json!({
        "type": "items",
        "lower": lower,
        "upper": upper,
        "items": items,
    });
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&resp).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn handle_items(cx: &Cx, ns: &NamespaceRef, v: &serde_json::Value) -> topcoat::Result<Response> {
    let lower = v["lower"]
        .as_str()
        .ok_or_else(|| bad_request("missing lower"))?;
    let upper = v["upper"]
        .as_str()
        .ok_or_else(|| bad_request("missing upper"))?;
    let peer_items: Vec<String> = v["items"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Compute our items in the range and return the diff
    let s = store(cx).clone();
    let n = ns.clone();
    let lo = lower.to_string();
    let up = upper.to_string();

    let our_items = tokio::task::spawn_blocking(move || {
        let tags = s.tag_list(&n)?;
        let in_range: Vec<String> = tags
            .iter()
            .filter(|t| {
                !t.name.starts_with('_')
                    && t.name.as_str() >= lo.as_str()
                    && t.name.as_str() < up.as_str()
            })
            .map(|t| t.kappa.clone())
            .collect();
        Ok::<Vec<String>, kappa_core::StoreError>(in_range)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

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
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&resp).unwrap_or_default(),
    )
        .into_response(cx)
}
