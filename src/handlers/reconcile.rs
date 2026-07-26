use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::bad_request;
use topcoat::router::{Body, IntoResponse, Response, RouteFuture, StatusCode};

use crate::auth;
use crate::store::fs::FsStore;
use crate::store::KappaStore;

use super::path_param;

fn store(cx: &Cx) -> &Arc<FsStore> {
    app_context::<Arc<FsStore>>(cx)
}

pub fn handle_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = super::read_body(body).await?;
        let ns = path_param(cx, "ns");
        handle(cx, ns, &bytes).await
    })
}

async fn handle(cx: &Cx, ns: &str, body: &[u8]) -> topcoat::Result<Response> {
    auth::authorize(ns, "reconcile")?;

    let v: serde_json::Value = serde_json::from_slice(body)?;
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

async fn handle_fingerprint(cx: &Cx, ns: &str, v: &serde_json::Value) -> topcoat::Result<Response> {
    let lower = v["lower"]
        .as_str()
        .ok_or_else(|| bad_request("missing lower"))?;
    let upper = v["upper"]
        .as_str()
        .ok_or_else(|| bad_request("missing upper"))?;
    let peer_fp_hex = v["fingerprint"]
        .as_str()
        .ok_or_else(|| bad_request("missing fingerprint"))?;

    let peer_fp = hex::decode(peer_fp_hex).map_err(|_| bad_request("invalid fingerprint hex"))?;

    let s = store(cx).clone();
    let ns_owned = ns.to_string();
    let lower_owned = lower.to_string();
    let upper_owned = upper.to_string();
    let our = tokio::task::spawn_blocking(move || {
        s.range_fingerprint(&ns_owned, &lower_owned, &upper_owned)
    })
    .await?
    .map_err(super::store_err)?;

    if peer_fp.len() == 32 && our.fingerprint[..] == peer_fp[..] {
        let resp = serde_json::json!({"type": "done", "lower": lower, "upper": upper});
        return (
            StatusCode::OK,
            serde_json::to_string(&resp).unwrap_or_default(),
        )
            .into_response(cx);
    }

    const PAYLOAD_THRESHOLD: usize = 32;
    if our.count <= PAYLOAD_THRESHOLD {
        let s = store(cx).clone();
        let ns_owned = ns.to_string();
        let lower_owned = lower.to_string();
        let upper_owned = upper.to_string();
        let items = tokio::task::spawn_blocking(move || {
            s.range_items(&ns_owned, &lower_owned, &upper_owned)
        })
        .await?
        .map_err(super::store_err)?;

        let resp =
            serde_json::json!({"type": "items", "lower": lower, "upper": upper, "items": items});
        return (
            StatusCode::OK,
            serde_json::to_string(&resp).unwrap_or_default(),
        )
            .into_response(cx);
    }

    let s = store(cx).clone();
    let ns_owned = ns.to_string();
    let lower_owned = lower.to_string();
    let upper_owned = upper.to_string();
    let items =
        tokio::task::spawn_blocking(move || s.range_items(&ns_owned, &lower_owned, &upper_owned))
            .await?
            .map_err(super::store_err)?;

    const RANGE_DIVISION: usize = 4;
    let chunk_size = items.len().div_ceil(RANGE_DIVISION);
    let mut sub_ranges = Vec::new();

    for chunk in items.chunks(chunk_size) {
        if chunk.is_empty() {
            continue;
        }
        let sub_lower = chunk.first().unwrap().clone();
        let sub_upper = upper.to_string();

        let s = store(cx).clone();
        let ns_owned = ns.to_string();
        let sl = sub_lower.clone();
        let su = sub_upper.clone();
        let sub_fp = tokio::task::spawn_blocking(move || s.range_fingerprint(&ns_owned, &sl, &su))
            .await?
            .map_err(super::store_err)?;

        sub_ranges.push(serde_json::json!({
            "type": "fingerprint",
            "lower": sub_lower,
            "upper": sub_upper,
            "fingerprint": hex::encode(sub_fp.fingerprint),
            "count": sub_fp.count,
        }));
    }

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

    let mut corrected = Vec::new();
    for sr in &sub_ranges {
        let sl = sr["lower"].as_str().unwrap_or("").to_string();
        let su = sr["upper"].as_str().unwrap_or("").to_string();
        let s = store(cx).clone();
        let ns_owned = ns.to_string();
        let fp = tokio::task::spawn_blocking(move || s.range_fingerprint(&ns_owned, &sl, &su))
            .await?
            .map_err(super::store_err)?;
        corrected.push(serde_json::json!({
            "type": "fingerprint",
            "lower": sr["lower"],
            "upper": sr["upper"],
            "fingerprint": hex::encode(fp.fingerprint),
            "count": fp.count,
        }));
    }

    let resp = serde_json::json!({"type": "subdivide", "ranges": corrected});
    (
        StatusCode::OK,
        serde_json::to_string(&resp).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn handle_items_request(
    cx: &Cx,
    ns: &str,
    v: &serde_json::Value,
) -> topcoat::Result<Response> {
    let lower = v["lower"]
        .as_str()
        .ok_or_else(|| bad_request("missing lower"))?;
    let upper = v["upper"]
        .as_str()
        .ok_or_else(|| bad_request("missing upper"))?;

    let s = store(cx).clone();
    let ns_owned = ns.to_string();
    let lower_owned = lower.to_string();
    let upper_owned = upper.to_string();
    let items =
        tokio::task::spawn_blocking(move || s.range_items(&ns_owned, &lower_owned, &upper_owned))
            .await?
            .map_err(super::store_err)?;

    let resp = serde_json::json!({"type": "items", "lower": lower, "upper": upper, "items": items});
    (
        StatusCode::OK,
        serde_json::to_string(&resp).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn handle_items(cx: &Cx, ns: &str, v: &serde_json::Value) -> topcoat::Result<Response> {
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

    let s = store(cx).clone();
    let ns_owned = ns.to_string();
    let peer_items_clone = peer_items.clone();
    tokio::task::spawn_blocking(move || {
        for item in &peer_items_clone {
            let _ = crate::store::fs::fingerprint::insert(s.root(), &ns_owned, item);
        }
    })
    .await?;

    let s = store(cx).clone();
    let ns_owned = ns.to_string();
    let lower_owned = lower.to_string();
    let upper_owned = upper.to_string();
    let our_items =
        tokio::task::spawn_blocking(move || s.range_items(&ns_owned, &lower_owned, &upper_owned))
            .await?
            .map_err(super::store_err)?;

    let peer_set: std::collections::HashSet<&str> = peer_items.iter().map(|s| s.as_str()).collect();
    let new_for_peer: Vec<&str> = our_items
        .iter()
        .filter(|k| !peer_set.contains(k.as_str()))
        .map(|s| s.as_str())
        .collect();

    let resp =
        serde_json::json!({"type": "items", "lower": lower, "upper": upper, "items": new_for_peer});
    (
        StatusCode::OK,
        serde_json::to_string(&resp).unwrap_or_default(),
    )
        .into_response(cx)
}
