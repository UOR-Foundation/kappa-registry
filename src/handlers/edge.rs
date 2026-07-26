use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::{bad_request, not_found};
use topcoat::router::{Body, IntoResponse, Response, RouteFuture, StatusCode};

use crate::auth::authorize;
use crate::kappa::{axis_of, compute_kappa};
use crate::ratelimit::OpClass;
use crate::store::fs::FsStore;
use crate::store::{Direction, KappaStore};

use super::path_param;

fn query_param(cx: &Cx, key: &str) -> Option<String> {
    let query = topcoat::router::uri(cx).query()?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(super::tag::percent_decode(v));
            }
        }
    }
    None
}

fn store(cx: &Cx) -> &Arc<FsStore> {
    app_context::<Arc<FsStore>>(cx)
}

pub fn put_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = super::read_body(body).await?;
        let ns = path_param(cx, "ns");
        put(cx, ns, &bytes).await
    })
}

pub fn query_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let node = path_param(cx, "edge_key");
        let direction = query_param(cx, "direction").unwrap_or_else(|| "outbound".to_string());
        let relation = query_param(cx, "relation");
        let n: Option<usize> = query_param(cx, "n").and_then(|s| s.parse().ok());
        let last = query_param(cx, "last");
        query(
            cx,
            ns,
            node,
            &direction,
            relation.as_deref(),
            n,
            last.as_deref(),
        )
        .await
    })
}

pub fn delete_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let kappa = path_param(cx, "edge_key");
        delete(cx, ns, kappa).await
    })
}

pub fn diff_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = super::read_body(body).await?;
        let ns = path_param(cx, "ns");
        diff(cx, ns, &bytes).await
    })
}

async fn put(cx: &Cx, ns: &str, body: &[u8]) -> topcoat::Result<Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))?;
    let source = v["source"]
        .as_str()
        .ok_or_else(|| bad_request("missing source"))?;
    let relation = v["relation"]
        .as_str()
        .ok_or_else(|| bad_request("missing relation"))?;
    let target = v["target"]
        .as_str()
        .ok_or_else(|| bad_request("missing target"))?;

    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let src = source.to_string();
    let exists = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let a = asserter.clone();
        move || {
            authorize(&*s, &n, OpClass::Write, &a)?;
            s.exists(&src)
        }
    })
    .await??;
    if !exists {
        return Err(bad_request("source kappa absent").into());
    }

    let metadata = vec![0xA0u8];
    let canonical = edge_canonical_pub(source.as_bytes(), relation, target.as_bytes(), &metadata);
    let axis = axis_of(source).unwrap_or("sha256");
    let edge_kappa = compute_kappa(axis, &canonical)?;

    let ek = edge_kappa.as_str().to_string();
    let canon = canonical.clone();
    tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.put(&ek, &canon)
    })
    .await??;

    let k = edge_kappa.as_str().to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        move || s.meta_set(&n, &k, &[("object-type", "edge")])
    })
    .await??;

    let ek = edge_kappa.as_str().to_string();
    let src = source.to_string();
    let rel = relation.to_string();
    let tgt = target.to_string();
    let canon = canonical;
    let meta = serde_json::json!({});
    let is_new = tokio::task::spawn_blocking(move || {
        s.edge_put(&n, &asserter, &ek, &src, &rel, &tgt, &canon, meta)
    })
    .await??;

    let status = if is_new {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    (
        status,
        [
            ("x-kappa-label", edge_kappa.as_str().to_string()),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

async fn query(
    cx: &Cx,
    ns: &str,
    node: &str,
    direction: &str,
    relation: Option<&str>,
    n: Option<usize>,
    last: Option<&str>,
) -> topcoat::Result<Response> {
    let dir = Direction::parse(direction);
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let node_owned = node.to_string();
    let rel = relation.map(String::from);
    let last_owned = last.map(String::from);
    let n_owned = ns.to_string();
    let edges = tokio::task::spawn_blocking(move || {
        authorize(&*s, &n_owned, OpClass::Read, &asserter)?;
        s.edge_query(
            &n_owned,
            &node_owned,
            dir,
            rel.as_deref(),
            n,
            last_owned.as_deref(),
        )
    })
    .await??;

    let body = serde_json::json!({"edges": edges});
    (
        StatusCode::OK,
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn delete(cx: &Cx, ns: &str, edge_kappa: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let ek = edge_kappa.to_string();
    let n = ns.to_string();
    let removed = tokio::task::spawn_blocking(move || {
        authorize(&*s, &n, OpClass::Admin, &asserter)?;
        s.edge_remove(&n, &ek)
    })
    .await??;
    if removed {
        StatusCode::ACCEPTED.into_response(cx)
    } else {
        Err(not_found().into())
    }
}

async fn diff(cx: &Cx, ns: &str, body: &[u8]) -> topcoat::Result<Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))?;
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

    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let result = tokio::task::spawn_blocking(move || {
        authorize(&*s, &n, OpClass::Read, &asserter)?;
        let rel_refs: Vec<&str> = rels.iter().map(|s| s.as_str()).collect();
        s.edge_diff(&n, &have, &want, &rel_refs)
    })
    .await??;

    let body = serde_json::json!({"diff": result});
    (
        StatusCode::OK,
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

pub fn edge_canonical_pub(
    source: &[u8],
    relation: &str,
    target: &[u8],
    metadata: &[u8],
) -> Vec<u8> {
    let mut canonical = Vec::new();
    canonical.extend_from_slice(source);
    canonical.push(0x00);
    canonical.extend_from_slice(relation.as_bytes());
    canonical.push(0x00);
    canonical.extend_from_slice(target);
    canonical.push(0x00);
    canonical.extend_from_slice(metadata);
    canonical
}
