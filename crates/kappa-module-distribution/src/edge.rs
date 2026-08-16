//! Edge CRUD HTTP handlers.
//!
//! PUT /v2/{*ns}/edges/        -- create edge
//! GET /v2/{*ns}/edges/{kappa} -- query edges by anchor
//! DELETE /v2/{*ns}/edges/{kappa} -- delete edge
//! POST /v2/{*ns}/edges/_diff  -- edge diff computation

use std::borrow::Cow;

use topcoat::context::Cx;
use topcoat::router::error::{bad_request, not_found};
use topcoat::router::response::{IntoResponse, Response};
use topcoat::router::{
    Body, Method, Path, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use kappa_core::canonical::canonical_bytes;
use kappa_core::kappa::kappa_from_bytes;
use kappa_core::types::{Direction, Edge, EdgeQuery, EdgeRelation, NamespaceRef};

use crate::{path_param, query_param, read_body, store};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(RouteFn::new(
            Method::PUT,
            Cow::Borrowed(Path::new("/v2/{*ns}/edges/")),
            put_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/edges/{edge_key}")),
            query_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            Cow::Borrowed(Path::new("/v2/{*ns}/edges/{edge_key}")),
            delete_route,
        ))
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/edges/_diff")),
            diff_route,
        ))
}

fn put_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = crate::resolve_ns_write_async(cx).await?;
        put(cx, &ns, &bytes).await
    })
}

fn query_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = crate::resolve_ns_read_async(cx).await?;
        let anchor = path_param(cx, "edge_key");
        let direction_str = query_param(cx, "direction").unwrap_or_else(|| "outbound".to_string());
        let relation_str = query_param(cx, "relation");
        let n: Option<usize> = query_param(cx, "n").and_then(|s| s.parse().ok());
        let last = query_param(cx, "last");
        query(
            cx,
            &ns,
            anchor,
            &direction_str,
            relation_str.as_deref(),
            n,
            last.as_deref(),
        )
        .await
    })
}

fn delete_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = crate::resolve_ns_write_async(cx).await?;
        let edge_kappa = path_param(cx, "edge_key");
        delete(cx, &ns, edge_kappa).await
    })
}

fn diff_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = crate::resolve_ns_read_async(cx).await?;
        diff(cx, &ns, &bytes).await
    })
}

async fn put(cx: &Cx, ns: &NamespaceRef, body: &[u8]) -> topcoat::Result<Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))?;
    let source = v["source"]
        .as_str()
        .ok_or_else(|| bad_request("missing source"))?;
    let relation_str = v["relation"]
        .as_str()
        .ok_or_else(|| bad_request("missing relation"))?;
    let target = v["target"]
        .as_str()
        .ok_or_else(|| bad_request("missing target"))?;

    let relation = EdgeRelation::parse(relation_str)
        .ok_or_else(|| bad_request(format!("unknown relation: {relation_str}")))?;

    let s = store(cx).clone();

    // Source must exist for content edges. Identity edges (Capability,
    // Delegation, Assertion) reference anchor strings, not blob kappas.
    let skip_source_check = matches!(
        relation,
        EdgeRelation::Capability | EdgeRelation::Delegation | EdgeRelation::Assertion
    );
    if !skip_source_check {
        let src = source.to_string();
        let exists = tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.blob_exists(&src)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

        if !exists {
            return crate::error_response(
                StatusCode::BAD_REQUEST,
                "EDGE_SOURCE_ABSENT",
                "source kappa does not exist",
            );
        }
    }

    let asserter = crate::registry_anchor(cx);
    let metadata = v.get("metadata").and_then(|m| serde_json::to_vec(m).ok());

    let edge = Edge {
        source: source.to_string(),
        target: target.to_string(),
        relation,
        asserter,
        value_kappa: None,
        metadata,
    };

    // Compute the edge kappa for the response (same as store does internally)
    let edge_kappa = kappa_from_bytes(&canonical_bytes(&edge));

    let n = ns.clone();
    tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.edge_put(&n, &edge)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    // Store object-type metadata (global + namespace-indexed)
    let ek = edge_kappa.clone();
    let n = ns.clone();
    tokio::task::spawn_blocking({
        let s = s.clone();
        move || {
            s.blob_put_meta(&ek, "object-type", b"edge")?;
            s.meta_set(&n, &ek, "object-type", "edge")
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    (
        StatusCode::CREATED,
        [
            ("x-kappa-label", edge_kappa),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

async fn query(
    cx: &Cx,
    ns: &NamespaceRef,
    anchor: &str,
    direction_str: &str,
    relation_str: Option<&str>,
    n: Option<usize>,
    _last: Option<&str>,
) -> topcoat::Result<Response> {
    let is_both = direction_str == "both";
    let relation = relation_str.and_then(EdgeRelation::parse);

    let s = store(cx).clone();
    let ns_owned = ns.clone();

    let mut edges = if is_both {
        let anchor_str = anchor.to_string();
        let rel = relation;
        tokio::task::spawn_blocking({
            let s = s.clone();
            let ns = ns_owned.clone();
            move || {
                let outbound_query = EdgeQuery {
                    anchor: anchor_str.clone(),
                    direction: Direction::Outbound,
                    relation: rel,
                    asserter: None,
                };
                let inbound_query = EdgeQuery {
                    anchor: anchor_str,
                    direction: Direction::Inbound,
                    relation: rel,
                    asserter: None,
                };
                let mut out = s.edge_query(&ns, &outbound_query)?;
                let inb = s.edge_query(&ns, &inbound_query)?;
                for edge in inb {
                    if !out.iter().any(|e| {
                        e.source == edge.source
                            && e.target == edge.target
                            && e.relation == edge.relation
                    }) {
                        out.push(edge);
                    }
                }
                Ok::<Vec<Edge>, kappa_core::StoreError>(out)
            }
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?
    } else {
        let direction = match direction_str {
            "inbound" => Direction::Inbound,
            _ => Direction::Outbound,
        };
        let query = EdgeQuery {
            anchor: anchor.to_string(),
            direction,
            relation,
            asserter: None,
        };
        tokio::task::spawn_blocking(move || s.edge_query(&ns_owned, &query))
            .await
            .map_err(|e| bad_request(e.to_string()))?
            .map_err(crate::store_err)?
    };

    if let Some(limit) = n {
        edges.truncate(limit);
    }

    let edge_json: Vec<serde_json::Value> = edges
        .iter()
        .map(|e| {
            let edge_bytes = canonical_bytes(e);
            let ek = kappa_from_bytes(&edge_bytes);
            serde_json::json!({
                "edge_kappa": ek,
                "source": e.source,
                "target": e.target,
                "relation": e.relation.as_str(),
                "asserter": e.asserter,
                "metadata": e.metadata.as_ref()
                    .and_then(|b| serde_json::from_slice::<serde_json::Value>(b).ok())
                    .unwrap_or(serde_json::Value::Object(serde_json::Map::new())),
            })
        })
        .collect();

    let body = serde_json::json!({"edges": edge_json});
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn delete(cx: &Cx, ns: &NamespaceRef, edge_kappa: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let ek = edge_kappa.to_string();
    let n = ns.clone();

    // Read the edge blob to get (source, target, relation) for the new
    // edge_delete signature. The edge blob is the dCBOR canonical form
    // stored by edge_put.
    let edge = tokio::task::spawn_blocking({
        let s = s.clone();
        let ek = ek.clone();
        move || {
            let bytes = s.blob_get(&ek)?;
            let edge: Edge = kappa_core::canonical::from_canonical(&bytes).map_err(|e| {
                kappa_core::StoreError::Rejected(format!("failed to decode edge blob: {}", e))
            })?;
            Ok::<Edge, kappa_core::StoreError>(edge)
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?;

    let edge = match edge {
        Ok(e) => e,
        Err(_) => return Err(not_found().into()),
    };

    tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.edge_delete(&n, &edge.source, &edge.target, edge.relation)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    StatusCode::ACCEPTED.into_response(cx)
}

async fn diff(cx: &Cx, ns: &NamespaceRef, body: &[u8]) -> topcoat::Result<Response> {
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

    let s = store(cx).clone();
    let n = ns.clone();

    let result = tokio::task::spawn_blocking(move || {
        let mut have_set = std::collections::HashSet::new();
        for root in &have {
            let query = EdgeQuery {
                anchor: root.clone(),
                direction: Direction::Outbound,
                relation: None,
                asserter: None,
            };
            if let Ok(edges) = s.edge_query(&n, &query) {
                for e in &edges {
                    have_set.insert(e.target.clone());
                }
            }
            have_set.insert(root.clone());
        }

        let mut want_set = Vec::new();
        for root in &want {
            let query = EdgeQuery {
                anchor: root.clone(),
                direction: Direction::Outbound,
                relation: None,
                asserter: None,
            };
            if let Ok(edges) = s.edge_query(&n, &query) {
                for e in &edges {
                    if !have_set.contains(&e.target) {
                        want_set.push(e.target.clone());
                    }
                }
            }
            if !have_set.contains(root) {
                want_set.push(root.clone());
            }
        }
        want_set.sort();
        want_set.dedup();
        want_set
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?;

    let body = serde_json::json!({"diff": result});
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}
