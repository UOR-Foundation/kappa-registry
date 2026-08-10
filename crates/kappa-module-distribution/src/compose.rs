//! Composition and witness HTTP handlers.
//!
//! POST /v2/{*ns}/compose/{op} -- apply categorical composition (g2/f4/e6/e7/e8)
//! GET /v2/{*ns}/witnesses/{kappa} -- retrieve witness blob for a composed kappa

use std::borrow::Cow;

use topcoat::context::Cx;
use topcoat::router::error::{bad_request, not_found};
use topcoat::router::{
    Body, IntoResponse, Method, Path, Response, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use kappa_core::kappa::{axis_of, compute_kappa, KappaLabel};
use kappa_core::types::{Direction, Edge, EdgeQuery, EdgeRelation};

use crate::{path_param, read_body, store};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/compose/{op}")),
            compose_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/witnesses/{kappa}")),
            witness_route,
        ))
}

fn compose_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = path_param(cx, "ns");
        let op = path_param(cx, "op");
        compose(cx, ns, op, &bytes).await
    })
}

fn witness_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let kappa = path_param(cx, "kappa");
        witness(cx, ns, kappa).await
    })
}

async fn compose(cx: &Cx, ns: &str, op_token: &str, body: &[u8]) -> topcoat::Result<Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))?;
    let operand_strs: Vec<String> = v["operands"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if operand_strs.is_empty() {
        return Err(bad_request("no operands").into());
    }

    let first_axis = axis_of(&operand_strs[0]).unwrap_or("sha256");
    for op in &operand_strs[1..] {
        if axis_of(op) != Some(first_axis) {
            return crate::error_response(
                StatusCode::UNPROCESSABLE_ENTITY,
                "AXIS_MISMATCH",
                "composition operands differ in sigma-axis",
            );
        }
    }

    let canon = match op_token {
        "g2" => {
            if operand_strs.len() != 2 {
                return Err(bad_request("g2 requires 2 operands").into());
            }
            canonical_g2(&operand_strs[0], &operand_strs[1])
        }
        "f4" => {
            if operand_strs.len() != 1 {
                return Err(bad_request("f4 requires 1 operand").into());
            }
            canonical_f4(&operand_strs[0])?
        }
        "e6" => {
            if operand_strs.len() != 1 {
                return Err(bad_request("e6 requires 1 operand").into());
            }
            canonical_e6(&operand_strs[0])?
        }
        "e7" => {
            if operand_strs.len() != 1 {
                return Err(bad_request("e7 requires 1 operand").into());
            }
            canonical_e7(&operand_strs[0])?
        }
        "e8" => {
            if operand_strs.len() != 1 {
                return Err(bad_request("e8 requires 1 operand").into());
            }
            operand_strs[0].as_bytes().to_vec()
        }
        _ => return Err(bad_request("unknown operation").into()),
    };

    let composed_kappa =
        compute_kappa(first_axis, &canon).map_err(|e| bad_request(e.to_string()))?;

    let s = store(cx).clone();

    // Store composed blob at its kappa address
    let ck = composed_kappa.as_str().to_string();
    let c = canon.clone();
    tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.ingest_verified(&ck,&c)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    // Store object-type metadata (global + namespace-indexed)
    let ck = composed_kappa.as_str().to_string();
    let n = ns.to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        move || {
            s.blob_put_meta(&ck, "object-type", b"composition")?;
            s.meta_set(&n, &ck, "object-type", "composition")
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    // Create witness blob
    let witness_data = witness_blob(71, 32, &canon);
    let witness_kappa =
        compute_kappa(first_axis, &witness_data).map_err(|e| bad_request(e.to_string()))?;

    let wk = witness_kappa.as_str().to_string();
    let w = witness_data;
    tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.ingest_verified(&wk,&w)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let wk = witness_kappa.as_str().to_string();
    let n = ns.to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        move || {
            s.blob_put_meta(&wk, "object-type", b"witness")?;
            s.meta_set(&n, &wk, "object-type", "witness")
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let asserter = crate::registry_anchor(cx);

    // Create composed-of edges
    for operand in &operand_strs {
        let edge = Edge {
            source: composed_kappa.as_str().to_string(),
            target: operand.clone(),
            relation: EdgeRelation::ComposedOf,
            asserter: asserter.clone(),
            value_kappa: None,
            metadata: Some(
                serde_json::to_vec(&serde_json::json!({"operation": op_token})).unwrap_or_default(),
            ),
        };
        let n = ns.to_string();
        let _ = tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.edge_put(&n, &edge)
        })
        .await;
    }

    // Create witness-of edge
    let witness_edge = Edge {
        source: witness_kappa.as_str().to_string(),
        target: composed_kappa.as_str().to_string(),
        relation: EdgeRelation::WitnessReceipt,
        asserter: asserter.clone(),
        value_kappa: None,
        metadata: None,
    };
    let n = ns.to_string();
    let _ = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.edge_put(&n, &witness_edge)
    })
    .await;

    let resp = serde_json::json!({
        "composed": composed_kappa.as_str(),
        "witness": witness_kappa.as_str(),
        "operands": operand_strs,
        "operation": op_token,
    });

    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&resp).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn witness(cx: &Cx, ns: &str, kappa: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.to_string();
    let k = kappa.to_string();

    let query = EdgeQuery {
        anchor: k.clone(),
        direction: Direction::Inbound,
        relation: Some(EdgeRelation::WitnessReceipt),
        asserter: None,
    };

    let edges = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        move || s.edge_query(&n, &query)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let witness_kappa = edges
        .first()
        .map(|e| e.source.clone())
        .ok_or_else(not_found)?;

    let wk = witness_kappa.clone();
    let content = tokio::task::spawn_blocking(move || s.blob_get(&wk))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

    (
        StatusCode::OK,
        [
            ("content-length", content.len().to_string()),
            ("x-kappa-label", witness_kappa),
            ("content-type", "application/octet-stream".to_string()),
        ],
        content,
    )
        .into_response(cx)
}

// -- Composition canonical forms ----------------------------------------------

fn canonical_g2(a: &str, b: &str) -> Vec<u8> {
    let ab = [a.as_bytes(), b.as_bytes()].concat();
    let ba = [b.as_bytes(), a.as_bytes()].concat();
    if ab <= ba {
        ab
    } else {
        ba
    }
}

fn canonical_f4(a: &str) -> topcoat::Result<Vec<u8>> {
    let kappa = KappaLabel::parse(a).map_err(|e| bad_request(e.to_string()))?;
    let comp = kappa.complement();
    let mut pair = [a.to_string(), comp.as_str().to_string()];
    pair.sort();
    Ok(pair[0].as_bytes().to_vec())
}

fn canonical_e6(a: &str) -> topcoat::Result<Vec<u8>> {
    let hex_part = a.split_once(':').map(|(_, h)| h).unwrap_or("");
    let digest = hex::decode(hex_part).map_err(|_| bad_request("bad hex in operand"))?;
    let first = *digest.first().ok_or_else(|| bad_request("empty digest"))?;
    let tag: u8 = if first % 9 <= 7 { 0x05 } else { 0x06 };
    let mut out = Vec::with_capacity(1 + a.len());
    out.push(tag);
    out.extend_from_slice(a.as_bytes());
    Ok(out)
}

fn canonical_e7(a: &str) -> topcoat::Result<Vec<u8>> {
    let axis = axis_of(a).ok_or_else(|| bad_request("no axis"))?;
    let hex_part = a.split_once(':').map(|(_, h)| h).unwrap_or("");
    let digest = hex::decode(hex_part).map_err(|_| bad_request("bad hex in operand"))?;
    if digest.is_empty() || digest.len() % 4 != 0 {
        return Err(bad_request("digest not divisible by 4").into());
    }
    let q = digest.len() / 4;
    let quarters: Vec<&[u8]> = (0..4).map(|i| &digest[i * q..(i + 1) * q]).collect();

    let mut best: Option<Vec<u8>> = None;
    for perm in &PERMS4 {
        let mut cand = Vec::with_capacity(digest.len());
        for &idx in perm {
            cand.extend_from_slice(quarters[idx]);
        }
        if best.as_ref().is_none_or(|b| cand < *b) {
            best = Some(cand);
        }
    }
    let result = format!("{}:{}", axis, hex::encode(best.unwrap()));
    Ok(result.into_bytes())
}

const PERMS4: [[usize; 4]; 24] = [
    [0, 1, 2, 3],
    [0, 1, 3, 2],
    [0, 2, 1, 3],
    [0, 2, 3, 1],
    [0, 3, 1, 2],
    [0, 3, 2, 1],
    [1, 0, 2, 3],
    [1, 0, 3, 2],
    [1, 2, 0, 3],
    [1, 2, 3, 0],
    [1, 3, 0, 2],
    [1, 3, 2, 0],
    [2, 0, 1, 3],
    [2, 0, 3, 1],
    [2, 1, 0, 3],
    [2, 1, 3, 0],
    [2, 3, 0, 1],
    [2, 3, 1, 0],
    [3, 0, 1, 2],
    [3, 0, 2, 1],
    [3, 1, 0, 2],
    [3, 1, 2, 0],
    [3, 2, 0, 1],
    [3, 2, 1, 0],
];

fn witness_blob(label_width: u16, fingerprint_width: u16, trace: &[u8]) -> Vec<u8> {
    let mut w = Vec::with_capacity(6 + trace.len());
    w.extend_from_slice(&label_width.to_le_bytes());
    w.extend_from_slice(&fingerprint_width.to_le_bytes());
    w.extend_from_slice(&1u16.to_le_bytes());
    w.extend_from_slice(trace);
    w
}
