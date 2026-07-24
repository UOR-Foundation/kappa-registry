use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::auth;
use crate::error::AppError;
use crate::kappa::{axis_of, compute_kappa, KappaLabel};
use crate::store::{Direction, KappaStore};
use crate::AppState;

pub async fn compose(
    state: &AppState,
    ns: &str,
    op_token: &str,
    body: &[u8],
) -> Result<Response, AppError> {
    auth::authorize(ns, "compose")?;

    let v: serde_json::Value = serde_json::from_slice(body)?;
    let operand_strs: Vec<String> = v["operands"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if operand_strs.is_empty() {
        return Err(AppError::NameInvalid("no operands".to_string()));
    }

    let first_axis = axis_of(&operand_strs[0]).unwrap_or("sha256");
    for op in &operand_strs[1..] {
        if axis_of(op) != Some(first_axis) {
            return Err(AppError::AxisMismatch);
        }
    }

    let canon = match op_token {
        "g2" => {
            if operand_strs.len() != 2 {
                return Err(AppError::NameInvalid("g2 requires 2 operands".to_string()));
            }
            canonical_g2(&operand_strs[0], &operand_strs[1])
        }
        "f4" => {
            if operand_strs.len() != 1 {
                return Err(AppError::NameInvalid("f4 requires 1 operand".to_string()));
            }
            canonical_f4(&operand_strs[0])?
        }
        "e6" => {
            if operand_strs.len() != 1 {
                return Err(AppError::NameInvalid("e6 requires 1 operand".to_string()));
            }
            canonical_e6(&operand_strs[0])?
        }
        "e7" => {
            if operand_strs.len() != 1 {
                return Err(AppError::NameInvalid("e7 requires 1 operand".to_string()));
            }
            canonical_e7(&operand_strs[0])?
        }
        "e8" => {
            if operand_strs.len() != 1 {
                return Err(AppError::NameInvalid("e8 requires 1 operand".to_string()));
            }
            operand_strs[0].as_bytes().to_vec()
        }
        _ => return Err(AppError::NameInvalid("unknown operation".to_string())),
    };

    let composed_kappa = compute_kappa(first_axis, &canon)?;

    let s = state.store.clone();
    let ck = composed_kappa.as_str().to_string();
    let c = canon.clone();
    tokio::task::spawn_blocking(move || s.put(&ck, &c)).await??;

    let s = state.store.clone();
    let k = composed_kappa.as_str().to_string();
    tokio::task::spawn_blocking(move || s.put_meta(&k, "object-type", b"composition")).await??;

    let witness = witness_blob(71, 32, &canon);
    let witness_kappa = compute_kappa(first_axis, &witness)?;

    let s = state.store.clone();
    let wk = witness_kappa.as_str().to_string();
    let w = witness.clone();
    tokio::task::spawn_blocking(move || s.put(&wk, &w)).await??;

    let s = state.store.clone();
    let k = witness_kappa.as_str().to_string();
    tokio::task::spawn_blocking(move || s.put_meta(&k, "object-type", b"witness")).await??;

    for operand in &operand_strs {
        let edge_canon = super::edge::edge_canonical_pub(
            composed_kappa.as_str().as_bytes(),
            "composed-of",
            operand.as_bytes(),
            op_token.as_bytes(),
        );
        let ek = compute_kappa(first_axis, &edge_canon)?;
        let s = state.store.clone();
        let ek_str = ek.as_str().to_string();
        let ec = edge_canon.clone();
        tokio::task::spawn_blocking({
            let s = s.clone();
            let ek = ek_str.clone();
            move || s.put(&ek, &ec)
        })
        .await??;
        let ck = composed_kappa.as_str().to_string();
        let op = operand.clone();
        let edge_meta = serde_json::json!({"operation": op_token});
        let n = ns.to_string();
        tokio::task::spawn_blocking(move || {
            s.edge_put(&n, &ek_str, &ck, "composed-of", &op, &edge_canon, edge_meta)
        })
        .await??;
    }

    let wit_edge = super::edge::edge_canonical_pub(
        witness_kappa.as_str().as_bytes(),
        "witness-of",
        composed_kappa.as_str().as_bytes(),
        b"",
    );
    let wit_ek = compute_kappa(first_axis, &wit_edge)?;
    let s = state.store.clone();
    let wek = wit_ek.as_str().to_string();
    let we = wit_edge.clone();
    tokio::task::spawn_blocking({
        let s = s.clone();
        let wek = wek.clone();
        move || s.put(&wek, &we)
    })
    .await??;
    let wk = witness_kappa.as_str().to_string();
    let ck = composed_kappa.as_str().to_string();
    let n = ns.to_string();
    let wit_meta = serde_json::json!({});
    tokio::task::spawn_blocking(move || {
        s.edge_put(&n, &wek, &wk, "witness-of", &ck, &wit_edge, wit_meta)
    })
    .await??;

    let operands_json: Vec<serde_json::Value> = operand_strs
        .iter()
        .map(|s| serde_json::Value::String(s.clone()))
        .collect();

    let resp = serde_json::json!({
        "composed": composed_kappa.as_str(),
        "witness": witness_kappa.as_str(),
        "operands": operands_json,
        "operation": op_token,
    });

    Ok((StatusCode::OK, Json(resp)).into_response())
}

pub async fn witness(state: &AppState, ns: &str, kappa: &str) -> Result<Response, AppError> {
    auth::authorize(ns, "witness.get")?;

    let s = state.store.clone();
    let k = kappa.to_string();
    let n = ns.to_string();
    let edges = tokio::task::spawn_blocking(move || {
        s.edge_find(&n, &k, Direction::Inbound, Some("witness-of"))
    })
    .await??;

    let witness_kappa = edges
        .first()
        .map(|e| e.source.clone())
        .ok_or(AppError::BlobUnknown)?;

    let s = state.store.clone();
    let wk = witness_kappa.clone();
    let content = tokio::task::spawn_blocking(move || s.get(&wk)).await??;
    let content = content.ok_or(AppError::BlobUnknown)?;

    Ok((
        StatusCode::OK,
        [
            ("content-length", content.len().to_string()),
            ("x-kappa-label", witness_kappa),
            ("content-type", "application/octet-stream".to_string()),
        ],
        content,
    )
        .into_response())
}

fn canonical_g2(a: &str, b: &str) -> Vec<u8> {
    let ab = [a.as_bytes(), b.as_bytes()].concat();
    let ba = [b.as_bytes(), a.as_bytes()].concat();
    if ab <= ba {
        ab
    } else {
        ba
    }
}

fn canonical_f4(a: &str) -> Result<Vec<u8>, AppError> {
    let kappa = KappaLabel::parse(a)?;
    let comp = kappa.complement();
    let mut pair = [a.to_string(), comp.as_str().to_string()];
    pair.sort();
    Ok(pair[0].as_bytes().to_vec())
}

fn canonical_e6(a: &str) -> Result<Vec<u8>, AppError> {
    let hex_part = a.split_once(':').map(|(_, h)| h).unwrap_or("");
    let digest = hex::decode(hex_part)
        .map_err(|_| AppError::NameInvalid("bad hex in operand".to_string()))?;
    let first = *digest
        .first()
        .ok_or_else(|| AppError::NameInvalid("empty digest".to_string()))?;
    let tag: u8 = if first % 9 <= 7 { 0x05 } else { 0x06 };
    let mut out = Vec::with_capacity(1 + a.len());
    out.push(tag);
    out.extend_from_slice(a.as_bytes());
    Ok(out)
}

fn canonical_e7(a: &str) -> Result<Vec<u8>, AppError> {
    let axis = axis_of(a).ok_or_else(|| AppError::NameInvalid("no axis".to_string()))?;
    let hex_part = a.split_once(':').map(|(_, h)| h).unwrap_or("");
    let digest = hex::decode(hex_part)
        .map_err(|_| AppError::NameInvalid("bad hex in operand".to_string()))?;
    if digest.is_empty() || digest.len() % 4 != 0 {
        return Err(AppError::NameInvalid(
            "digest not divisible by 4".to_string(),
        ));
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
