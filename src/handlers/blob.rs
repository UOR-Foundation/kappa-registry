use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::{bad_request, not_found};
use topcoat::router::{headers, uri, Body, IntoResponse, Response, RouteFuture, StatusCode};

use crate::auth::authorize;
use crate::kappa::{verify_kappa, KappaLabel};
use crate::ratelimit::OpClass;
use crate::store::fs::FsStore;
use crate::store::KappaStore;
use crate::MaxBlobSize;

use super::path_param;

fn query_param(cx: &Cx, key: &str) -> Option<String> {
    let query = uri(cx).query()?;
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
        let kappa = path_param(cx, "kappa");
        put(cx, ns, kappa, &bytes).await
    })
}

pub fn get_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let kappa = path_param(cx, "kappa");
        get(cx, ns, kappa).await
    })
}

pub fn head_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let kappa = path_param(cx, "kappa");
        head(cx, ns, kappa).await
    })
}

pub fn delete_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let kappa = path_param(cx, "kappa");
        delete(cx, ns, kappa).await
    })
}

pub fn meta_list_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        meta_list(cx, ns).await
    })
}

pub(crate) async fn put(
    cx: &Cx,
    ns: &str,
    kappa_str: &str,
    body: &[u8],
) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let a = asserter;
    let b = body.to_vec();
    tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let a = a.clone();
        let b = b.clone();
        move || {
            authorize(&*s, &n, OpClass::Write, &a)?;
            s.filter_evaluate(&n, &b).map_err(|reason| {
                crate::store::StoreError::Rejected(format!("filter rejected: {reason}"))
            })
        }
    })
    .await??;

    let max_size = app_context::<MaxBlobSize>(cx).0;
    if b.len() > max_size {
        return Err(bad_request(format!("body exceeds max blob size {max_size}")).into());
    }

    KappaLabel::parse(kappa_str)?;

    match verify_kappa(kappa_str, &b) {
        Ok(true) => {}
        Ok(false) => {
            return Err(bad_request(format!(
                "digest invalid: expected {kappa_str}, got content hash mismatch"
            ))
            .into());
        }
        Err(e) => return Err(e.into()),
    }

    if let Some(also_str) = query_param(cx, "also") {
        match verify_kappa(&also_str, &b) {
            Ok(true) => {}
            Ok(false) => {
                return Err(bad_request(format!(
                    "digest invalid: {also_str}, also kappa mismatch"
                ))
                .into());
            }
            Err(e) => return Err(e.into()),
        }
    }

    let k = kappa_str.to_string();
    let content = b.clone();
    let created = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.put(&k, &content)
    })
    .await??;

    if let Some(ct) = headers(cx)
        .get("content-type")
        .and_then(|v| v.to_str().ok())
    {
        let k = kappa_str.to_string();
        let ct_bytes = ct.as_bytes().to_vec();
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.put_meta(&k, "content-type", &ct_bytes)
        })
        .await??;
    }

    if let Some(also_str) = query_param(cx, "also") {
        let content = b;
        tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.put(&also_str, &content)
        })
        .await??;
    }

    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    (
        status,
        [
            ("x-kappa-label", kappa_str.to_string()),
            ("location", crate::urls::blob_url(ns, kappa_str)),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

async fn get(cx: &Cx, ns: &str, kappa: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let k = kappa.to_string();
    let ct = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let a = asserter;
        let k = k.clone();
        move || {
            authorize(&*s, &n, OpClass::Read, &a)?;
            s.get_meta(&k, "content-type")
        }
    })
    .await??
    .and_then(|v| String::from_utf8(v).ok())
    .unwrap_or_else(|| "application/octet-stream".to_string());

    let axis = kappa.split(':').next().unwrap_or("sha256");

    if let Some(range_header) = headers(cx).get("range").and_then(|v| v.to_str().ok()) {
        if let Some(range) = parse_range_header(range_header) {
            let k = kappa.to_string();
            let total_size = tokio::task::spawn_blocking({
                let s = s.clone();
                move || s.blob_size(&k)
            })
            .await??
            .ok_or_else(not_found)?;
            if range.0 >= total_size || range.1.is_some_and(|end| end < range.0) {
                return (
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    [("content-range", format!("bytes */{total_size}"))],
                    "range not satisfiable",
                )
                    .into_response(cx);
            }
            let (offset, length) = resolve_range(range, total_size);
            let end = offset + length - 1;
            let k = kappa.to_string();
            let content = tokio::task::spawn_blocking({
                let s = s.clone();
                move || s.blob_get_range(&k, offset, length)
            })
            .await??;
            return (
                StatusCode::PARTIAL_CONTENT,
                [
                    ("content-length", content.len().to_string()),
                    (
                        "content-range",
                        format!("bytes {offset}-{end}/{total_size}"),
                    ),
                    ("accept-ranges", "bytes".to_string()),
                    ("x-kappa-label", kappa.to_string()),
                    ("x-kappa-axis", axis.to_string()),
                    ("content-type", ct),
                    ("docker-content-digest", kappa.to_string()),
                ],
                content,
            )
                .into_response(cx);
        }
    }

    let k = kappa.to_string();
    let content = tokio::task::spawn_blocking(move || s.get(&k))
        .await??
        .ok_or_else(not_found)?;

    (
        StatusCode::OK,
        [
            ("content-length", content.len().to_string()),
            ("accept-ranges", "bytes".to_string()),
            ("x-kappa-label", kappa.to_string()),
            ("x-kappa-axis", axis.to_string()),
            ("content-type", ct),
            ("docker-content-digest", kappa.to_string()),
        ],
        content,
    )
        .into_response(cx)
}

fn parse_range_header(header: &str) -> Option<(u64, Option<u64>)> {
    let range = header.strip_prefix("bytes=")?;
    let (start_str, end_str) = range.split_once('-')?;
    let start: u64 = start_str.parse().ok()?;
    let end: Option<u64> = if end_str.is_empty() {
        None
    } else {
        Some(end_str.parse().ok()?)
    };
    Some((start, end))
}

fn resolve_range(range: (u64, Option<u64>), total: u64) -> (u64, u64) {
    let (start, end) = range;
    let end = end.map_or(total - 1, |e| std::cmp::min(e, total - 1));
    (start, end - start + 1)
}

async fn head(cx: &Cx, ns: &str, kappa: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let k = kappa.to_string();
    let size = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let a = asserter;
        let k = k.clone();
        move || {
            authorize(&*s, &n, OpClass::Read, &a)?;
            s.blob_size(&k)
        }
    })
    .await??
    .ok_or_else(not_found)?;

    let ct = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.get_meta(&k, "content-type")
    })
    .await??
    .and_then(|v| String::from_utf8(v).ok())
    .unwrap_or_else(|| "application/octet-stream".to_string());

    let axis = kappa.split(':').next().unwrap_or("sha256");

    (
        StatusCode::OK,
        [
            ("content-length", size.to_string()),
            ("accept-ranges", "bytes".to_string()),
            ("x-kappa-label", kappa.to_string()),
            ("x-kappa-axis", axis.to_string()),
            ("content-type", ct),
            ("docker-content-digest", kappa.to_string()),
        ],
    )
        .into_response(cx)
}

async fn delete(cx: &Cx, ns: &str, kappa: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let k = kappa.to_string();
    tokio::task::spawn_blocking(move || {
        authorize(&*s, &n, OpClass::Admin, &asserter)?;
        s.remove(&k)
    })
    .await??;
    StatusCode::ACCEPTED.into_response(cx)
}

async fn meta_list(cx: &Cx, ns: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let a = asserter;
        move || authorize(&*s, &n, OpClass::Read, &a)
    })
    .await??;

    let filters = query_params_multi(cx, "filter");
    if !filters.is_empty() {
        let parsed: Vec<(String, String)> = filters
            .iter()
            .filter_map(|f| {
                let (k, v) = f.split_once(':')?;
                Some((k.to_string(), v.to_string()))
            })
            .collect();
        if parsed.len() == 1 {
            let k = parsed[0].0.clone();
            let v = parsed[0].1.clone();
            let kappas = tokio::task::spawn_blocking({
                let s = s.clone();
                let n = n.clone();
                move || s.meta_query(&n, &k, &v)
            })
            .await??;
            let body = serde_json::json!({"kappas": kappas});
            return (
                StatusCode::OK,
                serde_json::to_string(&body).unwrap_or_default(),
            )
                .into_response(cx);
        } else {
            let kappas = tokio::task::spawn_blocking({
                let s = s.clone();
                let n = n.clone();
                move || {
                    let refs: Vec<(&str, &str)> = parsed
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                        .collect();
                    s.meta_query_compound(&n, &refs)
                }
            })
            .await??;
            let body = serde_json::json!({"kappas": kappas});
            return (
                StatusCode::OK,
                serde_json::to_string(&body).unwrap_or_default(),
            )
                .into_response(cx);
        }
    }

    let key = query_param(cx, "key").unwrap_or_default();
    let value = query_param(cx, "value").unwrap_or_default();
    if key.is_empty() {
        let k = key;
        let v = value;
        let kappas = tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.list_by_meta(&k, &v)
        })
        .await??;
        let body = serde_json::json!({"kappas": kappas});
        return (
            StatusCode::OK,
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response(cx);
    }

    let k = key;
    let v = value;
    let kappas = tokio::task::spawn_blocking(move || {
        if v.is_empty() {
            s.meta_query_exists(&n, &k)
        } else {
            s.meta_query(&n, &k, &v)
        }
    })
    .await??;
    let body = serde_json::json!({"kappas": kappas});
    (
        StatusCode::OK,
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

pub fn list_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let asserter = super::registry_anchor(cx);
        let s = store(cx).clone();
        let n = ns.to_string();
        let prefix = query_param(cx, "prefix").unwrap_or_default();
        let kappas = tokio::task::spawn_blocking(move || {
            authorize(&*s, &n, OpClass::Read, &asserter)?;
            s.list(&prefix)
        })
        .await??;
        let body = serde_json::json!({"kappas": kappas});
        (
            StatusCode::OK,
            serde_json::to_string(&body).unwrap_or_default(),
        )
            .into_response(cx)
    })
}

fn query_params_multi(cx: &Cx, key: &str) -> Vec<String> {
    let Some(query) = uri(cx).query() else {
        return Vec::new();
    };
    query
        .split('&')
        .filter_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k == key {
                Some(super::tag::percent_decode(v))
            } else {
                None
            }
        })
        .collect()
}
