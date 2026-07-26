use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::not_found;
use topcoat::router::{Body, IntoResponse, Response, RouteFuture, StatusCode};

use crate::auth;
use crate::kappa::{axis_of, compute_kappa};
use crate::store::fs::FsStore;
use crate::store::KappaStore;

use super::path_param;

fn store(cx: &Cx) -> &Arc<FsStore> {
    app_context::<Arc<FsStore>>(cx)
}

pub fn register_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = super::read_body(body).await?;
        let ns = path_param(cx, "ns");
        let scope = path_param(cx, "scope");
        register(cx, ns, scope, &bytes).await
    })
}

pub fn get_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let scope = path_param(cx, "scope");
        get(cx, ns, scope).await
    })
}

pub fn list_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        list(cx, ns).await
    })
}

async fn register(cx: &Cx, ns: &str, scope: &str, body: &[u8]) -> topcoat::Result<Response> {
    auth::authorize(ns, "schema.register")?;

    let s = store(cx).clone();
    let p = ns.to_string();
    let sc = scope.to_string();
    let old_schema = tokio::task::spawn_blocking({
        let s = s.clone();
        let p = p.clone();
        let sc = sc.clone();
        move || s.schema_get(&p, &sc)
    })
    .await?
    .map_err(super::store_err)?;
    let old_kappa = old_schema.map(|(k, _)| k);

    let content = body.to_vec();
    let s = store(cx).clone();
    let kappa = tokio::task::spawn_blocking({
        let s = s.clone();
        let p = ns.to_string();
        let sc = scope.to_string();
        let c = content.clone();
        move || s.schema_register(&p, &sc, &c)
    })
    .await?
    .map_err(super::store_err)?;

    let s = store(cx).clone();
    let k = kappa.clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking(move || s.meta_set(&n, &k, &[("object-type", "schema")]))
        .await?
        .map_err(super::store_err)?;

    if let Some(ref old_k) = old_kappa {
        if *old_k != kappa {
            let axis = axis_of(&kappa).unwrap_or("sha256");
            let metadata = vec![0xA0u8];
            let canonical = super::edge::edge_canonical_pub(
                kappa.as_bytes(),
                "derives-from",
                old_k.as_bytes(),
                &metadata,
            );
            let edge_kappa = compute_kappa(axis, &canonical)?;
            let s = store(cx).clone();
            let ek = edge_kappa.as_str().to_string();
            let canon = canonical.clone();
            tokio::task::spawn_blocking({
                let s = s.clone();
                let ek = ek.clone();
                move || s.put(&ek, &canon)
            })
            .await?
            .map_err(super::store_err)?;
            let new_k = kappa.clone();
            let old = old_k.clone();
            let n = ns.to_string();
            tokio::task::spawn_blocking(move || {
                s.edge_put(
                    &n,
                    &ek,
                    &new_k,
                    "derives-from",
                    &old,
                    &canonical,
                    serde_json::Value::Object(serde_json::Map::new()),
                )
            })
            .await?
            .map_err(super::store_err)?;
        }
    }

    (
        StatusCode::CREATED,
        [
            ("x-kappa-label", kappa),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

async fn get(cx: &Cx, ns: &str, scope: &str) -> topcoat::Result<Response> {
    auth::authorize(ns, "schema.get")?;

    let s = store(cx).clone();
    let p = ns.to_string();
    let sc = scope.to_string();
    let result = tokio::task::spawn_blocking(move || s.schema_get(&p, &sc))
        .await?
        .map_err(super::store_err)?;
    let (kappa, content) = result.ok_or_else(not_found)?;

    (
        StatusCode::OK,
        [
            ("content-length", content.len().to_string()),
            ("x-kappa-label", kappa),
            ("content-type", "application/octet-stream".to_string()),
        ],
        content,
    )
        .into_response(cx)
}

async fn list(cx: &Cx, ns: &str) -> topcoat::Result<Response> {
    auth::authorize(ns, "schema.list")?;

    let s = store(cx).clone();
    let p = ns.to_string();
    let records = tokio::task::spawn_blocking(move || s.schema_list(&p))
        .await?
        .map_err(super::store_err)?;
    let body = serde_json::json!({"schemas": records});
    (
        StatusCode::OK,
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}
