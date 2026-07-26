use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::not_found;
use topcoat::router::{Body, IntoResponse, Response, RouteFuture, StatusCode};

use crate::auth;
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
        let scope = path_param(cx, "filter_key");
        register(cx, ns, scope, &bytes).await
    })
}

pub fn list_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        list(cx, ns).await
    })
}

pub fn delete_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let kappa = path_param(cx, "filter_key");
        delete(cx, ns, kappa).await
    })
}

async fn register(cx: &Cx, ns: &str, scope: &str, body: &[u8]) -> topcoat::Result<Response> {
    auth::authorize(ns, "filter.register")?;

    let s = store(cx).clone();
    let p = ns.to_string();
    let sc = scope.to_string();
    let content = body.to_vec();
    let kappa = tokio::task::spawn_blocking(move || s.filter_register(&p, &sc, &content))
        .await?
        .map_err(super::store_err)?;

    let s = store(cx).clone();
    let k = kappa.clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking(move || s.meta_set(&n, &k, &[("object-type", "filter")]))
        .await?
        .map_err(super::store_err)?;

    (
        StatusCode::CREATED,
        [
            ("x-kappa-label", kappa),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

async fn list(cx: &Cx, ns: &str) -> topcoat::Result<Response> {
    auth::authorize(ns, "filter.list")?;

    let s = store(cx).clone();
    let p = ns.to_string();
    let records = tokio::task::spawn_blocking(move || s.filter_list(&p))
        .await?
        .map_err(super::store_err)?;
    let body = serde_json::json!({"filters": records});
    (
        StatusCode::OK,
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn delete(cx: &Cx, ns: &str, filter_kappa: &str) -> topcoat::Result<Response> {
    auth::authorize(ns, "filter.delete")?;

    let s = store(cx).clone();
    let fk = filter_kappa.to_string();
    let removed = tokio::task::spawn_blocking(move || s.filter_remove(&fk))
        .await?
        .map_err(super::store_err)?;
    if removed {
        StatusCode::ACCEPTED.into_response(cx)
    } else {
        Err(not_found().into())
    }
}
