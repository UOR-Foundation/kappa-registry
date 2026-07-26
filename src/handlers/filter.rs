use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::not_found;
use topcoat::router::{Body, IntoResponse, Response, RouteFuture, StatusCode};

use crate::auth::authorize;
use crate::ratelimit::OpClass;
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
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let p = ns.to_string();
    let sc = scope.to_string();
    let content = body.to_vec();
    let kappa = tokio::task::spawn_blocking({
        let s = s.clone();
        let p = p.clone();
        let a = asserter;
        move || {
            authorize(&*s, &p, OpClass::Write, &a)?;
            s.filter_register(&p, &sc, &content)
        }
    })
    .await??;

    let k = kappa.clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking(move || s.meta_set(&n, &k, &[("object-type", "filter")])).await??;

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
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let p = ns.to_string();
    let records = tokio::task::spawn_blocking(move || {
        authorize(&*s, &p, OpClass::Read, &asserter)?;
        s.filter_list(&p)
    })
    .await??;
    let body = serde_json::json!({"filters": records});
    (
        StatusCode::OK,
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn delete(cx: &Cx, ns: &str, filter_kappa: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    let fk = filter_kappa.to_string();
    let removed = tokio::task::spawn_blocking(move || {
        authorize(&*s, &n, OpClass::Admin, &asserter)?;
        s.filter_remove(&fk)
    })
    .await??;
    if removed {
        StatusCode::ACCEPTED.into_response(cx)
    } else {
        Err(not_found().into())
    }
}
