use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::{Body, IntoResponse, Response, RouteFuture, StatusCode};

use crate::auth::authorize;
use crate::ratelimit::OpClass;
use crate::store::fs::FsStore;
use crate::transaction::TransactionManager;

use super::path_param;

fn store(cx: &Cx) -> &Arc<FsStore> {
    app_context::<Arc<FsStore>>(cx)
}

fn transactions(cx: &Cx) -> &Arc<TransactionManager> {
    app_context::<Arc<TransactionManager>>(cx)
}

pub fn begin_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        begin(cx, ns).await
    })
}

pub fn put_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = super::read_body(body).await?;
        let ns = path_param(cx, "ns");
        let id = path_param(cx, "id");
        let kappa = path_param(cx, "kappa");
        put(cx, ns, id, kappa, &bytes).await
    })
}

pub fn commit_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let id = path_param(cx, "id");
        commit(cx, ns, id).await
    })
}

pub fn abort_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let id = path_param(cx, "id");
        abort(cx, ns, id).await
    })
}

async fn begin(cx: &Cx, ns: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking(move || authorize(&*s, &n, OpClass::Write, &asserter)).await??;

    let txn_id = transactions(cx).begin(ns)?;

    let body = serde_json::json!({"transaction_id": txn_id});
    (
        StatusCode::CREATED,
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn put(
    cx: &Cx,
    ns: &str,
    txn_id: &str,
    kappa: &str,
    body: &[u8],
) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let a = asserter;
        move || authorize(&*s, &n, OpClass::Write, &a)
    })
    .await??;

    let txn = txn_id.to_string();
    let k = kappa.to_string();
    let content = body.to_vec();
    let txns = transactions(cx).clone();
    let created = tokio::task::spawn_blocking(move || txns.put(&txn, &k, &content)).await??;

    let status = if created {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    (
        status,
        [
            ("x-kappa-label", kappa.to_string()),
            ("content-length", "0".to_string()),
        ],
    )
        .into_response(cx)
}

async fn commit(cx: &Cx, ns: &str, txn_id: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let a = asserter;
        move || authorize(&*s, &n, OpClass::Write, &a)
    })
    .await??;

    let txn = txn_id.to_string();
    let txns = transactions(cx).clone();
    let result = tokio::task::spawn_blocking(move || txns.commit(&txn, &*s)).await??;

    let body = serde_json::json!({"promoted": result.promoted});
    (
        StatusCode::OK,
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn abort(cx: &Cx, ns: &str, txn_id: &str) -> topcoat::Result<Response> {
    let asserter = super::registry_anchor(cx);
    let s = store(cx).clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let a = asserter;
        move || authorize(&*s, &n, OpClass::Write, &a)
    })
    .await??;

    let txn = txn_id.to_string();
    let txns = transactions(cx).clone();
    tokio::task::spawn_blocking(move || txns.abort(&txn)).await??;

    StatusCode::NO_CONTENT.into_response(cx)
}
