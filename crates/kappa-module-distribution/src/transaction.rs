//! Transaction HTTP handlers.
//!
//! POST   /v2/{*ns}/_transaction/begin      -- begin transaction
//! PUT    /v2/{*ns}/_transaction/{id}/{kappa} -- stage blob
//! POST   /v2/{*ns}/_transaction/{id}/commit -- commit
//! DELETE /v2/{*ns}/_transaction/{id}        -- abort

use std::borrow::Cow;
use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::bad_request;
use topcoat::router::{
    Body, IntoResponse, Method, Path, Response, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use kappa_core::transaction::TransactionManager;

use crate::{path_param, read_body, store};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/_transaction/begin")),
            begin_route,
        ))
        .route(RouteFn::new(
            Method::PUT,
            Cow::Borrowed(Path::new("/v2/{*ns}/_transaction/{id}/{kappa}")),
            put_route,
        ))
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/_transaction/{id}/commit")),
            commit_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            Cow::Borrowed(Path::new("/v2/{*ns}/_transaction/{id}")),
            abort_route,
        ))
}

fn transactions(cx: &Cx) -> &Arc<TransactionManager> {
    app_context::<Arc<TransactionManager>>(cx)
}

fn begin_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        begin(cx, ns).await
    })
}

fn put_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = path_param(cx, "ns");
        let id = path_param(cx, "id");
        let kappa = path_param(cx, "kappa");
        put(cx, ns, id, kappa, &bytes).await
    })
}

fn commit_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let id = path_param(cx, "id");
        commit(cx, ns, id).await
    })
}

fn abort_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let id = path_param(cx, "id");
        abort(cx, ns, id).await
    })
}

async fn begin(cx: &Cx, ns: &str) -> topcoat::Result<Response> {
    let txns = transactions(cx).clone();
    let n = ns.to_string();
    let txn_id = tokio::task::spawn_blocking(move || txns.begin(&n))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(|e| bad_request(e.to_string()))?;

    let body = serde_json::json!({"transaction_id": txn_id});
    (
        StatusCode::CREATED,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn put(
    cx: &Cx,
    _ns: &str,
    txn_id: &str,
    kappa: &str,
    body: &[u8],
) -> topcoat::Result<Response> {
    let txns = transactions(cx).clone();
    let tid = txn_id.to_string();
    let k = kappa.to_string();
    let content = body.to_vec();
    let created = tokio::task::spawn_blocking(move || txns.put(&tid, &k, &content))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(|e| bad_request(e.to_string()))?;

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

async fn commit(cx: &Cx, _ns: &str, txn_id: &str) -> topcoat::Result<Response> {
    let txns = transactions(cx).clone();
    let s = store(cx).clone();
    let tid = txn_id.to_string();
    let result = tokio::task::spawn_blocking(move || txns.commit(&tid, &*s))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(|e| bad_request(e.to_string()))?;

    let body = serde_json::json!({"promoted": result.promoted});
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn abort(cx: &Cx, _ns: &str, txn_id: &str) -> topcoat::Result<Response> {
    let txns = transactions(cx).clone();
    let tid = txn_id.to_string();
    tokio::task::spawn_blocking(move || txns.abort(&tid))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(|e| bad_request(e.to_string()))?;

    StatusCode::NO_CONTENT.into_response(cx)
}
