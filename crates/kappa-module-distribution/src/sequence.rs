//! Sequence HTTP handlers.
//!
//! POST /v2/{*ns}/_sequence/{name}/next -- increment and return
//! GET  /v2/{*ns}/_sequence/{name}      -- return current value

use std::borrow::Cow;

use topcoat::context::Cx;
use topcoat::router::error::bad_request;
use topcoat::router::{
    Body, IntoResponse, Method, Path, Response, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use kappa_core::types::NamespaceRef;

use crate::{path_param, store};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/_sequence/{name}/next")),
            next_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/_sequence/{name}")),
            current_route,
        ))
}

fn next_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = NamespaceRef::from(path_param(cx, "ns"));
        let name = path_param(cx, "name");
        next(cx, &ns, name).await
    })
}

fn current_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = NamespaceRef::from(path_param(cx, "ns"));
        let name = path_param(cx, "name");
        current(cx, &ns, name).await
    })
}

async fn next(cx: &Cx, ns: &NamespaceRef, name: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.clone();
    let nm = name.to_string();
    let val = tokio::task::spawn_blocking(move || s.sequence_next(&n, &nm))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

    let body = serde_json::json!({"name": name, "value": val});
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn current(cx: &Cx, ns: &NamespaceRef, name: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.clone();
    let nm = name.to_string();
    let val = tokio::task::spawn_blocking(move || s.sequence_current(&n, &nm))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

    let body = serde_json::json!({"name": name, "value": val});
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}
