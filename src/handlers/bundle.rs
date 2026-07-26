use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::error::bad_request;
use topcoat::router::{Body, IntoResponse, Response, RouteFuture, StatusCode};

use crate::auth;
use crate::store::fs::FsStore;
use crate::store::KappaStore;

use super::path_param;

fn store(cx: &Cx) -> &Arc<FsStore> {
    app_context::<Arc<FsStore>>(cx)
}

pub fn create_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = super::read_body(body).await?;
        let ns = path_param(cx, "ns");
        create(cx, ns, &bytes).await
    })
}

pub fn ingest_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = super::read_body(body).await?;
        let ns = path_param(cx, "ns");
        ingest(cx, ns, &bytes).await
    })
}

async fn create(cx: &Cx, ns: &str, body: &[u8]) -> topcoat::Result<Response> {
    auth::authorize(ns, "bundle.create")?;

    let v: serde_json::Value = serde_json::from_slice(body)?;
    let kappas: Vec<String> = v["kappas"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let delta = v["delta"].as_bool().unwrap_or(false);

    if kappas.is_empty() {
        return Err(bad_request("empty kappas list").into());
    }

    let s = store(cx).clone();
    let bundle = tokio::task::spawn_blocking(move || s.bundle_create(&kappas, delta))
        .await?
        .map_err(super::store_err)?;

    (
        StatusCode::OK,
        [("content-type", "application/x-kappa-bundle".to_string())],
        bundle,
    )
        .into_response(cx)
}

async fn ingest(cx: &Cx, ns: &str, body: &[u8]) -> topcoat::Result<Response> {
    auth::authorize(ns, "bundle.ingest")?;

    let s = store(cx).clone();
    let data = body.to_vec();
    let ingested = tokio::task::spawn_blocking(move || s.bundle_ingest(&data))
        .await?
        .map_err(super::store_err)?;

    let resp = serde_json::json!({"ingested": ingested});
    (
        StatusCode::OK,
        serde_json::to_string(&resp).unwrap_or_default(),
    )
        .into_response(cx)
}
