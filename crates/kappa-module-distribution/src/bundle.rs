//! Bundle HTTP handlers.
//!
//! POST /v2/{*ns}/_bundle/create -- create KBND bundle from kappa list
//! POST /v2/{*ns}/_bundle/ingest -- ingest and verify a KBND bundle

use std::borrow::Cow;

use topcoat::context::Cx;
use topcoat::router::error::bad_request;
use topcoat::router::{
    Body, IntoResponse, Method, Path, Response, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use kappa_core::types::NamespaceRef;

use crate::{path_param, read_body, store};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/_bundle/create")),
            create_route,
        ))
        .route(RouteFn::new(
            Method::POST,
            Cow::Borrowed(Path::new("/v2/{*ns}/_bundle/ingest")),
            ingest_route,
        ))
}

fn create_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = NamespaceRef::from(path_param(cx, "ns"));
        create(cx, &ns, &bytes).await
    })
}

fn ingest_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = NamespaceRef::from(path_param(cx, "ns"));
        ingest(cx, &ns, &bytes).await
    })
}

async fn create(cx: &Cx, _ns: &NamespaceRef, body: &[u8]) -> topcoat::Result<Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))?;
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
    let bundle = tokio::task::spawn_blocking(move || {
        let mut objects: Vec<(String, Vec<u8>)> = Vec::new();
        for k in &kappas {
            let content = s.blob_get(k)?;
            objects.push((k.clone(), content));
        }
        let refs: Vec<(&str, &[u8])> = objects
            .iter()
            .map(|(k, c)| (k.as_str(), c.as_slice()))
            .collect();
        Ok::<Vec<u8>, kappa_core::StoreError>(kappa_core::bundle::encode(&refs, delta))
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    (
        StatusCode::OK,
        [("content-type", "application/x-kappa-bundle".to_string())],
        bundle,
    )
        .into_response(cx)
}

async fn ingest(cx: &Cx, _ns: &NamespaceRef, body: &[u8]) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let data = body.to_vec();
    let ingested = tokio::task::spawn_blocking(move || {
        let resolve_base = |kappa: &str| -> Option<Vec<u8>> { s.blob_get(kappa).ok() };
        let entries = kappa_core::bundle::decode(&data, Some(&resolve_base))
            .map_err(|e| kappa_core::StoreError::Rejected(e.to_string()))?;
        let mut kappas = Vec::with_capacity(entries.len());
        for entry in &entries {
            s.ingest_verified(&entry.kappa,&entry.content)?;
            kappas.push(entry.kappa.clone());
        }
        Ok::<Vec<String>, kappa_core::StoreError>(kappas)
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let resp = serde_json::json!({"ingested": ingested});
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&resp).unwrap_or_default(),
    )
        .into_response(cx)
}
