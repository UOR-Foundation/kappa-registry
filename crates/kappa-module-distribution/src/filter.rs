//! Filter registration and management HTTP handlers.
//!
//! PUT    /v2/{*ns}/filters/{scope} -- register filter
//! GET    /v2/{*ns}/filters/        -- list filters
//! DELETE /v2/{*ns}/filters/{kappa} -- delete filter

use std::borrow::Cow;

use topcoat::context::Cx;
use topcoat::router::error::bad_request;
use topcoat::router::{
    Body, IntoResponse, Method, Path, Response, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use kappa_core::store::blob_put_computed;

use crate::{path_param, read_body, store};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(RouteFn::new(
            Method::PUT,
            Cow::Borrowed(Path::new("/v2/{*ns}/filters/{filter_key}")),
            register_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/filters/")),
            list_route,
        ))
        .route(RouteFn::new(
            Method::DELETE,
            Cow::Borrowed(Path::new("/v2/{*ns}/filters/{filter_key}")),
            delete_route,
        ))
}

fn register_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = path_param(cx, "ns");
        let scope = path_param(cx, "filter_key");
        register_filter(cx, ns, scope, &bytes).await
    })
}

fn list_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        list(cx, ns).await
    })
}

fn delete_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let kappa = path_param(cx, "filter_key");
        delete(cx, ns, kappa).await
    })
}

async fn register_filter(cx: &Cx, ns: &str, scope: &str, body: &[u8]) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.to_string();
    let sc = scope.to_string();
    let content = body.to_vec();

    let kappa = tokio::task::spawn_blocking({
        let s = s.clone();
        move || {
            let k = blob_put_computed(&*s, &content)?;
            s.tag_set(&n, &format!("_filter/{}", sc), &k)?;
            Ok::<String, kappa_core::StoreError>(k)
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    // Store object-type metadata (global + namespace-indexed)
    let k = kappa.clone();
    let n = ns.to_string();
    tokio::task::spawn_blocking({
        let s = s.clone();
        move || {
            s.blob_put_meta(&k, "object-type", b"filter")?;
            s.meta_set(&n, &k, "object-type", "filter")
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

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
    let s = store(cx).clone();
    let n = ns.to_string();

    let filters = tokio::task::spawn_blocking(move || s.tag_prefix(&n, "_filter/"))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

    let records: Vec<serde_json::Value> = filters
        .iter()
        .map(|t| {
            let scope = t.name.strip_prefix("_filter/").unwrap_or(&t.name);
            serde_json::json!({"scope": scope, "kappa": t.kappa})
        })
        .collect();

    let body = serde_json::json!({"filters": records});
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

async fn delete(cx: &Cx, ns: &str, filter_key: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.to_string();
    let fk = filter_key.to_string();

    tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        move || {
            let filters = s.tag_prefix(&n, "_filter/")?;
            for f in &filters {
                if f.kappa == fk || f.name == format!("_filter/{}", fk) {
                    s.tag_delete(&n, &f.name)?;
                    return Ok(());
                }
            }
            s.tag_delete(&n, &format!("_filter/{}", fk))
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    StatusCode::ACCEPTED.into_response(cx)
}
