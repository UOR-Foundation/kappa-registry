//! Schema registration and management HTTP handlers.
//!
//! PUT /v2/{*ns}/schemas/{scope} -- register schema (with evolution tracking)
//! GET /v2/{*ns}/schemas/{scope} -- get schema
//! GET /v2/{*ns}/schemas/        -- list schemas

use std::borrow::Cow;

use topcoat::context::Cx;
use topcoat::router::error::bad_request;
use topcoat::router::{
    Body, IntoResponse, Method, Path, Response, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use kappa_core::store::blob_put_computed;
use kappa_core::types::{Edge, EdgeRelation};

use crate::{path_param, read_body, store};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(RouteFn::new(
            Method::PUT,
            Cow::Borrowed(Path::new("/v2/{*ns}/schemas/{scope}")),
            register_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/schemas/{scope}")),
            get_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/schemas/")),
            list_route,
        ))
}

fn register_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = path_param(cx, "ns");
        let scope = path_param(cx, "scope");
        register_schema(cx, ns, scope, &bytes).await
    })
}

fn get_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let scope = path_param(cx, "scope");
        get(cx, ns, scope).await
    })
}

fn list_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        list(cx, ns).await
    })
}

async fn register_schema(cx: &Cx, ns: &str, scope: &str, body: &[u8]) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.to_string();
    let sc = scope.to_string();
    let content = body.to_vec();

    // Check for existing schema at this scope (for evolution tracking)
    let old_kappa = {
        let s = s.clone();
        let n = n.clone();
        let sc = sc.clone();
        tokio::task::spawn_blocking(move || {
            s.tag_get(&n, &format!("_schema/{}", sc))
                .ok()
                .map(|e| e.kappa)
        })
        .await
        .map_err(|e| bad_request(e.to_string()))?
    };

    // Store new schema blob and tag
    let kappa = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        let sc = sc.clone();
        move || {
            let k = blob_put_computed(&*s, &content)?;
            s.tag_set(&n, &format!("_schema/{}", sc), &k)?;
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
            s.blob_put_meta(&k, "object-type", b"schema")?;
            s.meta_set(&n, &k, "object-type", "schema")
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    // Schema evolution: create derives-from edge from new to old
    if let Some(old_k) = old_kappa {
        if old_k != kappa {
            let asserter = crate::registry_anchor(cx);
            let edge = Edge {
                source: kappa.clone(),
                target: old_k,
                relation: EdgeRelation::DerivedFrom,
                asserter,
                value_kappa: None,
                metadata: None,
            };
            let n = ns.to_string();
            let _ = tokio::task::spawn_blocking({
                let s = s.clone();
                move || s.edge_put(&n, &edge)
            })
            .await;
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
    let s = store(cx).clone();
    let n = ns.to_string();
    let sc = scope.to_string();

    let (kappa, content) = tokio::task::spawn_blocking(move || {
        let tag_name = format!("_schema/{}", sc);
        let entry = s.tag_get(&n, &tag_name)?;
        let content = s.blob_get(&entry.kappa)?;
        Ok::<(String, Vec<u8>), kappa_core::StoreError>((entry.kappa, content))
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

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
    let s = store(cx).clone();
    let n = ns.to_string();

    let schemas = tokio::task::spawn_blocking(move || s.tag_prefix(&n, "_schema/"))
        .await
        .map_err(|e| bad_request(e.to_string()))?
        .map_err(crate::store_err)?;

    let records: Vec<serde_json::Value> = schemas
        .iter()
        .map(|t| {
            let scope = t.name.strip_prefix("_schema/").unwrap_or(&t.name);
            serde_json::json!({"scope": scope, "kappa": t.kappa})
        })
        .collect();

    let body = serde_json::json!({"schemas": records});
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}
