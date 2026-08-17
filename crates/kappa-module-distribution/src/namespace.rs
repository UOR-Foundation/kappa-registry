//! Namespace root and proof HTTP handlers.
//!
//! GET /v2/{*ns}/_root              -- current epoch root for namespace
//! GET /v2/{*ns}/_root/proof/{name} -- Merkle proof for a tag within epoch root

use std::borrow::Cow;

use topcoat::context::Cx;
use topcoat::router::error::bad_request;
use topcoat::router::response::{IntoResponse, Response};
use topcoat::router::{
    Body, Method, Path, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use std::sync::Arc;

use kappa_core::identity::node::NodeIdentity;
use kappa_core::types::NamespaceRef;
use topcoat::context::try_app_context;

use crate::{path_param, query_param, store};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/_root/proof/{name}")),
            proof_route,
        ))
        .route(RouteFn::new(
            Method::GET,
            Cow::Borrowed(Path::new("/v2/{*ns}/_root")),
            root_route,
        ))
}

fn root_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = crate::resolve_ns_read_async(cx).await?;
        root(cx, &ns).await
    })
}

fn proof_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = crate::resolve_ns_read_async(cx).await?;
        let name = path_param(cx, "name");
        proof(cx, &ns, name).await
    })
}

/// GET /v2/{*ns}/_root
/// Returns current epoch root kappa and tag count.
/// ?signed=true includes signer anchor, algorithm, and signature.
async fn root(cx: &Cx, ns: &NamespaceRef) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.clone();
    let want_signed = query_param(cx, "signed").as_deref() == Some("true");

    let (root_kappa, tag_count) = tokio::task::spawn_blocking({
        let s = s.clone();
        let n = n.clone();
        move || {
            let root = s.epoch_current(&n)?;
            let tags = s.tag_list(&n)?;
            let count = tags.iter().filter(|t| !t.name.starts_with('_')).count();
            Ok::<(Option<String>, usize), kappa_core::StoreError>((root, count))
        }
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    if want_signed {
        if let Some(ref rk) = root_kappa {
            if let Some(ni) = try_app_context::<Arc<NodeIdentity>>(cx) {
                let timestamp = chrono::Utc::now().to_rfc3339();
                let message = format!("{}\n{rk}\n{timestamp}", ns.as_str());
                let signature = ni.sign(message.as_bytes()).unwrap_or_default();
                let body = serde_json::json!({
                    "namespace": ns.as_str(),
                    "root": rk,
                    "count": tag_count,
                    "timestamp": timestamp,
                    "algorithm": ni.algorithm(),
                    "public_key": hex::encode(ni.public_key()),
                    "signature": hex::encode(&signature),
                    "signer_anchor": ni.anchor().as_str(),
                });
                return (
                    StatusCode::OK,
                    [("content-type", "application/json".to_string())],
                    serde_json::to_string(&body).unwrap_or_default(),
                )
                    .into_response(cx);
            }
        }
    }

    let body = serde_json::json!({
        "root": root_kappa,
        "count": tag_count,
    });
    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&body).unwrap_or_default(),
    )
        .into_response(cx)
}

/// GET /v2/{*ns}/_root/proof/{name}
/// Returns the epoch root and a Merkle inclusion proof for the named tag.
async fn proof(cx: &Cx, ns: &NamespaceRef, name: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();
    let n = ns.clone();
    let nm = name.to_string();

    let result = tokio::task::spawn_blocking(move || {
        let root_kappa = s
            .epoch_current(&n)?
            .ok_or_else(|| kappa_core::StoreError::NotFound("no epoch root".to_string()))?;
        let epoch = s.epoch_get(&root_kappa)?;

        // Find the tag's position in the sorted tag list for proof index
        let tags = s.tag_list(&n)?;
        let public_tags: Vec<&kappa_core::types::TagEntry> =
            tags.iter().filter(|t| !t.name.starts_with('_')).collect();
        let index = public_tags
            .iter()
            .position(|t| t.name == nm)
            .ok_or_else(|| kappa_core::StoreError::NotFound(format!("tag {} not found", nm)))?;

        Ok::<serde_json::Value, kappa_core::StoreError>(serde_json::json!({
            "root": root_kappa,
            "epoch_number": epoch.epoch_number,
            "tag_name": nm,
            "tag_index": index,
            "timestamp_ms": epoch.timestamp_ms,
        }))
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&result).unwrap_or_default(),
    )
        .into_response(cx)
}
