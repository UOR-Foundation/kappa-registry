use std::sync::Arc;

use topcoat::context::{app_context, Cx};
use topcoat::router::{Body, Response, RouteFuture, StatusCode};

use crate::auth;
use crate::store::fs::FsStore;
use crate::store::{Direction, KappaStore};

use super::path_param;

fn query_param(cx: &Cx, key: &str) -> Option<String> {
    let query = topcoat::router::uri(cx).query()?;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            if k == key {
                return Some(super::tag::percent_decode(v));
            }
        }
    }
    None
}

fn store(cx: &Cx) -> &Arc<FsStore> {
    app_context::<Arc<FsStore>>(cx)
}

pub fn list_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = path_param(cx, "ns");
        let digest = path_param(cx, "digest");
        list(cx, ns, digest).await
    })
}

async fn list(cx: &Cx, ns: &str, digest: &str) -> topcoat::Result<Response> {
    auth::authorize(ns, "referrers.list")?;

    let s = store(cx).clone();
    let node = digest.to_string();
    let n = ns.to_string();
    let edges = tokio::task::spawn_blocking(move || {
        s.edge_query(&n, &node, Direction::Inbound, Some("refers-to"), None, None)
    })
    .await?
    .map_err(super::store_err)?;

    let artifact_type_filter = query_param(cx, "artifactType");

    let mut descriptors: Vec<serde_json::Value> = Vec::new();
    for edge in &edges {
        let s = store(cx).clone();
        let source = edge.source.clone();
        let manifest_bytes = tokio::task::spawn_blocking(move || s.get(&source))
            .await?
            .map_err(super::store_err)?;
        if let Some(body) = manifest_bytes {
            let manifest: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
            let media_type = manifest
                .get("mediaType")
                .and_then(|m| m.as_str())
                .unwrap_or("application/vnd.oci.image.manifest.v1+json");
            let artifact_type = manifest
                .get("artifactType")
                .and_then(|a| a.as_str())
                .or_else(|| {
                    manifest
                        .get("config")
                        .and_then(|c| c.get("mediaType"))
                        .and_then(|m| m.as_str())
                })
                .unwrap_or("");
            let size = body.len();
            let annotations = manifest
                .get("annotations")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            if let Some(ref filter) = artifact_type_filter {
                if artifact_type != filter {
                    continue;
                }
            }

            descriptors.push(serde_json::json!({
                "mediaType": media_type,
                "digest": edge.source,
                "size": size,
                "artifactType": artifact_type,
                "annotations": annotations,
            }));
        }
    }

    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": descriptors,
    });

    let body_bytes = serde_json::to_vec(&index).unwrap_or_default();
    let mut response = Response::new(Body::from(body_bytes));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        "content-type",
        "application/vnd.oci.image.index.v1+json".parse().unwrap(),
    );
    if artifact_type_filter.is_some() {
        response
            .headers_mut()
            .insert("oci-filters-applied", "artifactType".parse().unwrap());
    }
    Ok(response)
}
