//! OCI referrers API: list manifests that refer to a given digest.

use topcoat::context::Cx;
use topcoat::router::{Body, Response, RouteFuture, StatusCode};

use kappa_core::types::{Direction, EdgeQuery, EdgeRelation, NamespaceRef};

use crate::{path_param, query_param, store};

pub fn list_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let _ = body;
        let ns = crate::resolve_ns_read_async(cx).await?;
        let digest = path_param(cx, "digest");
        list(cx, &ns, digest).await
    })
}

async fn list(cx: &Cx, ns: &NamespaceRef, digest: &str) -> topcoat::Result<Response> {
    let s = store(cx).clone();

    let query = EdgeQuery {
        anchor: digest.to_string(),
        direction: Direction::Inbound,
        relation: Some(EdgeRelation::RefersTo),
        asserter: None,
    };

    let n = ns.clone();
    let edges = tokio::task::spawn_blocking({
        let s = s.clone();
        move || s.edge_query(&n, &query)
    })
    .await
    .map_err(|e| topcoat::router::error::bad_request(e.to_string()))?
    .map_err(crate::store_err)?;

    let artifact_type_filter = query_param(cx, "artifactType");

    let mut descriptors: Vec<serde_json::Value> = Vec::new();
    for edge in &edges {
        let source_kappa = edge.source.clone();
        let manifest_bytes = tokio::task::spawn_blocking({
            let s = s.clone();
            move || s.blob_get(&source_kappa)
        })
        .await
        .map_err(|e| topcoat::router::error::bad_request(e.to_string()))?;

        let body = match manifest_bytes {
            Ok(b) => b,
            Err(_) => continue,
        };

        let manifest: serde_json::Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(_) => continue,
        };

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
