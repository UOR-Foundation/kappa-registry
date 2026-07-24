use std::collections::HashMap;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

use crate::auth;
use crate::error::AppError;
use crate::store::{Direction, KappaStore};
use crate::AppState;

pub async fn list(
    state: &AppState,
    ns: &str,
    digest: &str,
    params: &HashMap<String, String>,
) -> Result<Response, AppError> {
    auth::authorize(ns, "referrers.list")?;

    let s = state.store.clone();
    let node = digest.to_string();
    let n = ns.to_string();
    let edges = tokio::task::spawn_blocking(move || {
        s.edge_query(&n, &node, Direction::Inbound, Some("refers-to"), None, None)
    })
    .await??;

    let artifact_type_filter = params.get("artifactType").map(|s| s.as_str());

    let mut descriptors: Vec<serde_json::Value> = Vec::new();
    for edge in &edges {
        let s = state.store.clone();
        let source = edge.source.clone();
        let manifest_bytes = tokio::task::spawn_blocking(move || s.get(&source)).await??;
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
            let annotations = manifest
                .get("annotations")
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            if let Some(filter) = artifact_type_filter {
                if artifact_type != filter {
                    continue;
                }
            }

            let mut desc = serde_json::json!({
                "mediaType": media_type,
                "digest": edge.source,
                "size": body.len(),
            });
            if !artifact_type.is_empty() {
                desc["artifactType"] = serde_json::json!(artifact_type);
            }
            if !annotations.is_null() {
                desc["annotations"] = annotations;
            }
            descriptors.push(desc);
        }
    }

    let index = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": descriptors,
    });

    let body = serde_json::to_vec(&index).unwrap_or_default();
    let mut resp = axum::http::Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/vnd.oci.image.index.v1+json");
    if artifact_type_filter.is_some() {
        resp = resp.header("oci-filters-applied", "artifactType");
    }
    Ok(resp
        .body(axum::body::Body::from(body))
        .unwrap()
        .into_response())
}
