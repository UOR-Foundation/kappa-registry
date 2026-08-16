//! Cascade delete HTTP handler.
//!
//! POST /v2/{*ns}/blobs/_cascade -- delete blobs reachable from roots

use std::borrow::Cow;

use topcoat::context::Cx;
use topcoat::router::error::bad_request;
use topcoat::router::{
    Body, IntoResponse, Method, Path, Response, RouteFn, RouteFuture, RouterBuilder, StatusCode,
};

use kappa_core::types::{Direction, EdgeQuery, NamespaceRef};

use crate::{path_param, read_body, store};

pub fn register(builder: RouterBuilder) -> RouterBuilder {
    builder.route(RouteFn::new(
        Method::POST,
        Cow::Borrowed(Path::new("/v2/{*ns}/blobs/_cascade")),
        cascade_route,
    ))
}

fn cascade_route(cx: &Cx, body: Body) -> RouteFuture<'_> {
    Box::pin(async move {
        let bytes = read_body(body).await?;
        let ns = NamespaceRef::from(path_param(cx, "ns"));
        cascade(cx, &ns, &bytes).await
    })
}

/// POST /v2/{*ns}/blobs/_cascade
/// Body: {"roots": ["sha256:...", ...]}
///
/// Computes the reachable set from the given roots via outbound edges,
/// then deletes every blob in the reachable set along with its tags
/// and edges. This is the inverse of GC -- GC retains reachable, cascade
/// deletes reachable.
async fn cascade(cx: &Cx, ns: &NamespaceRef, body: &[u8]) -> topcoat::Result<Response> {
    let v: serde_json::Value =
        serde_json::from_slice(body).map_err(|e| bad_request(format!("invalid JSON: {e}")))?;
    let roots: Vec<String> = v["roots"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    if roots.is_empty() {
        return Err(bad_request("empty roots list").into());
    }

    let s = store(cx).clone();
    let n = ns.clone();

    let report = tokio::task::spawn_blocking(move || {
        // Compute reachable set from roots
        let reachable = kappa_core::gc::compute_reachable(&roots, &|kappa: &str| {
            let query = EdgeQuery {
                anchor: kappa.to_string(),
                direction: Direction::Outbound,
                relation: None,
                asserter: None,
            };
            s.edge_query(&n, &query)
                .unwrap_or_default()
                .into_iter()
                .map(|e| e.target)
                .collect()
        });

        // Delete every blob in the reachable set
        let mut deleted = 0usize;
        for kappa in &reachable {
            if s.blob_delete(kappa).is_ok() {
                deleted += 1;
            }
        }

        serde_json::json!({
            "deleted": deleted,
            "reachable": reachable.len(),
        })
    })
    .await
    .map_err(|e| bad_request(e.to_string()))?;

    (
        StatusCode::OK,
        [("content-type", "application/json".to_string())],
        serde_json::to_string(&report).unwrap_or_default(),
    )
        .into_response(cx)
}
