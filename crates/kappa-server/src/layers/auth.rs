//! Authentication and authorization layer.
//!
//! Two checks, in order:
//! 1. Bearer token: rejects unauthenticated requests when auth is required.
//! 2. Reserved namespace: rejects writes to reserved namespaces without
//!    a capability edge from the caller's identity.

use std::sync::Arc;

use topcoat::context::{app_context, try_app_context, CxBuilder};
use topcoat::router::{Body, Next, Response, StatusCode};

use kappa_core::store::KappaStore;

use crate::auth::{authorize, is_reserved, BearerAuth};
use crate::ratelimit::{classify_request, OpClass};

pub fn auth_layer<'a>(
    cx: &'a mut CxBuilder,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let path = topcoat::router::uri(cx).path().to_string();
        let method = topcoat::router::method(cx).to_string();

        // 1. Bearer token authentication
        if let Some(bearer) = try_app_context::<Arc<BearerAuth>>(cx) {
            let hdrs = topcoat::router::headers(cx);
            if let Err(rejection) = bearer.check(&path, hdrs) {
                return Ok(rejection);
            }
        }

        // 2. Reserved namespace authorization
        // Extract namespace from /v2/{ns}/... paths
        if let Some(ns) = extract_namespace(&path) {
            if is_reserved(&ns) {
                let op = classify_request(&method, &path);
                if !matches!(op, OpClass::Exempt) {
                    // Anonymous requests have no asserter identity.
                    // Reserved namespaces require a capability edge.
                    // Without an asserter, the authorize check will find
                    // no matching edges and reject.
                    let asserter = "anonymous";
                    let store = app_context::<Arc<dyn KappaStore>>(cx);
                    let s = store.clone();
                    let ns_owned = ns.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        authorize(&*s, &ns_owned, op, asserter)
                    })
                    .await;

                    let authorized = match result {
                        Ok(Ok(())) => true,
                        _ => false,
                    };

                    if !authorized {
                        let body_str = format!(
                            r#"{{"errors":[{{"code":"DENIED","message":"reserved namespace requires capability"}}]}}"#
                        );
                        let mut response = Response::new(Body::from(body_str));
                        *response.status_mut() = StatusCode::FORBIDDEN;
                        response
                            .headers_mut()
                            .insert("content-type", "application/json".parse().unwrap());
                        return Ok(response);
                    }
                }
            }
        }

        next.run(cx, body).await
    })
}

/// Extract the namespace from a /v2/{ns}/... path.
/// Returns None for non-v2 paths or paths without a namespace segment.
fn extract_namespace(path: &str) -> Option<String> {
    let path = path.strip_prefix("/v2/")?;
    // The namespace is everything up to the next known segment boundary:
    // /blobs/, /manifests/, /tags/, /edges/, /filters/, /schemas/,
    // /gc/, /_transaction/, /_sequence/, /_root, /_events, /_bundle/,
    // /_reconcile, /_uploads/, /compose/, /witnesses/, /referrers/
    let boundaries = [
        "/blobs/", "/manifests/", "/tags/", "/edges/", "/filters/",
        "/schemas/", "/gc/", "/_transaction/", "/_sequence/", "/_root",
        "/_events", "/_bundle/", "/_reconcile", "/compose/", "/witnesses/",
        "/referrers/", "/_uploads/", "/_ws", "/_crdt/",
    ];
    for boundary in boundaries {
        if let Some(idx) = path.find(boundary) {
            if idx > 0 {
                return Some(path[..idx].to_string());
            }
        }
    }
    None
}
