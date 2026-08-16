//! Authentication and authorization layer.
//!
//! Two checks, in order:
//! 1. Bearer token: rejects unauthenticated requests when auth is required.
//!    Resolves the token to an asserter anchor for authorization.
//! 2. Reserved namespace: rejects operations on reserved namespaces without
//!    a capability edge (or delegation chain) from the caller's identity.

use std::sync::Arc;

use topcoat::context::{app_context, try_app_context, Cx};
use topcoat::router::response::Response;
use topcoat::router::{Body, Next, StatusCode};

use kappa_core::store::KappaStore;

use crate::auth::{authorize, is_reserved, BearerAuth};
use crate::ratelimit::{classify_request, OpClass};


pub fn auth_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let path = topcoat::router::request::uri(cx).path().to_string();
        let method = topcoat::router::request::method(cx).to_string();

        // 1. Bearer token authentication -> resolved asserter identity
        let asserter = if let Some(bearer) = try_app_context::<Arc<BearerAuth>>(cx) {
            let hdrs = topcoat::router::request::headers(cx);
            match bearer.check(&path, hdrs) {
                Ok(identity) => identity.asserter,
                Err(rejection) => return Ok(rejection),
            }
        } else {
            "anonymous".to_string()
        };

        // Store caller identity in request context for downstream handlers
        let cx = cx.with(kappa_core::types::CallerIdentity(asserter.clone()));

        // 2. Reserved namespace authorization using resolved identity
        if let Some(ns) = extract_namespace(&path) {
            if is_reserved(&ns) {
                let op = classify_request(&method, &path);
                if !matches!(op, OpClass::Exempt) {
                    let store = app_context::<Arc<dyn KappaStore>>(&cx);
                    let s = store.clone();
                    let ns_name = ns.clone();
                    let asserter_owned = asserter.clone();
                    let result = tokio::task::spawn_blocking(move || {
                        // /v2/ paths are OCI protocol scope
                        authorize(&*s, &ns_name, Some("oci"), op, &asserter_owned)
                    })
                    .await;

                    let authorized = matches!(result, Ok(Ok(())));

                    if !authorized {
                        let body_str = r#"{"errors":[{"code":"DENIED","message":"reserved namespace requires capability"}]}"#;
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

        next.run(&cx, body).await
    })
}

/// Extract the namespace from a /v2/{ns}/... path.
/// Returns None for non-v2 paths or paths without a namespace segment.
fn extract_namespace(path: &str) -> Option<String> {
    let path = path.strip_prefix("/v2/")?;
    let boundaries = [
        "/blobs/", "/manifests/", "/tags/", "/edges/", "/filters/",
        "/schemas/", "/gc/", "/_transaction/", "/_sequence/", "/_root",
        "/_events", "/_bundle/", "/_reconcile", "/compose/", "/witnesses/",
        "/referrers/", "/_uploads/", "/_events/", "/_crdt/",
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
