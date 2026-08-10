//! OCI Warning header on OCI and kappa-distribution responses only.
//! Warning: 299 - "kappa-registry"
//! Per kappa-distribution spec section 6.1.
//!
//! S3 and Git responses do NOT receive this header. Detection is by
//! path prefix: /v2/ is OCI/kappa-distribution, /{repo}.git/ is Git,
//! everything else (/{bucket}/...) is S3.

use topcoat::context::CxBuilder;
use topcoat::router::{Body, Next, Response, StatusCode};

pub fn warning_layer<'a>(
    cx: &'a mut CxBuilder,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        // Determine protocol hint from request path
        let is_oci = {
            use topcoat::context::request_context;
            let parts: &http::request::Parts = request_context(cx);
            let path = parts.uri.path();
            path.starts_with("/v2/") || path == "/v2" || path.starts_with("/v2?")
                || path.starts_with("/identity/")
                || path == "/_status" || path.starts_with("/_status/")
                || path == "/openapi.json" || path == "/docs"
        };

        let mut response = match next.run(cx, body).await {
            Ok(r) => r,
            Err(e) => {
                let mut r = Response::new(Body::from(e.response_body()));
                *r.status_mut() = e.status_code();
                r.headers_mut()
                    .insert("content-type", "text/plain".parse().unwrap());
                r
            }
        };

        // Only add Warning header to OCI/kappa-distribution responses
        if is_oci {
            response
                .headers_mut()
                .insert("warning", "299 - \"kappa-registry\"".parse().unwrap());
        }
        Ok(response)
    })
}
