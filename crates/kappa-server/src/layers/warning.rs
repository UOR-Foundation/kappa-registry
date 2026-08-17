//! OCI Warning header on OCI and kappa-distribution responses only.
//! Warning: 299 - "kappa-registry"
//! Per kappa-distribution spec section 6.1.
//!
//! Non-OCI responses (S3, Git, Nix) do NOT receive this header.
//! Detection is by request path prefix: /v2/, /identity/, /_status,
//! /openapi.json, /docs are OCI/kappa-distribution.
//!
//! The header is added to BOTH success and error responses on OCI
//! paths. Error responses are converted to HTTP responses with the
//! error's status code and body so the Warning header can be attached.

use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, Next};

pub fn warning_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let is_oci = {
            use topcoat::context::request_context;
            let parts: &http::request::Parts = request_context(cx);
            let path = parts.uri.path();
            path.starts_with("/v2/") || path == "/v2" || path.starts_with("/v2?")
                || path.starts_with("/identity/")
                || path == "/_status" || path.starts_with("/_status/")
                || path == "/openapi.json" || path == "/docs"
        };

        if !is_oci {
            return next.run(cx, body).await;
        }

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

        response
            .headers_mut()
            .insert("warning", "299 - \"kappa-registry\"".parse().unwrap());
        Ok(response)
    })
}
