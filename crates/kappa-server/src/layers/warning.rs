//! OCI Warning header on every response, including errors.
//! Warning: 299 - "kappa-registry"
//! Per kappa-distribution spec section 6.1.

use topcoat::context::CxBuilder;
use topcoat::router::{Body, Next, Response, StatusCode};

pub fn warning_layer<'a>(
    cx: &'a mut CxBuilder,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let mut response = match next.run(cx, body).await {
            Ok(r) => r,
            Err(e) => {
                // Convert error to response so the warning header is attached.
                // Without this, error responses (404, 400, etc.) bypass the header.
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
