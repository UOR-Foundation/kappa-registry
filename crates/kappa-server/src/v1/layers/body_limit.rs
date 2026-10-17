//! Request body size enforcement by declared Content-Length.
//!
//! The protocol detector that claims a request declares its body class
//! (`BodyClass`), recorded by the namespace layer. Content bodies are
//! bounded by `MaxBlobSize`, control documents by `MaxApiBodyBytes`.
//! Handlers enforce their exact limits while reading the body; this layer
//! rejects oversized requests before any handler work.

use topcoat::context::{Cx, try_request_context};
use topcoat::router::response::Response;
use topcoat::router::{Body, Next, StatusCode};

use kappa_handler::BodyClass;
pub use kappa_handler::MaxBlobSize;

#[derive(Clone)]
pub struct MaxApiBodyBytes(pub usize);

pub fn body_limit_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        // The namespace layer runs before path-scoped layers and records the
        // class of every request; its absence is a layer-order defect.
        let Some(class) = try_request_context::<BodyClass>(cx).copied() else {
            tracing::error!("body class missing from request context");
            return Ok(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL",
                "request body class unavailable",
            ));
        };
        let (limit, code) = match class {
            BodyClass::Content => (kappa_handler::service::<MaxBlobSize>(cx).0, "SIZE_EXCEEDED"),
            BodyClass::Control => (
                kappa_handler::service::<MaxApiBodyBytes>(cx).0,
                "SIZE_INVALID",
            ),
        };

        if let Some(declared) = topcoat::router::request::headers(cx)
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            && declared > limit
        {
            return Ok(json_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                code,
                &format!("body {declared} bytes exceeds limit {limit}"),
            ));
        }
        next.run(cx, body).await
    })
}

fn json_error(status: StatusCode, code: &str, message: &str) -> Response {
    let body = serde_json::json!({"errors": [{"code": code, "message": message}]}).to_string();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        "content-type",
        http::HeaderValue::from_static("application/json"),
    );
    response
}
