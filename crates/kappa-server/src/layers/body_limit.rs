//! Request body size enforcement.
//!
//! Two independent limits:
//! - Blob upload paths (/blobs/, /_uploads/): bounded by MaxBlobSize
//! - All other paths (JSON API): bounded by MaxApiBodyBytes
//!
//! Both configurable via environment variables. Checks Content-Length
//! header. Returns 413 with OCI error envelope if exceeded.

use topcoat::context::{try_app_context, CxBuilder};
use topcoat::router::{Body, Next, Response, StatusCode};

use kappa_core::types::MaxBlobSize;

/// Maximum request body for non-blob API endpoints.
#[derive(Clone)]
pub struct MaxApiBodyBytes(pub usize);

fn is_blob_path(path: &str) -> bool {
    path.contains("/blobs/") || path.contains("/_uploads/") || path.starts_with("/_nix/nar/")
}

pub fn body_limit_layer<'a>(
    cx: &'a mut CxBuilder,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let path = topcoat::router::uri(cx).path().to_owned();
        let is_blob = is_blob_path(&path);

        let limit = if is_blob {
            try_app_context::<MaxBlobSize>(cx).map(|m| m.0)
        } else {
            try_app_context::<MaxApiBodyBytes>(cx).map(|m| m.0)
        };

        tracing::debug!(
            path = %path,
            is_blob = is_blob,
            limit = ?limit,
            "body_limit_layer check"
        );

        if let Some(max) = limit {
            if let Some(cl) = topcoat::router::headers(cx)
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<usize>().ok())
            {
                tracing::debug!(
                    content_length = cl,
                    max = max,
                    rejected = cl > max,
                    "body_limit_layer content-length check"
                );
                if cl > max {
                    let code = if is_blob_path(&path) {
                        "SIZE_EXCEEDED"
                    } else {
                        "SIZE_INVALID"
                    };
                    let body_str = format!(
                        r#"{{"errors":[{{"code":"{code}","message":"request body {} bytes exceeds limit {}"}}]}}"#,
                        cl, max
                    );
                    let mut response = Response::new(Body::from(body_str));
                    *response.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
                    response
                        .headers_mut()
                        .insert("content-type", "application/json".parse().unwrap());
                    return Ok(response);
                }
            }
        }
        next.run(cx, body).await
    })
}
