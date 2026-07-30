//! Per-request timeout. 504 Gateway Timeout with OCI error envelope.

use std::time::Duration;

use topcoat::context::{try_app_context, CxBuilder};
use topcoat::router::{Body, Next, Response, StatusCode};

#[derive(Clone)]
pub struct RequestTimeout(pub Duration);

pub fn timeout_layer<'a>(
    cx: &'a mut CxBuilder,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let deadline = try_app_context::<RequestTimeout>(cx)
            .map(|t| t.0)
            .unwrap_or(Duration::from_secs(300));

        match tokio::time::timeout(deadline, next.run(cx, body)).await {
            Ok(result) => result,
            Err(_elapsed) => {
                let body_str = r#"{"errors":[{"code":"TIMEOUT","message":"request timeout exceeded"}]}"#;
                let mut response = Response::new(Body::from(body_str));
                *response.status_mut() = StatusCode::GATEWAY_TIMEOUT;
                response
                    .headers_mut()
                    .insert("content-type", "application/json".parse().unwrap());
                Ok(response)
            }
        }
    })
}
