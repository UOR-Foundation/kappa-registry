//! The request's one deadline. The whole request, every phase of it, is
//! bounded by the configured timeout: the layer publishes the deadline
//! into the request context (`RequestDeadline`), which every preparation
//! and execution of the request honours (`kappa_handler::request_deadline`),
//! and answers with a timeout when the handler outlives it.

use std::time::{Duration, Instant};

use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, Next, StatusCode};

use kappa_handler::RequestDeadline;

#[derive(Clone)]
pub struct RequestTimeout(pub Duration);

pub fn timeout_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let timeout = kappa_handler::try_service::<RequestTimeout>(cx)
            .map(|t| t.0)
            .unwrap_or(Duration::from_secs(300));
        let cx = cx.with(RequestDeadline(Instant::now() + timeout));

        match tokio::time::timeout(timeout, next.run(&cx, body)).await {
            Ok(result) => result,
            Err(_elapsed) => {
                let body_str =
                    r#"{"errors":[{"code":"TIMEOUT","message":"request timeout exceeded"}]}"#;
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
