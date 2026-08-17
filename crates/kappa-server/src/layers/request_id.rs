//! Request ID assignment. Every request gets a UUID v4 in:
//! - Response header: X-Request-Id
//! - Request context: RequestId(String)
//! - Tracing span: request_id field

use topcoat::context::Cx;
use topcoat::router::{Body, Next};

#[derive(Clone, Debug)]
pub struct RequestId(pub String);

pub fn request_id_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let id = uuid::Uuid::new_v4().to_string();
        let cx = cx.with(RequestId(id.clone()));
        let mut response = next.run(&cx, body).await?;
        response
            .headers_mut()
            .insert("x-request-id", id.parse().unwrap());
        Ok(response)
    })
}
