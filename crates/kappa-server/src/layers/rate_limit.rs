//! Rate limiting layer. Thin wrapper around TieredRateLimiter.
//! Reads ClientIp from context (set by proxy_trust layer).

use std::sync::Arc;

use topcoat::context::{try_app_context, CxBuilder};
use topcoat::router::{Body, Next, Response};

use super::proxy_trust::ClientIp;
use crate::ratelimit::{attach_headers, classify_request, TieredRateLimiter};

pub fn rate_limit_layer<'a>(
    cx: &'a mut CxBuilder,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let snapshot = if let Some(limiter) = try_app_context::<Arc<TieredRateLimiter>>(cx) {
            let ip = try_app_context::<ClientIp>(cx)
                .map(|c| c.0)
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            let uri_path = topcoat::router::uri(cx).path();
            let method = topcoat::router::method(cx);
            let op_class = classify_request(method.as_str(), uri_path);
            match limiter.check(ip, op_class) {
                Ok(snap) => snap,
                Err(rejection) => {
                    return Ok(*rejection);
                }
            }
        } else {
            None
        };

        let mut response = match next.run(cx, body).await {
            Ok(r) => r,
            Err(e) => {
                let mut r = Response::new(Body::from(e.response_body()));
                *r.status_mut() = e.status_code();
                if let Some(ref snap) = snapshot {
                    attach_headers(&mut r, snap);
                }
                return Ok(r);
            }
        };

        if let Some(ref snap) = snapshot {
            attach_headers(&mut response, snap);
        }

        Ok(response)
    })
}
