use topcoat::context::{Cx, try_request_context};
use topcoat::router::response::Response;
use topcoat::router::{Body, Next};

use super::proxy_trust::ClientIp;
use crate::ratelimit::{TieredRateLimiter, attach_headers, classify_request};

pub fn rate_limit_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let snapshot = if let Some(limiter) = kappa_handler::try_service::<TieredRateLimiter>(cx) {
            let ip = try_request_context::<ClientIp>(cx)
                .map(|c| c.0)
                .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            let path = topcoat::router::request::uri(cx).path();
            let method = topcoat::router::request::method(cx);
            let op = classify_request(method.as_str(), path);
            match limiter.check(ip, op) {
                Ok(snap) => snap,
                Err(rejection) => return Ok(*rejection),
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
