//! CORS handling. OPTIONS preflight bypasses auth/ratelimit.
//! Actual requests get Access-Control-Allow-Origin and Expose-Headers.

use topcoat::context::Cx;
use topcoat::router::response::Response;
use topcoat::router::{Body, Method, Next, StatusCode};

const ALLOW_METHODS: &str = "GET, HEAD, PUT, POST, DELETE, PATCH, OPTIONS";

const ALLOW_HEADERS: &str = "Authorization, Content-Type, Content-Length, \
    Content-Range, Docker-Content-Digest, If-None-Match, Last-Event-ID, Range";

const EXPOSE_HEADERS: &str = "Docker-Content-Digest, WWW-Authenticate, Link, \
    Location, Range, X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After, \
    OCI-Chunk-Min-Length, OCI-Subject, OCI-Tag, Warning, ETag, X-Request-Id, \
    Accept-Ranges, X-Kappa-Label, X-Kappa-Axis";

pub fn cors_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let method = topcoat::router::request::method(cx).clone();
        let origin = topcoat::router::request::headers(cx).get("origin").cloned();

        if method == Method::OPTIONS {
            let mut response = Response::new(Body::empty());
            *response.status_mut() = StatusCode::NO_CONTENT;
            if let Some(origin) = origin {
                let h = response.headers_mut();
                h.insert("access-control-allow-origin", origin);
                h.insert(
                    "access-control-allow-methods",
                    ALLOW_METHODS.parse().unwrap(),
                );
                h.insert(
                    "access-control-allow-headers",
                    ALLOW_HEADERS.parse().unwrap(),
                );
                h.insert("access-control-max-age", "86400".parse().unwrap());
                h.insert(
                    "access-control-expose-headers",
                    EXPOSE_HEADERS.parse().unwrap(),
                );
            }
            return Ok(response);
        }

        let mut response = next.run(cx, body).await?;
        if let Some(origin) = origin {
            let h = response.headers_mut();
            h.insert("access-control-allow-origin", origin);
            h.insert(
                "access-control-expose-headers",
                EXPOSE_HEADERS.parse().unwrap(),
            );
        }
        Ok(response)
    })
}
