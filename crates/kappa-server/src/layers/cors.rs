//! CORS handling. OPTIONS preflight bypasses auth/ratelimit.
//! Actual requests get Access-Control-Allow-Origin and Expose-Headers.
//!
//! `/passkey/` and the Prism mailbox `/prism/` have their own policy
//! (prism/identity/1 and /3): reads are public with `*`, and writes are
//! allowed only from the configured identity origins, so no other page can
//! drive a registration, a revocation or a mailbox post from a browser.

use http::HeaderValue;
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

const PASSKEY_METHODS: &str = "GET, HEAD, POST, OPTIONS";
const PASSKEY_HEADERS: &str = "Content-Type";
const PASSKEY_EXPOSE: &str = "X-RateLimit-Limit, X-RateLimit-Remaining, Retry-After, X-Request-Id";

pub fn cors_layer<'a>(cx: &'a Cx, body: Body, next: Next<'a>) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let method = topcoat::router::request::method(cx).clone();
        let origin = topcoat::router::request::headers(cx).get("origin").cloned();

        let path = topcoat::router::request::uri(cx).path();
        if path.starts_with("/passkey/") || path.starts_with("/prism/") {
            return passkey_cors(cx, body, next, method, origin).await;
        }

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

/// True when `origin` is an identity origin the passkey routes accept.
fn identity_origin(cx: &Cx, origin: &HeaderValue) -> bool {
    #[cfg(feature = "passkey")]
    {
        let state = topcoat::context::try_app_context::<
            std::sync::Arc<kappa_module_passkey::PasskeyState>,
        >(cx);
        match (state, origin.to_str()) {
            (Some(state), Ok(origin)) => state.config.allows(origin),
            _ => false,
        }
    }
    // Without the passkey module no origin is an identity origin; the
    // parameters exist only for the feature-enabled build.
    #[cfg(not(feature = "passkey"))]
    {
        let _ = (cx, origin);
        false
    }
}

async fn passkey_cors<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
    method: Method,
    origin: Option<HeaderValue>,
) -> topcoat::Result<Response> {
    let browser = origin.is_some();
    let allowed = origin.filter(|o| identity_origin(cx, o));
    let read = method == Method::GET || method == Method::HEAD;

    let mut response = if method == Method::POST && browser && allowed.is_none() {
        // The router's cross-origin check is lifted for /passkey/ so the
        // identity page can write; every other browser origin is refused
        // here. Clients without an Origin header carry no ambient
        // credentials and pass, as they do through the router's check.
        let mut response = Response::new(Body::from(
            r#"{"error":"origin","message":"only an identity origin may write identity records from a browser"}"#,
        ));
        *response.status_mut() = StatusCode::FORBIDDEN;
        response
            .headers_mut()
            .insert("content-type", HeaderValue::from_static("application/json"));
        response
    } else if method == Method::OPTIONS {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        if allowed.is_some() {
            let h = response.headers_mut();
            h.insert(
                "access-control-allow-methods",
                PASSKEY_METHODS.parse().unwrap(),
            );
            h.insert(
                "access-control-allow-headers",
                PASSKEY_HEADERS.parse().unwrap(),
            );
            h.insert("access-control-max-age", "86400".parse().unwrap());
        }
        response
    } else {
        next.run(cx, body).await?
    };

    let h = response.headers_mut();
    if read {
        h.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    } else if let Some(origin) = allowed {
        h.insert("access-control-allow-origin", origin);
    }
    h.insert("vary", HeaderValue::from_static("Origin"));
    h.insert(
        "access-control-expose-headers",
        PASSKEY_EXPOSE.parse().unwrap(),
    );
    Ok(response)
}
