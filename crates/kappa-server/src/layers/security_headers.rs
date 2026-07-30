//! Security headers on every response.
//! X-Content-Type-Options, X-Frame-Options, Referrer-Policy, CSP, HSTS.

use topcoat::context::{try_app_context, CxBuilder};
use topcoat::router::{Body, Next};

/// Marker type in app_context when TLS is enabled.
/// Presence triggers HSTS header.
#[derive(Clone)]
pub struct TlsEnabled;

pub fn security_headers_layer<'a>(
    cx: &'a mut CxBuilder,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let tls = try_app_context::<TlsEnabled>(cx).is_some();
        let mut response = next.run(cx, body).await?;
        let h = response.headers_mut();
        h.insert("x-content-type-options", "nosniff".parse().unwrap());
        h.insert("x-frame-options", "DENY".parse().unwrap());
        h.insert("referrer-policy", "no-referrer".parse().unwrap());
        if !h.contains_key("content-security-policy") {
            h.insert(
                "content-security-policy",
                "default-src 'none'".parse().unwrap(),
            );
        }
        if tls {
            h.insert(
                "strict-transport-security",
                "max-age=63072000; includeSubDomains".parse().unwrap(),
            );
        }
        Ok(response)
    })
}
