//! Client IP canonicalization from proxy headers or TCP peer.
//! All downstream layers read ClientIp from context instead of
//! parsing headers independently.

use std::net::IpAddr;

use topcoat::context::{try_app_context, Cx};
use topcoat::router::{Body, Next};

#[derive(Clone, Debug)]
pub struct ClientIp(pub IpAddr);

#[derive(Clone, Debug)]
pub struct ProxyTrustConfig {
    pub trusted_header: Option<String>,
}

pub fn proxy_trust_layer<'a>(
    cx: &'a Cx,
    body: Body,
    next: Next<'a>,
) -> topcoat::router::LayerFuture<'a> {
    Box::pin(async move {
        let config = try_app_context::<ProxyTrustConfig>(cx);
        let hdrs = topcoat::router::request::headers(cx);

        let ip = match config.and_then(|c| c.trusted_header.as_deref()) {
            Some("x-forwarded-for") => hdrs
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| {
                    s.split(',')
                        .next()
                        .and_then(|s| s.trim().parse::<IpAddr>().ok())
                })
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            Some("x-real-ip") => hdrs
                .get("x-real-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<IpAddr>().ok())
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            Some("forwarded") => hdrs
                .get("forwarded")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| {
                    for part in s.split(';') {
                        if let Some(addr) = part.trim().strip_prefix("for=") {
                            let addr = addr.trim_matches('"').trim_matches('[').trim_matches(']');
                            if let Ok(ip) = addr.parse::<IpAddr>() {
                                return Some(ip);
                            }
                            if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
                                return Some(sa.ip());
                            }
                        }
                    }
                    None
                })
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
            _ => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        };

        let cx = cx.with(ClientIp(ip));
        next.run(&cx, body).await
    })
}
