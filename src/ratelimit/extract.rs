//! Client IP extraction for per-IP rate limiting.
//!
//! Priority: X-Forwarded-For, X-Real-IP, Forwarded, fallback to localhost.

use std::net::IpAddr;

use topcoat::context::Cx;
use topcoat::router::headers;

/// Extract the client IP address from the request context.
pub fn extract_ip(cx: &Cx) -> IpAddr {
    let hdrs = headers(cx);

    // X-Forwarded-For: first valid IP in the comma-separated list
    if let Some(xff) = hdrs.get("x-forwarded-for") {
        if let Ok(s) = xff.to_str() {
            if let Some(ip) = s.split(',').find_map(|s| s.trim().parse::<IpAddr>().ok()) {
                return ip;
            }
        }
    }

    // X-Real-IP
    if let Some(xri) = hdrs.get("x-real-ip") {
        if let Ok(s) = xri.to_str() {
            if let Ok(ip) = s.parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // Forwarded header (RFC 7239)
    if let Some(fwd) = hdrs.get("forwarded") {
        if let Ok(s) = fwd.to_str() {
            for part in s.split(';') {
                let part = part.trim();
                if let Some(addr) = part.strip_prefix("for=") {
                    let addr = addr.trim_matches('"').trim_matches('[').trim_matches(']');
                    if let Ok(ip) = addr.parse::<IpAddr>() {
                        return ip;
                    }
                    if let Ok(sa) = addr.parse::<std::net::SocketAddr>() {
                        return sa.ip();
                    }
                }
            }
        }
    }

    std::net::Ipv4Addr::LOCALHOST.into()
}
