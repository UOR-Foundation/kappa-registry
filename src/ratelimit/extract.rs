//! Client IP extraction for per-IP rate limiting.
//!
//! Priority: X-Forwarded-For, X-Real-IP, Forwarded, ConnectInfo peer IP.
//! Same priority order as tower_governor's SmartIpKeyExtractor.

use axum::extract::ConnectInfo;
use http::Request;
use std::net::{IpAddr, SocketAddr};

/// Extract the client IP address from the request.
/// Returns None only if no IP source is available (should not happen
/// when the server is started with `into_make_service_with_connect_info`).
pub fn extract_ip<B>(req: &Request<B>) -> Option<IpAddr> {
    let headers = req.headers();

    // X-Forwarded-For: first valid IP in the comma-separated list
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(s) = xff.to_str() {
            if let Some(ip) = s.split(',').find_map(|s| s.trim().parse::<IpAddr>().ok()) {
                return Some(ip);
            }
        }
    }

    // X-Real-IP
    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(s) = xri.to_str() {
            if let Ok(ip) = s.parse::<IpAddr>() {
                return Some(ip);
            }
        }
    }

    // Forwarded header (RFC 7239)
    if let Some(fwd) = headers.get("forwarded") {
        if let Ok(s) = fwd.to_str() {
            // Parse "for=<ip>" directive
            for part in s.split(';') {
                let part = part.trim();
                if let Some(addr) = part.strip_prefix("for=") {
                    let addr = addr.trim_matches('"').trim_matches('[').trim_matches(']');
                    if let Ok(ip) = addr.parse::<IpAddr>() {
                        return Some(ip);
                    }
                    // Try as socket addr (ip:port)
                    if let Ok(sa) = addr.parse::<SocketAddr>() {
                        return Some(sa.ip());
                    }
                }
            }
        }
    }

    // ConnectInfo from axum
    if let Some(ci) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        return Some(ci.0.ip());
    }

    None
}
