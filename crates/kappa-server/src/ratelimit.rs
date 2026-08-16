//! Tiered per-IP rate limiting with GCRA token buckets.
//!
//! Three operation classes (Read, Write, Admin) each with independent
//! GCRA token buckets per client IP. Health and version endpoints are
//! Exempt. Configuration is per-class via environment variables parsed
//! by config::Config.
//!
//! Response headers (x-ratelimit-limit, x-ratelimit-remaining,
//! retry-after) expose bucket state so clients can self-throttle.
//!
//! IP extraction priority: X-Forwarded-For first entry, X-Real-IP,
//! Forwarded (RFC 7239) for= directive, fallback to 127.0.0.1.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use governor::clock::DefaultClock;
use governor::middleware::StateInformationMiddleware;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};

use http::header::HeaderValue;
use topcoat::router::response::Response;
use topcoat::router::{Body, StatusCode};

use crate::config::{ClassConfig, RateLimitConfig};

type KeyedLimiter =
    RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock, StateInformationMiddleware>;

/// Operation class for rate limiting. Every request is classified into
/// one of these before the rate limit check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpClass {
    /// Exempt from all rate limiting (health probes, version check, status).
    Exempt,
    /// Read operations: GET/HEAD on content, metadata, listings.
    Read,
    /// Write operations: PUT/POST/PATCH on content, manifests, edges.
    Write,
    /// Administrative operations: DELETE, GC, transactions, reconcile, cascade.
    Admin,
}

/// Result of a rate limit check on a successful (non-rejected) request.
/// Carried through to attach headers to the response.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitSnapshot {
    pub limit: u32,
    pub remaining: u32,
}

/// Holds one GCRA bucket per operation class. Each bucket is keyed by
/// client IP so different clients have independent quotas.
#[derive(Clone)]
pub struct TieredRateLimiter {
    read: Option<Arc<KeyedLimiter>>,
    write: Option<Arc<KeyedLimiter>>,
    admin: Option<Arc<KeyedLimiter>>,
    config: RateLimitConfig,
}

impl TieredRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Self {
        Self {
            read: build_limiter(&config.read),
            write: build_limiter(&config.write),
            admin: build_limiter(&config.admin),
            config: config.clone(),
        }
    }

    /// Check the request against the bucket for `class` and `ip`.
    ///
    /// Returns Ok(Some(snapshot)) if allowed with rate limit state,
    /// Ok(None) if exempt (no headers to attach),
    /// Err(response) if rate limited (429 response ready to send).
    pub fn check(
        &self,
        ip: IpAddr,
        class: OpClass,
    ) -> Result<Option<RateLimitSnapshot>, Box<Response>> {
        let (limiter, class_config) = match class {
            OpClass::Exempt => return Ok(None),
            OpClass::Read => (&self.read, &self.config.read),
            OpClass::Write => (&self.write, &self.config.write),
            OpClass::Admin => (&self.admin, &self.config.admin),
        };
        let limiter = match limiter {
            Some(l) => l,
            None => return Ok(None),
        };
        match limiter.check_key(&ip) {
            Ok(snapshot) => Ok(Some(RateLimitSnapshot {
                limit: class_config.burst,
                remaining: snapshot.remaining_burst_capacity(),
            })),
            Err(negative) => {
                let wait_time = negative
                    .wait_time_from(governor::clock::Clock::now(&DefaultClock::default()))
                    .as_secs();
                Err(Box::new(build_429_response(wait_time, class_config.burst)))
            }
        }
    }
}

/// Attach rate limit headers to a successful response.
pub fn attach_headers(response: &mut Response, snapshot: &RateLimitSnapshot) {
    let headers = response.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&snapshot.limit.to_string()) {
        headers.insert("x-ratelimit-limit", v);
    }
    if let Ok(v) = HeaderValue::from_str(&snapshot.remaining.to_string()) {
        headers.insert("x-ratelimit-remaining", v);
    }
}

/// Build a 429 Too Many Requests response with rate limit headers.
fn build_429_response(wait_time: u64, burst: u32) -> Response {
    let body_str = format!("Too Many Requests! Wait for {wait_time}s");
    let mut resp = Response::new(Body::from(body_str));
    *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    let h = resp.headers_mut();
    h.insert("retry-after", HeaderValue::from(wait_time));
    h.insert("x-ratelimit-after", HeaderValue::from(wait_time));
    h.insert("x-ratelimit-limit", HeaderValue::from(burst));
    h.insert("x-ratelimit-remaining", HeaderValue::from(0u32));
    resp
}

/// Build a governor rate limiter from a ClassConfig.
/// Returns None if rate limiting is disabled for this class (period_ms == 0).
fn build_limiter(config: &ClassConfig) -> Option<Arc<KeyedLimiter>> {
    if config.period_ms == 0 || config.burst == 0 {
        return None;
    }
    let quota = Quota::with_period(Duration::from_millis(config.period_ms))
        .expect("period must be non-zero")
        .allow_burst(NonZeroU32::new(config.burst).expect("burst must be non-zero"));
    Some(Arc::new(
        RateLimiter::keyed(quota).with_middleware::<StateInformationMiddleware>(),
    ))
}

/// Extract the client IP address from request headers.
///
/// Priority:
/// 1. X-Forwarded-For: first valid IP in the comma-separated list
/// 2. X-Real-IP: single IP
/// 3. Forwarded: RFC 7239 for= directive
/// 4. Fallback to 127.0.0.1
pub fn extract_client_ip(headers: &topcoat::router::HeaderMap) -> IpAddr {
    // X-Forwarded-For: first valid IP in the comma-separated list
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(s) = xff.to_str() {
            if let Some(ip) = s.split(',').find_map(|s| s.trim().parse::<IpAddr>().ok()) {
                return ip;
            }
        }
    }

    // X-Real-IP
    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(s) = xri.to_str() {
            if let Ok(ip) = s.parse::<IpAddr>() {
                return ip;
            }
        }
    }

    // Forwarded header (RFC 7239)
    if let Some(fwd) = headers.get("forwarded") {
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

/// Classify an HTTP request into an OpClass based on method and path.
///
/// This is an exhaustive lookup covering every registered route.
/// Adding a route without a corresponding entry here defaults to
/// method-based classification (GET/HEAD=Read, PUT/POST/PATCH=Write,
/// DELETE=Admin).
pub fn classify_request(method: &str, path: &str) -> OpClass {
    // Exempt: version check, health probes, status
    if path == "/v2" || path == "/v2/" || path.starts_with("/v2/_health/") || path == "/_status" {
        return OpClass::Exempt;
    }

    // Admin paths (POST/DELETE that are administrative, not content writes)
    if path.contains("/gc/pin") || path.contains("/gc/unpin") || path.contains("/gc/sweep") {
        return OpClass::Admin;
    }
    if path.contains("/_transaction/begin")
        || path.ends_with("/commit")
        || (path.contains("/_transaction/") && method == "DELETE")
    {
        return OpClass::Admin;
    }
    if path.contains("/_reconcile") {
        return OpClass::Admin;
    }
    if path.contains("/blobs/_cascade") {
        return OpClass::Admin;
    }
    if path.contains("/tags/_prefix") {
        return OpClass::Admin;
    }

    // DELETE is always Admin
    if method == "DELETE" {
        return OpClass::Admin;
    }

    // Read: GET, HEAD
    if matches!(method, "GET" | "HEAD") {
        return OpClass::Read;
    }

    // Write: PUT, POST, PATCH (covers blob put, manifest put, tag put,
    // tag batch, edge put, schema put, filter put, upload start/chunk/complete,
    // bundle ingest, compose, sequence next)
    OpClass::Write
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(burst: u32) -> RateLimitConfig {
        RateLimitConfig {
            read: ClassConfig {
                period_ms: 1000,
                burst,
            },
            write: ClassConfig {
                period_ms: 1000,
                burst,
            },
            admin: ClassConfig {
                period_ms: 1000,
                burst,
            },
        }
    }

    #[test]
    fn allows_within_burst() {
        let limiter = TieredRateLimiter::new(&test_config(3));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..3 {
            assert!(limiter.check(ip, OpClass::Read).is_ok());
        }
        assert!(limiter.check(ip, OpClass::Read).is_err(), "4th rejected");
    }

    #[test]
    fn exempt_always_passes() {
        let limiter = TieredRateLimiter::new(&test_config(1));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..100 {
            assert!(limiter.check(ip, OpClass::Exempt).is_ok());
        }
    }

    #[test]
    fn classes_independent() {
        let limiter = TieredRateLimiter::new(&test_config(2));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(limiter.check(ip, OpClass::Read).is_ok());
        assert!(limiter.check(ip, OpClass::Read).is_ok());
        assert!(limiter.check(ip, OpClass::Read).is_err());
        assert!(limiter.check(ip, OpClass::Write).is_ok());
        assert!(limiter.check(ip, OpClass::Write).is_ok());
        assert!(limiter.check(ip, OpClass::Write).is_err());
    }

    #[test]
    fn per_ip_isolation() {
        let limiter = TieredRateLimiter::new(&test_config(2));
        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();
        assert!(limiter.check(ip1, OpClass::Read).is_ok());
        assert!(limiter.check(ip1, OpClass::Read).is_ok());
        assert!(limiter.check(ip1, OpClass::Read).is_err());
        assert!(limiter.check(ip2, OpClass::Read).is_ok());
    }

    #[test]
    fn disabled_config_passes_all() {
        let disabled = RateLimitConfig {
            read: ClassConfig {
                period_ms: 0,
                burst: 0,
            },
            write: ClassConfig {
                period_ms: 0,
                burst: 0,
            },
            admin: ClassConfig {
                period_ms: 0,
                burst: 0,
            },
        };
        let limiter = TieredRateLimiter::new(&disabled);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        for _ in 0..1000 {
            assert!(limiter.check(ip, OpClass::Read).is_ok());
            assert!(limiter.check(ip, OpClass::Write).is_ok());
            assert!(limiter.check(ip, OpClass::Admin).is_ok());
        }
    }

    #[test]
    fn snapshot_values_correct() {
        let limiter = TieredRateLimiter::new(&test_config(5));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let snap = limiter.check(ip, OpClass::Read).unwrap().unwrap();
        assert_eq!(snap.limit, 5);
        assert_eq!(snap.remaining, 4);
    }

    #[test]
    fn rejected_response_has_headers() {
        let limiter = TieredRateLimiter::new(&test_config(1));
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        let _ = limiter.check(ip, OpClass::Read);
        let err = *limiter.check(ip, OpClass::Read).unwrap_err();
        assert_eq!(err.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(err.headers().get("retry-after").is_some());
        assert!(err.headers().get("x-ratelimit-limit").is_some());
        assert_eq!(err.headers().get("x-ratelimit-remaining").unwrap(), "0");
    }

    #[test]
    fn partial_class_config() {
        let config = RateLimitConfig {
            read: ClassConfig {
                period_ms: 1000,
                burst: 2,
            },
            write: ClassConfig {
                period_ms: 0,
                burst: 0,
            },
            admin: ClassConfig {
                period_ms: 0,
                burst: 0,
            },
        };
        assert!(config.is_enabled());
        let limiter = TieredRateLimiter::new(&config);
        let ip: IpAddr = "127.0.0.1".parse().unwrap();
        assert!(limiter.check(ip, OpClass::Read).is_ok());
        assert!(limiter.check(ip, OpClass::Read).is_ok());
        assert!(limiter.check(ip, OpClass::Read).is_err());
        for _ in 0..100 {
            assert!(limiter.check(ip, OpClass::Write).is_ok());
        }
    }

    // -- classify_request tests --

    #[test]
    fn classify_version_exempt() {
        assert_eq!(classify_request("GET", "/v2/"), OpClass::Exempt);
        assert_eq!(classify_request("GET", "/v2"), OpClass::Exempt);
    }

    #[test]
    fn classify_health_exempt() {
        assert_eq!(classify_request("GET", "/v2/_health/live"), OpClass::Exempt);
        assert_eq!(
            classify_request("GET", "/v2/_health/ready"),
            OpClass::Exempt
        );
    }

    #[test]
    fn classify_status_exempt() {
        assert_eq!(classify_request("GET", "/_status"), OpClass::Exempt);
    }

    #[test]
    fn classify_blob_get_read() {
        assert_eq!(
            classify_request("GET", "/v2/ns/blobs/sha256:abc"),
            OpClass::Read
        );
    }

    #[test]
    fn classify_blob_head_read() {
        assert_eq!(
            classify_request("HEAD", "/v2/ns/blobs/sha256:abc"),
            OpClass::Read
        );
    }

    #[test]
    fn classify_blob_put_write() {
        assert_eq!(
            classify_request("PUT", "/v2/ns/blobs/sha256:abc"),
            OpClass::Write
        );
    }

    #[test]
    fn classify_blob_delete_admin() {
        assert_eq!(
            classify_request("DELETE", "/v2/ns/blobs/sha256:abc"),
            OpClass::Admin
        );
    }

    #[test]
    fn classify_gc_sweep_admin() {
        assert_eq!(classify_request("POST", "/v2/ns/gc/sweep"), OpClass::Admin);
    }

    #[test]
    fn classify_gc_pin_admin() {
        assert_eq!(classify_request("POST", "/v2/ns/gc/pin"), OpClass::Admin);
    }

    #[test]
    fn classify_transaction_begin_admin() {
        assert_eq!(
            classify_request("POST", "/v2/ns/_transaction/begin"),
            OpClass::Admin
        );
    }

    #[test]
    fn classify_transaction_commit_admin() {
        assert_eq!(
            classify_request("POST", "/v2/ns/_transaction/abc/commit"),
            OpClass::Admin
        );
    }

    #[test]
    fn classify_reconcile_admin() {
        assert_eq!(
            classify_request("POST", "/v2/ns/_reconcile"),
            OpClass::Admin
        );
    }

    #[test]
    fn classify_cascade_admin() {
        assert_eq!(
            classify_request("POST", "/v2/ns/blobs/_cascade"),
            OpClass::Admin
        );
    }

    #[test]
    fn classify_tag_prefix_delete_admin() {
        assert_eq!(
            classify_request("DELETE", "/v2/ns/tags/_prefix"),
            OpClass::Admin
        );
    }

    #[test]
    fn classify_manifest_put_write() {
        assert_eq!(
            classify_request("PUT", "/v2/ns/manifests/latest"),
            OpClass::Write
        );
    }

    #[test]
    fn classify_upload_post_write() {
        assert_eq!(
            classify_request("POST", "/v2/ns/blobs/uploads/"),
            OpClass::Write
        );
    }

    #[test]
    fn classify_edge_put_write() {
        assert_eq!(classify_request("PUT", "/v2/ns/edges/"), OpClass::Write);
    }

    #[test]
    fn classify_tag_list_read() {
        assert_eq!(classify_request("GET", "/v2/ns/tags/list"), OpClass::Read);
    }
}
