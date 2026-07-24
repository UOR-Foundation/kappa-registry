//! GCRA token bucket limiter with per-class, per-IP buckets.

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use governor::clock::DefaultClock;
use governor::middleware::StateInformationMiddleware;
use governor::state::keyed::DefaultKeyedStateStore;
use governor::{Quota, RateLimiter};
use http::header::HeaderValue;
use http::{Response, StatusCode};

use super::OpClass;

type KeyedLimiter =
    RateLimiter<IpAddr, DefaultKeyedStateStore<IpAddr>, DefaultClock, StateInformationMiddleware>;

/// Per-class rate limit parameters.
#[derive(Debug, Clone)]
pub struct ClassConfig {
    /// Token refill interval in milliseconds. 0 = no limit for this class.
    pub period_ms: u64,
    /// Maximum burst capacity.
    pub burst: u32,
}

/// Tiered rate limit configuration.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub read: ClassConfig,
    pub write: ClassConfig,
    pub admin: ClassConfig,
}

impl RateLimitConfig {
    pub fn disabled() -> Self {
        Self {
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
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.read.period_ms > 0 || self.write.period_ms > 0 || self.admin.period_ms > 0
    }
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

/// Result of a rate limit check on a successful (non-rejected) request.
/// Carried through dispatch to attach headers to the response.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitSnapshot {
    pub limit: u32,
    pub remaining: u32,
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
    /// Returns `Ok(snapshot)` if allowed -- the snapshot contains the
    /// bucket state for response headers.
    /// Returns `Err(response)` with a complete 429 response if rejected.
    pub fn check(
        &self,
        ip: IpAddr,
        class: OpClass,
    ) -> Result<Option<RateLimitSnapshot>, Box<Response<Body>>> {
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
pub fn attach_headers(response: &mut Response<Body>, snapshot: &RateLimitSnapshot) {
    let headers = response.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&snapshot.limit.to_string()) {
        headers.insert("x-ratelimit-limit", v);
    }
    if let Ok(v) = HeaderValue::from_str(&snapshot.remaining.to_string()) {
        headers.insert("x-ratelimit-remaining", v);
    }
}

fn build_429_response(wait_time: u64, burst: u32) -> Response<Body> {
    let body = format!("Too Many Requests! Wait for {wait_time}s");
    let mut resp = Response::new(Body::from(body));
    *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    let h = resp.headers_mut();
    h.insert("retry-after", HeaderValue::from(wait_time));
    h.insert("x-ratelimit-after", HeaderValue::from(wait_time));
    h.insert("x-ratelimit-limit", HeaderValue::from(burst));
    h.insert("x-ratelimit-remaining", HeaderValue::from(0u32));
    resp
}

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
        // Exhaust read
        assert!(limiter.check(ip, OpClass::Read).is_ok());
        assert!(limiter.check(ip, OpClass::Read).is_ok());
        assert!(limiter.check(ip, OpClass::Read).is_err());
        // Write still has capacity
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
        // ip2 unaffected
        assert!(limiter.check(ip2, OpClass::Read).is_ok());
    }

    #[test]
    fn disabled_config_passes_all() {
        let limiter = TieredRateLimiter::new(&RateLimitConfig::disabled());
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
        let _ = limiter.check(ip, OpClass::Read); // consume the 1 token
        let err = *limiter.check(ip, OpClass::Read).unwrap_err();
        assert_eq!(err.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(err.headers().get("retry-after").is_some());
        assert!(err.headers().get("x-ratelimit-limit").is_some());
        assert_eq!(err.headers().get("x-ratelimit-remaining").unwrap(), "0");
    }

    #[test]
    fn partial_class_config() {
        // Only read is limited
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
        // Read limited
        assert!(limiter.check(ip, OpClass::Read).is_ok());
        assert!(limiter.check(ip, OpClass::Read).is_ok());
        assert!(limiter.check(ip, OpClass::Read).is_err());
        // Write unlimited
        for _ in 0..100 {
            assert!(limiter.check(ip, OpClass::Write).is_ok());
        }
    }
}
