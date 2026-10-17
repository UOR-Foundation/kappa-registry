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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpClass {
    Exempt,
    Read,
    Write,
    Admin,
}

impl OpClass {
    pub fn is_write(&self) -> bool {
        matches!(self, Self::Write | Self::Admin)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitSnapshot {
    pub limit: u32,
    pub remaining: u32,
}

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
        let Some(limiter) = limiter else {
            return Ok(None);
        };
        match limiter.check_key(&ip) {
            Ok(snapshot) => Ok(Some(RateLimitSnapshot {
                limit: class_config.burst,
                remaining: snapshot.remaining_burst_capacity(),
            })),
            Err(negative) => {
                let wait = negative
                    .wait_time_from(governor::clock::Clock::now(&DefaultClock::default()))
                    .as_secs();
                Err(Box::new(build_429(wait, class_config.burst)))
            }
        }
    }
}

pub fn attach_headers(response: &mut Response, snapshot: &RateLimitSnapshot) {
    let h = response.headers_mut();
    if let Ok(v) = HeaderValue::from_str(&snapshot.limit.to_string()) {
        h.insert("x-ratelimit-limit", v);
    }
    if let Ok(v) = HeaderValue::from_str(&snapshot.remaining.to_string()) {
        h.insert("x-ratelimit-remaining", v);
    }
}

fn build_429(wait: u64, burst: u32) -> Response {
    let mut resp = Response::new(Body::from(format!("Too Many Requests. Wait {wait}s")));
    *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    let h = resp.headers_mut();
    h.insert("retry-after", HeaderValue::from(wait));
    h.insert("x-ratelimit-limit", HeaderValue::from(burst));
    h.insert("x-ratelimit-remaining", HeaderValue::from(0u32));
    resp
}

fn build_limiter(config: &ClassConfig) -> Option<Arc<KeyedLimiter>> {
    if config.period_ms == 0 || config.burst == 0 {
        return None;
    }
    let burst = NonZeroU32::new(config.burst)?;
    let quota = Quota::with_period(Duration::from_millis(config.period_ms))?.allow_burst(burst);
    Some(Arc::new(
        RateLimiter::keyed(quota).with_middleware::<StateInformationMiddleware>(),
    ))
}

pub fn classify_request(method: &str, path: &str) -> OpClass {
    if path == "/v2" || path == "/v2/" || path.starts_with("/v2/_health/") || path == "/_status" {
        return OpClass::Exempt;
    }
    if path.contains("/gc/pin") || path.contains("/gc/unpin") || path.contains("/gc/sweep") {
        return OpClass::Admin;
    }
    if path == crate::detect::NODE_ROTATE_PATH {
        return OpClass::Admin;
    }
    if path.contains("/_transaction/begin")
        || path.ends_with("/commit")
        || (path.contains("/_transaction/") && method == "DELETE")
    {
        return OpClass::Admin;
    }
    if path.contains("/_reconcile")
        || path.contains("/blobs/_cascade")
        || path.contains("/tags/_prefix")
    {
        return OpClass::Admin;
    }
    if method == "DELETE" {
        return OpClass::Admin;
    }
    if matches!(method, "GET" | "HEAD") {
        return OpClass::Read;
    }
    OpClass::Write
}
