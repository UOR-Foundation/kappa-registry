//! Tiered per-IP rate limiting.
//!
//! Three operation classes (Read, Write, Admin) each with independent
//! GCRA token buckets per client IP. Health and version endpoints are
//! Exempt. Configuration is per-class via environment variables.
//! Response headers (`x-ratelimit-limit`, `x-ratelimit-remaining`,
//! `retry-after`) expose bucket state so clients can self-throttle.

mod extract;
pub mod limiter;

pub use extract::extract_ip;
pub use limiter::{ClassConfig, RateLimitConfig, TieredRateLimiter};

/// Operation class for rate limiting. Derived per-endpoint via the
/// `#[derive(ClassifyEndpoint)]` proc macro with `#[op_class(...)]`
/// annotations on each `Endpoint` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpClass {
    /// Exempt from all rate limiting (health probes, version check).
    Exempt,
    /// Read operations: GET/HEAD on content, metadata, listings.
    Read,
    /// Write operations: PUT/POST/PATCH on content, manifests, edges.
    Write,
    /// Administrative operations: DELETE, GC, transactions, reconcile.
    Admin,
}
