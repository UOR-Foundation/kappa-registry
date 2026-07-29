//! Server configuration from environment variables.
//!
//! Every configurable value has an env var, a default, and a parse error
//! that exits the process with a message. No silent fallbacks to wrong
//! values -- if the env var is set but unparseable, the server refuses
//! to start rather than running with an unintended configuration.
//!
//! Environment variables:
//!   KAPPA_LISTEN_ADDR           host:port (default 127.0.0.1:5000, OCI convention)
//!   KAPPA_STORE_ROOT            blob/tag/epoch storage root (default ./data)
//!   KAPPA_MAX_BLOB_SIZE         max bytes per blob PUT (default 256 MiB)
//!   KAPPA_UPLOAD_TIMEOUT        chunked upload session TTL in seconds (default 3600)
//!   KAPPA_SIGNING_ALGORITHM     node signing key algorithm (default ed25519)
//!   KAPPA_MAX_TRANSACTIONS      max concurrent transactions (default 64)
//!   KAPPA_MAX_STAGING_BYTES     global transaction staging limit (default 256 MiB)
//!   KAPPA_RATELIMIT_READ_PERIOD_MS    GCRA token interval for reads (default 0 = disabled)
//!   KAPPA_RATELIMIT_READ_BURST        GCRA burst capacity for reads (default 1000)
//!   KAPPA_RATELIMIT_WRITE_PERIOD_MS   GCRA token interval for writes (default 0 = disabled)
//!   KAPPA_RATELIMIT_WRITE_BURST       GCRA burst capacity for writes (default 200)
//!   KAPPA_RATELIMIT_ADMIN_PERIOD_MS   GCRA token interval for admin ops (default 0 = disabled)
//!   KAPPA_RATELIMIT_ADMIN_BURST       GCRA burst capacity for admin ops (default 50)

use std::net::SocketAddr;
use std::path::PathBuf;

/// Per-class rate limit parameters for the GCRA token bucket.
#[derive(Debug, Clone)]
pub struct ClassConfig {
    /// Token refill interval in milliseconds. 0 = no limit for this class.
    pub period_ms: u64,
    /// Maximum burst capacity (number of requests allowed in a burst
    /// before throttling begins).
    pub burst: u32,
}

/// Tiered rate limit configuration covering all three operation classes.
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub read: ClassConfig,
    pub write: ClassConfig,
    pub admin: ClassConfig,
}

impl RateLimitConfig {
    /// True if any class has rate limiting enabled (period_ms > 0).
    pub fn is_enabled(&self) -> bool {
        self.read.period_ms > 0 || self.write.period_ms > 0 || self.admin.period_ms > 0
    }
}

/// Complete server configuration parsed from environment variables.
pub struct Config {
    /// Listen address as host:port. Default 127.0.0.1:5000 (OCI convention).
    pub listen_addr: SocketAddr,
    /// Root directory for blob storage, tags, epochs, keys.
    pub store_root: PathBuf,
    /// Maximum content size for a single blob PUT. Requests exceeding
    /// this are rejected with 413. Default 256 MiB.
    pub max_blob_size: usize,
    /// Chunked upload session timeout in seconds. Sessions without
    /// activity beyond this TTL are reaped. Default 3600 (1 hour).
    pub upload_timeout_secs: u64,
    /// Node signing key algorithm. Default "ed25519".
    pub signing_algorithm: String,
    /// Maximum concurrent active transactions. Default 64.
    pub max_transactions: usize,
    /// Global byte limit across all active transaction staging areas.
    /// Default 256 MiB.
    pub max_staging_bytes: usize,
    /// Per-class rate limiting configuration.
    pub rate_limit: RateLimitConfig,
}

impl Config {
    /// Parse configuration from environment variables.
    ///
    /// Exits with a diagnostic message if any env var is set to an
    /// unparseable value. Missing env vars fall back to defaults.
    pub fn from_env() -> Self {
        let listen_addr: SocketAddr = env_or("KAPPA_LISTEN_ADDR", "127.0.0.1:5000")
            .parse()
            .unwrap_or_else(|e| config_exit(&format!("KAPPA_LISTEN_ADDR: {e}")));

        let store_root = PathBuf::from(env_or("KAPPA_STORE_ROOT", "./data"));

        let max_blob_size: usize = env_parse("KAPPA_MAX_BLOB_SIZE", 256 * 1024 * 1024);

        let upload_timeout_secs: u64 = env_parse("KAPPA_UPLOAD_TIMEOUT", 3600);

        let signing_algorithm = env_or("KAPPA_SIGNING_ALGORITHM", "ed25519");

        let max_transactions: usize = env_parse("KAPPA_MAX_TRANSACTIONS", 64);

        let max_staging_bytes: usize = env_parse("KAPPA_MAX_STAGING_BYTES", 256 * 1024 * 1024);

        let rate_limit = RateLimitConfig {
            read: ClassConfig {
                period_ms: env_parse("KAPPA_RATELIMIT_READ_PERIOD_MS", 0),
                burst: env_parse("KAPPA_RATELIMIT_READ_BURST", 1000),
            },
            write: ClassConfig {
                period_ms: env_parse("KAPPA_RATELIMIT_WRITE_PERIOD_MS", 0),
                burst: env_parse("KAPPA_RATELIMIT_WRITE_BURST", 200),
            },
            admin: ClassConfig {
                period_ms: env_parse("KAPPA_RATELIMIT_ADMIN_PERIOD_MS", 0),
                burst: env_parse("KAPPA_RATELIMIT_ADMIN_BURST", 50),
            },
        };

        Config {
            listen_addr,
            store_root,
            max_blob_size,
            upload_timeout_secs,
            signing_algorithm,
            max_transactions,
            max_staging_bytes,
            rate_limit,
        }
    }

    /// The host portion of listen_addr for topcoat HOST env var.
    pub fn listen_host(&self) -> String {
        self.listen_addr.ip().to_string()
    }

    /// The port portion of listen_addr for topcoat PORT env var.
    pub fn listen_port(&self) -> String {
        self.listen_addr.port().to_string()
    }
}

/// Read an env var with a fallback default.
fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

/// Read and parse an env var. If the var is set but unparseable, exit
/// with a diagnostic. If the var is unset, return the default.
fn env_parse<T: std::str::FromStr + std::fmt::Display>(key: &str, default: T) -> T
where
    T::Err: std::fmt::Display,
{
    match std::env::var(key) {
        Ok(val) => val
            .parse()
            .unwrap_or_else(|e| config_exit(&format!("{key}: {e}"))),
        Err(_) => default,
    }
}

/// Fatal configuration error. Prints message to stderr and exits.
#[cold]
#[inline(never)]
fn config_exit(msg: &str) -> ! {
    eprintln!("configuration error: {msg}");
    std::process::exit(2);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_or_returns_default() {
        // Use a var name that won't exist in any test environment
        let val = env_or("KAPPA_TEST_NONEXISTENT_VAR_XYZ", "fallback");
        assert_eq!(val, "fallback");
    }

    #[test]
    fn listen_host_and_port_split() {
        let cfg = Config {
            listen_addr: "10.0.0.1:8080".parse().unwrap(),
            store_root: PathBuf::from("/tmp"),
            max_blob_size: 1024,
            upload_timeout_secs: 60,
            signing_algorithm: "ed25519".into(),
            max_transactions: 4,
            max_staging_bytes: 4096,
            rate_limit: RateLimitConfig {
                read: ClassConfig {
                    period_ms: 0,
                    burst: 100,
                },
                write: ClassConfig {
                    period_ms: 0,
                    burst: 50,
                },
                admin: ClassConfig {
                    period_ms: 0,
                    burst: 10,
                },
            },
        };
        assert_eq!(cfg.listen_host(), "10.0.0.1");
        assert_eq!(cfg.listen_port(), "8080");
    }

    #[test]
    fn rate_limit_disabled_when_all_zero() {
        let rl = RateLimitConfig {
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
        assert!(!rl.is_enabled());
    }

    #[test]
    fn rate_limit_enabled_when_any_nonzero() {
        let rl = RateLimitConfig {
            read: ClassConfig {
                period_ms: 100,
                burst: 10,
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
        assert!(rl.is_enabled());
    }
}
