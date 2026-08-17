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
    /// Whether fsync is called on blob writes. Default true.
    pub fsync: bool,
    /// Bearer token authentication tokens with identity anchors.
    /// Each entry is (token, anchor). Format: "token=anchor".
    /// Every token MUST bind to an asserter anchor. The anchor is
    /// the asserter identity used for authorization on reserved
    /// namespaces and delegation chains.
    /// Parsed from KAPPA_AUTH_TOKENS: comma-separated, or @filepath
    /// to read one token per line from a file. Entries without "="
    /// are rejected at startup.
    pub auth_tokens: Vec<(String, String)>,
    /// Whether bearer token auth is required. Default false.
    pub auth_required: bool,
    /// Disk pressure threshold in megabytes. Default 1024 (1 GiB).
    /// When available space drops below this, blob writes are rejected
    /// with 507 Insufficient Storage.
    pub disk_pressure_threshold_mb: u64,
    /// Disk pressure check interval in seconds. Default 30.
    pub disk_pressure_check_interval_secs: u64,
    /// TLS certificate path. If set with tls_key, enables HTTPS.
    pub tls_cert: Option<String>,
    /// TLS private key path. If set with tls_cert, enables HTTPS.
    pub tls_key: Option<String>,
    /// Per-request timeout in seconds. Default 300.
    pub request_timeout_secs: u64,
    /// Max non-blob request body in bytes. Default 4 MiB.
    pub max_api_body_bytes: usize,
    /// Trusted proxy header for client IP extraction. Default unset.
    pub proxy_trusted_header: Option<String>,
    /// CORS allowed origins. Default "*" (permissive).
    pub cors_allowed_origins: String,
    /// Veilid transport: storage directory.
    pub veilid_storage_dir: Option<String>,
    /// Veilid transport: namespace.
    pub veilid_namespace: Option<String>,
    /// Veilid transport: allow insecure protected store (testing only).
    pub veilid_insecure: bool,
    /// Federation peer URLs for epoch probing.
    pub federation_peers: Vec<String>,
    /// Probe interval in seconds.
    pub probe_interval_secs: u64,
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

        let fsync = env_or("KAPPA_FSYNC", "true") == "true";

        let auth_tokens = parse_auth_tokens(&env_or("KAPPA_AUTH_TOKENS", ""));
        let auth_required = env_or("KAPPA_AUTH_REQUIRED", "false") == "true";

        let disk_pressure_threshold_mb: u64 =
            env_parse("KAPPA_DISK_PRESSURE_THRESHOLD_MB", 1024);
        let disk_pressure_check_interval_secs: u64 =
            env_parse("KAPPA_DISK_PRESSURE_CHECK_INTERVAL_SECS", 30);

        let tls_cert = std::env::var("KAPPA_TLS_CERT").ok();
        let tls_key = std::env::var("KAPPA_TLS_KEY").ok();

        let request_timeout_secs: u64 = env_parse("KAPPA_REQUEST_TIMEOUT_SECS", 300);
        let max_api_body_bytes: usize =
            env_parse("KAPPA_MAX_API_BODY_BYTES", 4 * 1024 * 1024);
        let proxy_trusted_header = std::env::var("KAPPA_PROXY_TRUSTED_HEADERS").ok();
        let cors_allowed_origins = env_or("KAPPA_CORS_ALLOWED_ORIGINS", "*");

        let veilid_storage_dir = std::env::var("KAPPA_VEILID_STORAGE_DIR").ok();
        let veilid_namespace = std::env::var("KAPPA_VEILID_NAMESPACE").ok();
        let veilid_insecure = env_or("KAPPA_VEILID_INSECURE", "false") == "true";

        let federation_peers: Vec<String> = env_or("KAPPA_FEDERATION_PEERS", "")
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect();
        let probe_interval_secs: u64 = env_parse("KAPPA_PROBE_INTERVAL_SECS", 60);

        Config {
            listen_addr,
            store_root,
            max_blob_size,
            upload_timeout_secs,
            signing_algorithm,
            max_transactions,
            max_staging_bytes,
            rate_limit,
            fsync,
            auth_tokens,
            auth_required,
            disk_pressure_threshold_mb,
            disk_pressure_check_interval_secs,
            tls_cert,
            tls_key,
            request_timeout_secs,
            max_api_body_bytes,
            proxy_trusted_header,
            cors_allowed_origins,
            veilid_storage_dir,
            veilid_namespace,
            veilid_insecure,
            federation_peers,
            probe_interval_secs,
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

/// Parse auth tokens from the KAPPA_AUTH_TOKENS value.
/// If the value starts with @, read tokens from the file (one per line).
/// Otherwise split on comma.
///
/// Each entry can be:
///   "token"         -- authenticates, resolves to anonymous identity
///   "token=anchor"  -- authenticates AND resolves to the specified anchor
///
/// The anchor is an asserter identity (e.g. "sha256:abc...") used for
/// authorization decisions on reserved namespaces and delegation chains.
fn parse_auth_tokens(raw: &str) -> Vec<(String, String)> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Vec::new();
    }
    let lines: Vec<String> = if let Some(path) = raw.strip_prefix('@') {
        match std::fs::read_to_string(path) {
            Ok(contents) => contents
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty())
                .collect(),
            Err(e) => {
                config_exit(&format!("KAPPA_AUTH_TOKENS file {}: {}", path, e));
            }
        }
    } else {
        raw.split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect()
    };
    lines.into_iter().map(|entry| {
        if let Some((token, anchor)) = entry.split_once('=') {
            (token.to_string(), anchor.to_string())
        } else {
            config_exit(&format!(
                "KAPPA_AUTH_TOKENS: entry {:?} missing '=anchor' -- format is 'token=anchor'",
                entry
            ));
        }
    }).collect()
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
            fsync: true,
            auth_tokens: Vec::new(),
            auth_required: false,
            disk_pressure_threshold_mb: 1024,
            disk_pressure_check_interval_secs: 30,
            tls_cert: None,
            tls_key: None,
            request_timeout_secs: 300,
            max_api_body_bytes: 4 * 1024 * 1024,
            proxy_trusted_header: None,
            cors_allowed_origins: "*".into(),
            veilid_storage_dir: None,
            veilid_namespace: None,
            veilid_insecure: false,
            federation_peers: Vec::new(),
            probe_interval_secs: 60,
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
