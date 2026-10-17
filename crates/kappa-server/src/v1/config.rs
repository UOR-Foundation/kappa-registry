use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct ClassConfig {
    pub period_ms: u64,
    pub burst: u32,
}

#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub read: ClassConfig,
    pub write: ClassConfig,
    pub admin: ClassConfig,
}

impl RateLimitConfig {
    pub fn is_enabled(&self) -> bool {
        self.read.period_ms > 0 || self.write.period_ms > 0 || self.admin.period_ms > 0
    }
}

/// A configuration value that could not be used.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{key}: {reason}")]
    Invalid { key: &'static str, reason: String },
    #[error("KAPPA_AUTH_TOKENS file {path}: {source}")]
    TokenFile {
        path: String,
        source: std::io::Error,
    },
    #[error("KAPPA_AUTH_TOKENS: entry {entry:?} missing '=anchor'")]
    TokenEntry { entry: String },
    #[error("KAPPA_AUTH_TOKENS: anchor '{anchor}' is not a valid kappa: {reason}")]
    TokenAnchor { anchor: String, reason: String },
}

pub struct Config {
    pub listen_addr: SocketAddr,
    /// Where the binary writes the address it bound, once bound. With
    /// `KAPPA_LISTEN_ADDR` port 0, a supervisor learns the kernel-assigned
    /// port from this file instead of reserving a port it must release
    /// before the server can bind it.
    pub ready_file: Option<PathBuf>,
    pub store_root: PathBuf,
    pub encryption_key_file: Option<PathBuf>,
    pub max_blob_size: usize,
    /// Bytes every delta decode in flight (git pack deltas, bundle
    /// entries) may hold at once across every request.
    pub max_delta_bytes: usize,
    /// Staged resources (uploads, multipart uploads, transactions) open at
    /// once across every namespace; zero disables the limit.
    pub max_transactions: usize,
    /// Bytes every open staged resource may hold in total; zero disables
    /// the limit.
    pub max_staging_bytes: u64,
    pub signing_algorithm: String,
    /// The rotation witness key: an Ed25519 seed, raw or hex, of a signer
    /// other than the node's. Absent, authority rotation is refused.
    pub rotation_witness_key_file: Option<PathBuf>,
    pub rate_limit: RateLimitConfig,
    pub fsync: bool,
    pub auth_tokens: Vec<(String, kappa_store::kappa::Kappa)>,
    /// `token=anchor`: a bearer token whose anchor is delegated `_root`
    /// authority by the node at startup.
    pub root_token: Option<String>,
    pub auth_required: bool,
    pub disk_pressure_threshold_mb: u64,
    pub disk_pressure_check_interval_secs: u64,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub request_timeout_secs: u64,
    pub max_api_body_bytes: usize,
    pub proxy_trusted_header: Option<String>,
    pub cors_allowed_origins: String,
    pub veilid_storage_dir: Option<String>,
    pub veilid_namespace: Option<String>,
    pub veilid_insecure: bool,
    pub federation_peers: Vec<String>,
    pub probe_interval_secs: u64,
    pub s3_base_domain: String,
    pub pds_hostname: String,
    pub plc_directory_url: String,
    pub rekor_url: String,
    pub nix_priority: u32,
    pub nix_trusted_keys: String,
    pub handle_verify_interval_secs: u64,
    pub handle_ttl_ms: u64,
    pub lifecycle_interval_secs: u64,
    /// Seconds between content inventory steps.
    pub inventory_interval_secs: u64,
    /// Inventory entries examined per step.
    pub inventory_batch: usize,
    pub tls_client_ca: Option<String>,
    /// Maximum concurrently open CRDT collaboration rooms. Each room holds
    /// at most 16 MiB of state in memory.
    pub crdt_max_rooms: usize,
}

/// Reads configuration keys from one source: the process environment, or
/// any key-value set a caller supplies. A value that is not UTF-8 reads as
/// absent for text settings, as the environment's `var` does; path
/// settings keep the raw value.
struct Source<F: Fn(&str) -> Option<OsString>>(F);

impl<F: Fn(&str) -> Option<OsString>> Source<F> {
    fn text(&self, key: &str) -> Option<String> {
        (self.0)(key).and_then(|value| value.into_string().ok())
    }

    fn path(&self, key: &str) -> Option<PathBuf> {
        (self.0)(key).map(PathBuf::from)
    }

    fn text_or(&self, key: &str, default: &str) -> String {
        self.text(key).unwrap_or_else(|| default.to_owned())
    }

    fn flag(&self, key: &str, default: &str) -> bool {
        self.text_or(key, default) == "true"
    }

    fn parse<T: std::str::FromStr>(&self, key: &'static str, default: T) -> Result<T, ConfigError>
    where
        T::Err: std::fmt::Display,
    {
        match self.text(key) {
            Some(value) => value.parse().map_err(|error: T::Err| ConfigError::Invalid {
                key,
                reason: error.to_string(),
            }),
            None => Ok(default),
        }
    }
}

impl Config {
    /// Configuration from the process environment. An unusable value ends
    /// the process with exit status 2 and the reason on stderr.
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var_os(key)).unwrap_or_else(|error| {
            eprintln!("configuration error: {error}");
            std::process::exit(2);
        })
    }

    /// Configuration from `lookup`, keyed exactly as the environment is.
    /// Absent keys take the documented defaults.
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<OsString>) -> Result<Self, ConfigError> {
        let source = Source(lookup);
        Ok(Config {
            listen_addr: source.parse(
                "KAPPA_LISTEN_ADDR",
                SocketAddr::from(([127, 0, 0, 1], 5000)),
            )?,
            ready_file: source.path("KAPPA_READY_FILE"),
            store_root: source
                .path("KAPPA_STORE_ROOT")
                .unwrap_or_else(|| PathBuf::from("./data")),
            encryption_key_file: source.path("KAPPA_ENCRYPTION_KEY_FILE"),
            max_blob_size: source.parse("KAPPA_MAX_BLOB_SIZE", 256 * 1024 * 1024)?,
            max_delta_bytes: source.parse("KAPPA_MAX_DELTA_BYTES", 256 * 1024 * 1024)?,
            max_transactions: source.parse("KAPPA_MAX_TRANSACTIONS", 64)?,
            max_staging_bytes: source.parse("KAPPA_MAX_STAGING_BYTES", 256 * 1024 * 1024)?,
            signing_algorithm: source.text_or("KAPPA_SIGNING_ALGORITHM", "ed25519"),
            rotation_witness_key_file: source.path("KAPPA_ROTATION_WITNESS_KEY_FILE"),
            rate_limit: RateLimitConfig {
                read: ClassConfig {
                    period_ms: source.parse("KAPPA_RATELIMIT_READ_PERIOD_MS", 0)?,
                    burst: source.parse("KAPPA_RATELIMIT_READ_BURST", 1000)?,
                },
                write: ClassConfig {
                    period_ms: source.parse("KAPPA_RATELIMIT_WRITE_PERIOD_MS", 0)?,
                    burst: source.parse("KAPPA_RATELIMIT_WRITE_BURST", 200)?,
                },
                admin: ClassConfig {
                    period_ms: source.parse("KAPPA_RATELIMIT_ADMIN_PERIOD_MS", 0)?,
                    burst: source.parse("KAPPA_RATELIMIT_ADMIN_BURST", 50)?,
                },
            },
            fsync: source.flag("KAPPA_FSYNC", "true"),
            auth_tokens: parse_auth_tokens(&source.text_or("KAPPA_AUTH_TOKENS", ""))?,
            root_token: source.text("KAPPA_ROOT_TOKEN"),
            auth_required: source.flag("KAPPA_AUTH_REQUIRED", "false"),
            disk_pressure_threshold_mb: source.parse("KAPPA_DISK_PRESSURE_THRESHOLD_MB", 1024)?,
            disk_pressure_check_interval_secs: source
                .parse("KAPPA_DISK_PRESSURE_CHECK_INTERVAL_SECS", 30)?,
            tls_cert: source.text("KAPPA_TLS_CERT"),
            tls_key: source.text("KAPPA_TLS_KEY"),
            request_timeout_secs: source.parse("KAPPA_REQUEST_TIMEOUT_SECS", 300)?,
            max_api_body_bytes: source.parse("KAPPA_MAX_API_BODY_BYTES", 4 * 1024 * 1024)?,
            proxy_trusted_header: source.text("KAPPA_PROXY_TRUSTED_HEADERS"),
            cors_allowed_origins: source.text_or("KAPPA_CORS_ALLOWED_ORIGINS", "*"),
            veilid_storage_dir: source.text("KAPPA_VEILID_STORAGE_DIR"),
            veilid_namespace: source.text("KAPPA_VEILID_NAMESPACE"),
            veilid_insecure: source.flag("KAPPA_VEILID_INSECURE", "false"),
            federation_peers: source
                .text_or("KAPPA_FEDERATION_PEERS", "")
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_string())
                .collect(),
            probe_interval_secs: source.parse("KAPPA_PROBE_INTERVAL_SECS", 60)?,
            s3_base_domain: source.text_or("KAPPA_S3_BASE_DOMAIN", ""),
            pds_hostname: source.text_or("KAPPA_PDS_HOSTNAME", "http://localhost:5000"),
            plc_directory_url: source.text_or("KAPPA_PLC_DIRECTORY_URL", "https://plc.directory"),
            rekor_url: source.text_or("KAPPA_REKOR_URL", "https://rekor.sigstore.dev"),
            nix_priority: source.parse("KAPPA_NIX_PRIORITY", 30)?,
            nix_trusted_keys: source.text_or("KAPPA_NIX_TRUSTED_KEYS", ""),
            handle_verify_interval_secs: source.parse("KAPPA_HANDLE_VERIFY_INTERVAL_SECS", 3600)?,
            handle_ttl_ms: source.parse("KAPPA_HANDLE_TTL_MS", 24 * 3600 * 1000)?,
            lifecycle_interval_secs: source.parse("KAPPA_LIFECYCLE_INTERVAL_SECS", 86400)?,
            inventory_interval_secs: source.parse("KAPPA_INVENTORY_INTERVAL_SECS", 300)?,
            inventory_batch: source.parse("KAPPA_INVENTORY_BATCH", 4096)?,
            tls_client_ca: source.text("KAPPA_TLS_CLIENT_CA"),
            crdt_max_rooms: source.parse("KAPPA_CRDT_MAX_ROOMS", 1000)?,
        })
    }
}

fn parse_auth_tokens(raw: &str) -> Result<Vec<(String, kappa_store::kappa::Kappa)>, ConfigError> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let lines: Vec<String> = if let Some(path) = raw.strip_prefix('@') {
        std::fs::read_to_string(path)
            .map_err(|source| ConfigError::TokenFile {
                path: path.to_owned(),
                source,
            })?
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect()
    } else {
        raw.split(',')
            .map(|t| t.trim().to_string())
            .filter(|t| !t.is_empty())
            .collect()
    };
    lines
        .into_iter()
        .map(|entry| match entry.split_once('=') {
            Some((token, anchor_str)) => kappa_store::kappa::Kappa::parse(anchor_str)
                .map(|anchor| (token.to_string(), anchor))
                .map_err(|e| ConfigError::TokenAnchor {
                    anchor: anchor_str.to_owned(),
                    reason: e.to_string(),
                }),
            None => Err(ConfigError::TokenEntry { entry }),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn config_of(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let values: HashMap<String, OsString> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        Config::from_lookup(|key| values.get(key).cloned())
    }

    #[test]
    fn absent_keys_take_the_documented_defaults() -> Result<(), ConfigError> {
        let config = config_of(&[])?;
        assert_eq!(config.listen_addr, SocketAddr::from(([127, 0, 0, 1], 5000)));
        assert_eq!(config.store_root, PathBuf::from("./data"));
        assert_eq!(config.max_blob_size, 256 * 1024 * 1024);
        assert_eq!(config.max_delta_bytes, 256 * 1024 * 1024);
        assert_eq!(config.max_transactions, 64);
        assert_eq!(config.max_staging_bytes, 256 * 1024 * 1024);
        assert!(config.fsync);
        assert!(!config.rate_limit.is_enabled());
        assert!(config.auth_tokens.is_empty());
        Ok(())
    }

    #[test]
    fn supplied_values_override_defaults() -> Result<(), ConfigError> {
        let config = config_of(&[
            ("KAPPA_LISTEN_ADDR", "127.0.0.1:0"),
            ("KAPPA_STORE_ROOT", "/tmp/store"),
            ("KAPPA_FSYNC", "false"),
            ("KAPPA_RATELIMIT_WRITE_PERIOD_MS", "200"),
            ("KAPPA_FEDERATION_PEERS", "a, b,"),
        ])?;
        assert_eq!(config.listen_addr.port(), 0);
        assert_eq!(config.store_root, PathBuf::from("/tmp/store"));
        assert!(!config.fsync);
        assert!(config.rate_limit.is_enabled());
        assert_eq!(config.federation_peers, ["a", "b"]);
        Ok(())
    }

    #[test]
    fn unusable_values_are_errors_naming_their_key() {
        let error = config_of(&[("KAPPA_MAX_BLOB_SIZE", "lots")]).err();
        assert!(
            matches!(
                error,
                Some(ConfigError::Invalid {
                    key: "KAPPA_MAX_BLOB_SIZE",
                    ..
                })
            ),
            "{error:?}"
        );
        assert!(matches!(
            config_of(&[("KAPPA_AUTH_TOKENS", "token-without-anchor")]),
            Err(ConfigError::TokenEntry { .. })
        ));
        assert!(matches!(
            config_of(&[("KAPPA_AUTH_TOKENS", "t=not-a-kappa")]),
            Err(ConfigError::TokenAnchor { .. })
        ));
    }
}
