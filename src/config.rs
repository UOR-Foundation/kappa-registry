use std::net::SocketAddr;
use std::path::PathBuf;

pub struct Config {
    pub listen_addr: SocketAddr,
    pub store_root: PathBuf,
    pub max_blob_size: usize,
    pub upload_timeout_secs: u64,
    pub rate_limit_rps: u64,
    pub rate_limit_burst: u32,
    pub max_transactions: usize,
    pub max_staging_bytes: usize,
}

impl Config {
    pub fn from_env() -> Self {
        let listen_addr: SocketAddr = env_or("KAPPA_LISTEN_ADDR", "127.0.0.1:8080")
            .parse()
            .unwrap_or_else(|e| config_exit(&format!("KAPPA_LISTEN_ADDR: {e}")));

        let store_root = PathBuf::from(env_or("KAPPA_STORE_ROOT", "./data"));

        let max_blob_size: usize = env_or("KAPPA_MAX_BLOB_SIZE", "67108864")
            .parse()
            .unwrap_or(67_108_864);

        let upload_timeout_secs: u64 = env_or("KAPPA_UPLOAD_TIMEOUT", "3600")
            .parse()
            .unwrap_or(3600);

        let rate_limit_rps: u64 = env_or("KAPPA_RATE_LIMIT_RPS", "0").parse().unwrap_or(0);

        let rate_limit_burst: u32 = env_or("KAPPA_RATE_LIMIT_BURST", "50").parse().unwrap_or(50);

        let max_transactions: usize = env_or("KAPPA_MAX_TRANSACTIONS", "64").parse().unwrap_or(64);

        // Default 256 MiB global staging limit
        let max_staging_bytes: usize = env_or("KAPPA_MAX_STAGING_BYTES", "268435456")
            .parse()
            .unwrap_or(268_435_456);

        Config {
            listen_addr,
            store_root,
            max_blob_size,
            upload_timeout_secs,
            rate_limit_rps,
            rate_limit_burst,
            max_transactions,
            max_staging_bytes,
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[cold]
#[inline(never)]
fn config_exit(msg: &str) -> ! {
    eprintln!("configuration error: {msg}");
    std::process::exit(2);
}
