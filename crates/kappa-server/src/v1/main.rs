//! kappa-registry server binary: configuration from the environment,
//! logging, then the assembled server on the configured address, over TLS
//! when a certificate is configured, until SIGINT or SIGTERM.

use std::net::SocketAddr;
use std::path::Path;

use kappa_server::{app, config, listener, shutdown, tls};

/// Report the bound address: written beside `path`, then renamed onto it,
/// so a reader never sees a partial address.
fn write_ready_file(path: &Path, bound: SocketAddr) -> std::io::Result<()> {
    let mut staging = path.as_os_str().to_owned();
    staging.push(".partial");
    std::fs::write(&staging, bound.to_string())?;
    std::fs::rename(&staging, path)
}

#[tokio::main]
async fn main() {
    let cfg = config::Config::from_env();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let tls_config = tls::TlsConfig::from_env();
    let server = match app::build(&cfg, tls_config.is_some()).await {
        Ok(server) => server,
        Err(error) => {
            tracing::error!(%error, "kappa-registry cannot start");
            std::process::exit(2);
        }
    };

    // The listener is bound here and handed to the server; topcoat does not
    // read HOST or PORT.
    let tcp = match tokio::net::TcpListener::bind(cfg.listen_addr).await {
        Ok(tcp) => tcp,
        Err(error) => {
            tracing::error!(listen = %cfg.listen_addr, %error, "cannot bind the listen address");
            std::process::exit(2);
        }
    };
    let bound = match tcp.local_addr() {
        Ok(bound) => bound,
        Err(error) => {
            tracing::error!(%error, "cannot read the bound address");
            std::process::exit(2);
        }
    };
    let acceptor = tls_config.as_ref().map(tls::build_acceptor);
    if let Some(path) = &cfg.ready_file
        && let Err(error) = write_ready_file(path, bound)
    {
        tracing::error!(path = %path.display(), %error, "cannot write the ready file");
        std::process::exit(2);
    }
    let served = match (tls_config, acceptor) {
        (Some(tls_cfg), Some(acceptor)) => {
            let listener = tls::TlsListener::new(tcp, acceptor, tls_cfg.handshake_timeout);
            tracing::info!(listen = %bound, tls = true, "kappa-registry starting");
            server.serve(listener, shutdown::shutdown_signal()).await
        }
        _ => {
            tracing::info!(listen = %bound, "kappa-registry starting");
            server
                .serve(
                    listener::NoDelayListener::new(tcp),
                    shutdown::shutdown_signal(),
                )
                .await
        }
    };
    if let Err(error) = served {
        tracing::error!(%error, "server error");
        std::process::exit(1);
    }
}
