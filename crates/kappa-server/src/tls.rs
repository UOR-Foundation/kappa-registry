//! TLS and mTLS listener for kappa-registry.
//!
//! Wraps TCP with tokio-rustls. Implements topcoat's Listener trait.
//! Handshake failures and timeouts are absorbed (logged at debug) --
//! a single bad client never crashes the accept loop.
//! ALPN negotiates h2 and http/1.1 for HTTP/2 over TLS.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// TLS configuration parsed from environment.
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
    pub client_ca_path: Option<String>,
    pub handshake_timeout: Duration,
}

impl TlsConfig {
    pub fn from_env() -> Option<Self> {
        let cert = std::env::var("KAPPA_TLS_CERT").ok();
        let key = std::env::var("KAPPA_TLS_KEY").ok();
        match (cert, key) {
            (Some(c), Some(k)) => {
                let client_ca = std::env::var("KAPPA_TLS_CLIENT_CA").ok();
                let timeout_secs: u64 = std::env::var("KAPPA_TLS_HANDSHAKE_TIMEOUT_SECS")
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(10);
                Some(Self {
                    cert_path: c,
                    key_path: k,
                    client_ca_path: client_ca,
                    handshake_timeout: Duration::from_secs(timeout_secs),
                })
            }
            (Some(_), None) => {
                eprintln!("configuration error: KAPPA_TLS_CERT set without KAPPA_TLS_KEY");
                std::process::exit(2);
            }
            (None, Some(_)) => {
                eprintln!("configuration error: KAPPA_TLS_KEY set without KAPPA_TLS_CERT");
                std::process::exit(2);
            }
            (None, None) => None,
        }
    }
}

fn build_server_config(
    tls_config: &TlsConfig,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    let cert_file = std::fs::File::open(&tls_config.cert_path)
        .map_err(|e| format!("cert {}: {}", tls_config.cert_path, e))?;
    let key_file = std::fs::File::open(&tls_config.key_path)
        .map_err(|e| format!("key {}: {}", tls_config.key_path, e))?;

    let certs: Vec<_> = rustls_pemfile::certs(&mut io::BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err("no certificates found in cert file".into());
    }

    let key = rustls_pemfile::private_key(&mut io::BufReader::new(key_file))?
        .ok_or("no private key found in key file")?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut config = if let Some(ref ca_path) = tls_config.client_ca_path {
        let ca_file = std::fs::File::open(ca_path)
            .map_err(|e| format!("client CA {}: {}", ca_path, e))?;
        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut io::BufReader::new(ca_file)) {
            root_store.add(cert?)?;
        }
        let verifier =
            rustls::server::WebPkiClientVerifier::builder_with_provider(
                Arc::new(root_store),
                provider.clone(),
            ).build()?;
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(verifier)
            .with_single_cert(certs, key)?
    } else {
        rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?
    };

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

pub fn build_acceptor(tls_config: &TlsConfig) -> TlsAcceptor {
    match build_server_config(tls_config) {
        Ok(c) => TlsAcceptor::from(Arc::new(c)),
        Err(e) => {
            eprintln!("TLS configuration error: {e}");
            std::process::exit(2);
        }
    }
}

pub struct TlsListener {
    tcp: TcpListener,
    acceptor: TlsAcceptor,
    handshake_timeout: Duration,
}

impl TlsListener {
    pub fn new(tcp: TcpListener, acceptor: TlsAcceptor, handshake_timeout: Duration) -> Self {
        Self {
            tcp,
            acceptor,
            handshake_timeout,
        }
    }
}

impl topcoat::router::Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> io::Result<(Self::Io, Self::Addr)> {
        loop {
            let (stream, addr) = self.tcp.accept().await?;
            match tokio::time::timeout(self.handshake_timeout, self.acceptor.accept(stream)).await {
                Ok(Ok(tls)) => return Ok((tls, addr)),
                Ok(Err(e)) => {
                    tracing::debug!(peer = %addr, error = %e, "TLS handshake failed");
                    continue;
                }
                Err(_) => {
                    tracing::debug!(peer = %addr, "TLS handshake timeout");
                    continue;
                }
            }
        }
    }

    fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp.local_addr().ok()
    }
}
