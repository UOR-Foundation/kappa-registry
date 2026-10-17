use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

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
            (Some(c), Some(k)) => Some(Self {
                cert_path: c,
                key_path: k,
                client_ca_path: std::env::var("KAPPA_TLS_CLIENT_CA").ok(),
                handshake_timeout: Duration::from_secs(
                    std::env::var("KAPPA_TLS_HANDSHAKE_TIMEOUT_SECS")
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(10),
                ),
            }),
            (Some(_), None) => {
                eprintln!("KAPPA_TLS_CERT set without KAPPA_TLS_KEY");
                std::process::exit(2);
            }
            (None, Some(_)) => {
                eprintln!("KAPPA_TLS_KEY set without KAPPA_TLS_CERT");
                std::process::exit(2);
            }
            (None, None) => None,
        }
    }
}

pub fn build_acceptor(config: &TlsConfig) -> TlsAcceptor {
    match build_server_config(config) {
        Ok(c) => TlsAcceptor::from(Arc::new(c)),
        Err(e) => {
            eprintln!("TLS configuration error: {e}");
            std::process::exit(2);
        }
    }
}

fn build_server_config(
    config: &TlsConfig,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    let cert_file = std::fs::File::open(&config.cert_path)
        .map_err(|e| format!("cert {}: {}", config.cert_path, e))?;
    let key_file = std::fs::File::open(&config.key_path)
        .map_err(|e| format!("key {}: {}", config.key_path, e))?;

    let certs: Vec<_> =
        rustls_pemfile::certs(&mut io::BufReader::new(cert_file)).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err("no certificates in cert file".into());
    }

    let key = rustls_pemfile::private_key(&mut io::BufReader::new(key_file))?
        .ok_or("no private key in key file")?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut server_config = if let Some(ref ca_path) = config.client_ca_path {
        let ca_file =
            std::fs::File::open(ca_path).map_err(|e| format!("client CA {}: {}", ca_path, e))?;
        let mut root_store = rustls::RootCertStore::empty();
        for cert in rustls_pemfile::certs(&mut io::BufReader::new(ca_file)) {
            root_store.add(cert?)?;
        }
        let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(root_store),
            provider.clone(),
        )
        .build()?;
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

    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(server_config)
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
            // Records carry the head and body of small responses in
            // separate segments as plain TCP does; see `crate::listener`.
            let (stream, addr) = crate::listener::accept_nodelay(&self.tcp).await?;
            match tokio::time::timeout(self.handshake_timeout, self.acceptor.accept(stream)).await {
                Ok(Ok(tls)) => return Ok((tls, addr)),
                Ok(Err(e)) => {
                    tracing::debug!(peer = %addr, error = %e, "TLS handshake failed");
                }
                Err(_) => {
                    tracing::debug!(peer = %addr, "TLS handshake timeout");
                }
            }
        }
    }

    fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp.local_addr().ok()
    }
}
