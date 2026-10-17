//! TCP acceptance for the HTTP server.
//!
//! Every accepted connection has `TCP_NODELAY` set before it is served.
//! HTTP/1 writes a response's head and body as separate segments; with
//! Nagle's algorithm on, a small body waits for the peer to acknowledge
//! the head, and a peer delaying its acknowledgement (40 ms on Linux) adds
//! that wait to every small response on a kept-alive connection. topcoat
//! serves the accepted stream as is, so the option is set here. A
//! connection whose option cannot be set is closed rather than served
//! degraded, and accepting continues.

use std::io;
use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};

/// Accept the next connection from `tcp` with `TCP_NODELAY` set.
///
/// # Errors
///
/// An error accepting from the listener itself.
pub async fn accept_nodelay(tcp: &TcpListener) -> io::Result<(TcpStream, SocketAddr)> {
    loop {
        let (stream, peer) = tcp.accept().await?;
        match stream.set_nodelay(true) {
            Ok(()) => return Ok((stream, peer)),
            Err(error) => {
                tracing::warn!(%peer, %error, "closing connection: TCP_NODELAY not settable");
            }
        }
    }
}

/// A TCP listener serving every connection with `TCP_NODELAY` set.
pub struct NoDelayListener(TcpListener);

impl NoDelayListener {
    pub const fn new(tcp: TcpListener) -> Self {
        Self(tcp)
    }
}

impl topcoat::router::Listener for NoDelayListener {
    type Io = TcpStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> io::Result<(Self::Io, Self::Addr)> {
        accept_nodelay(&self.0).await
    }

    fn tcp_addr(&self) -> Option<SocketAddr> {
        self.0.local_addr().ok()
    }
}

#[cfg(test)]
mod tests {
    use topcoat::router::Listener;

    use super::*;

    #[tokio::test]
    async fn accepted_connections_have_nodelay_where_plain_acceptance_does_not() -> io::Result<()> {
        let plain = TcpListener::bind(("127.0.0.1", 0)).await?;
        let _client = TcpStream::connect(plain.local_addr()?).await?;
        let (accepted, _) = plain.accept().await?;
        assert!(
            !accepted.nodelay()?,
            "a plain accepted stream must start without TCP_NODELAY for this test to observe the listener"
        );

        let mut listener = NoDelayListener::new(TcpListener::bind(("127.0.0.1", 0)).await?);
        let addr = listener
            .tcp_addr()
            .ok_or_else(|| io::Error::other("listener reports no address"))?;
        let _client = TcpStream::connect(addr).await?;
        let (accepted, _) = listener.accept().await?;
        assert!(accepted.nodelay()?);
        Ok(())
    }
}
