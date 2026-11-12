//! The transport reconciliation runs on: one request to one peer, one
//! response. Every exchange of the protocol (epoch root, snapshot, pull,
//! blob) is a request whose bytes the transport never inspects, so this is
//! the whole seam. A transport backend (Veilid through
//! `kappa-transport-veilid`, a loopback in tests and benches) satisfies
//! it; the reconciliation loop, the per-peer initiator and the blob fetch
//! take nothing wider.

use async_trait::async_trait;

/// Why a request to a peer did not get its response.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("peer not found: {0}")]
    PeerNotFound(String),
    #[error("transport not configured")]
    NotConfigured,
    #[error("message too large: {size} bytes exceeds limit {limit}")]
    MessageTooLarge { size: usize, limit: usize },
    #[error("peer rejected: {0}")]
    Rejected(String),
    /// The bytes on either side did not decode as the protocol expects.
    #[error("codec: {0}")]
    Codec(String),
}

/// One request/response call to a peer named by its transport locator.
#[async_trait]
pub trait ReconcileTransport: Send + Sync {
    /// Send `request` to `peer` and return the response bytes.
    async fn call_peer(&self, peer: &str, request: &[u8]) -> Result<Vec<u8>, TransportError>;

    /// Whether this transport can reach any peer at all. A loop over a
    /// non-operational transport skips every peer rather than failing each.
    fn is_operational(&self) -> bool {
        true
    }
}

#[async_trait]
impl<T: ReconcileTransport + ?Sized> ReconcileTransport for std::sync::Arc<T> {
    async fn call_peer(&self, peer: &str, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        (**self).call_peer(peer, request).await
    }

    fn is_operational(&self) -> bool {
        (**self).is_operational()
    }
}

/// The transport of a single-node deployment: no peer is reachable and
/// every call says so.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoOpTransport;

#[async_trait]
impl ReconcileTransport for NoOpTransport {
    async fn call_peer(&self, _peer: &str, _request: &[u8]) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::NotConfigured)
    }

    fn is_operational(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_noop_transport_reaches_no_peer() {
        let transport = NoOpTransport;
        assert!(!transport.is_operational());
        match transport.call_peer("peer-1", b"request").await {
            Err(TransportError::NotConfigured) => {}
            other => panic!("expected NotConfigured, got {other:?}"),
        }
        let shared: std::sync::Arc<dyn ReconcileTransport> = std::sync::Arc::new(NoOpTransport);
        assert!(!shared.is_operational());
        match shared.call_peer("peer-1", b"request").await {
            Err(TransportError::NotConfigured) => {}
            other => panic!("expected NotConfigured through Arc, got {other:?}"),
        }
    }
}
