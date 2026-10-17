//! Node-to-node communication primitives for federation.
//!
//! The `PeerTransport` trait abstracts the transport layer so that
//! federation logic (epoch exchange, reconciliation, blob replication)
//! is independent of the wire protocol (HTTP, gRPC, Veilid, QUIC).

/// Errors from peer transport operations.
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
}

/// Node-to-node communication.
pub trait PeerTransport: Send + Sync {
    /// Fire-and-forget batch message to a peer.
    fn send_batch(&self, peer: &str, data: &[u8]) -> Result<(), TransportError>;

    /// Request/response call to a peer. Returns response bytes.
    fn call_peer(&self, peer: &str, data: &[u8]) -> Result<Vec<u8>, TransportError>;

    /// Fetch the current epoch root from a peer for a namespace.
    fn fetch_epoch_root(&self, peer: &str, namespace: &str) -> Result<Vec<u8>, TransportError>;

    /// Estimate round-trip time to a peer. None if unknown.
    fn rtt_estimate(&self, peer: &str) -> Option<std::time::Duration>;

    /// Whether this transport is operational (has been configured
    /// and can reach at least one peer).
    fn is_operational(&self) -> bool {
        true
    }
}

/// No-op transport for single-node deployments and tests.
/// All operations return `NotConfigured`.
pub struct NoOpTransport;

impl PeerTransport for NoOpTransport {
    fn send_batch(&self, _peer: &str, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotConfigured)
    }

    fn call_peer(&self, _peer: &str, _data: &[u8]) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::NotConfigured)
    }

    fn fetch_epoch_root(&self, _peer: &str, _ns: &str) -> Result<Vec<u8>, TransportError> {
        Err(TransportError::NotConfigured)
    }

    fn rtt_estimate(&self, _peer: &str) -> Option<std::time::Duration> {
        None
    }

    fn is_operational(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_transport_returns_not_configured() {
        let t = NoOpTransport;
        assert!(matches!(
            t.send_batch("peer-1", b"data"),
            Err(TransportError::NotConfigured)
        ));
        assert!(matches!(
            t.call_peer("peer-1", b"data"),
            Err(TransportError::NotConfigured)
        ));
        assert!(matches!(
            t.fetch_epoch_root("peer-1", "ns"),
            Err(TransportError::NotConfigured)
        ));
        assert!(t.rtt_estimate("peer-1").is_none());
        assert!(!t.is_operational());
    }
}
