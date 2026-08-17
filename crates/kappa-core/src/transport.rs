//! PeerTransport trait (seam S6): node-to-node communication.

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("peer not found: {0}")]
    PeerNotFound(String),
    #[error("transport not configured")]
    NotConfigured,
}

pub trait PeerTransport: Send + Sync {
    /// Fire-and-forget message to a peer (no response expected).
    fn send_batch(&self, peer: &str, data: &[u8]) -> Result<(), TransportError>;
    /// Request/response call to a peer. Returns the response bytes.
    fn call_peer(&self, peer: &str, data: &[u8]) -> Result<Vec<u8>, TransportError>;
    /// Fetch the current epoch root from a peer for a namespace.
    fn fetch_epoch_root(&self, peer: &str, namespace: &str) -> Result<Vec<u8>, TransportError>;
    /// Estimate round-trip time to a peer.
    fn rtt_estimate(&self, peer: &str) -> Option<std::time::Duration>;
}

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
}
