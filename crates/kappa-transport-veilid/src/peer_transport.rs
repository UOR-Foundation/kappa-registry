//! PeerTransport implementation over rekindle-transport-veilid.
//!
//! Adapts TransportNode's async Sender/Caller to kappa-core's sync
//! PeerTransport trait. Uses tokio::runtime::Handle::block_on for
//! the async-to-sync bridge.

use std::sync::Arc;

use kappa_core::transport::{PeerTransport, TransportError};
use rekindle_transport_veilid::TransportNode;

/// Veilid-backed PeerTransport for kappa-registry federation.
///
/// Wraps an `Arc<TransportNode>` started by the kappa-server main
/// function. Does not own the node lifecycle -- the server owns it.
pub struct VeilidPeerTransport {
    node: Arc<TransportNode>,
}

impl VeilidPeerTransport {
    /// Create from an existing, started TransportNode.
    pub fn new(node: Arc<TransportNode>) -> Self {
        Self { node }
    }

    /// Resolve a peer identifier to a PeerTarget via the PeerRegistry.
    ///
    /// The peer string is a hex-encoded route blob or a peer key that
    /// has been cached in the PeerRegistry via cache_peer_route.
    fn resolve_peer(
        &self,
        peer: &str,
    ) -> Result<rekindle_transport_veilid::PeerTarget, TransportError> {
        // Try PeerRegistry cache first (O(1), no DHT read)
        {
            let registry = self.node.peers();
            let mut reg = registry.write();
            if let Some(result) = reg.get_or_import(peer, |blob| {
                self.node
                    .import_route(blob)
                    .map_err(|e| rekindle_transport_veilid::VeilidTransportError::RouteImportFailed {
                        peer: peer.to_string(),
                        reason: e.to_string(),
                    })
            }) {
                return result.map_err(|e| TransportError::PeerNotFound(e.to_string()));
            }
        }

        // Cache miss: try interpreting peer as hex-encoded route blob
        let blob = hex::decode(peer)
            .map_err(|e| TransportError::PeerNotFound(format!("not hex: {e}")))?;
        let target = self
            .node
            .import_route(&blob)
            .map_err(|e| TransportError::PeerNotFound(e.to_string()))?;

        // Cache the route blob for future lookups
        self.node.peers().write().cache_route(peer, blob);

        Ok(target)
    }
}

impl PeerTransport for VeilidPeerTransport {
    fn call_peer(
        &self,
        peer: &str,
        data: &[u8],
    ) -> Result<Vec<u8>, TransportError> {
        if !self.node.is_ready() {
            return Err(TransportError::NotConfigured);
        }

        let target = self.resolve_peer(peer)?;
        let caller = self.node.caller();
        let data = data.to_vec();

        tokio::runtime::Handle::current()
            .block_on(async { caller.call_raw(&target, &data).await })
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))
    }

    fn send_batch(
        &self,
        peer: &str,
        data: &[u8],
    ) -> Result<(), TransportError> {
        if !self.node.is_ready() {
            return Err(TransportError::NotConfigured);
        }

        let target = self.resolve_peer(peer)?;
        let sender = self.node.sender();
        let data = data.to_vec();

        tokio::runtime::Handle::current()
            .block_on(async { sender.send_raw(&target, &data).await })
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))
    }

    fn fetch_epoch_root(
        &self,
        peer: &str,
        namespace: &str,
    ) -> Result<Vec<u8>, TransportError> {
        if !self.node.is_ready() {
            return Err(TransportError::NotConfigured);
        }

        let target = self.resolve_peer(peer)?;
        let caller = self.node.caller();

        // Protocol: byte 0x01 + postcard-encoded namespace
        let mut request = vec![0x01u8];
        request.extend_from_slice(namespace.as_bytes());

        tokio::runtime::Handle::current()
            .block_on(async { caller.call_raw(&target, &request).await })
            .map_err(|e| TransportError::ConnectionFailed(e.to_string()))
    }

    fn rtt_estimate(
        &self,
        peer: &str,
    ) -> Option<std::time::Duration> {
        if !self.node.is_ready() {
            return None;
        }

        let target = match self.resolve_peer(peer) {
            Ok(t) => t,
            Err(_) => return None,
        };

        let caller = self.node.caller();
        let start = std::time::Instant::now();

        // Protocol: byte 0x00 = ping
        let result = tokio::runtime::Handle::current()
            .block_on(async { caller.call_raw(&target, &[0x00]).await });

        match result {
            Ok(_) => Some(start.elapsed()),
            Err(_) => None,
        }
    }
}
