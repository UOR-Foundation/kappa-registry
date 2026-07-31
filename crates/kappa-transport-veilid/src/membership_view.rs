//! MembershipView implementation backed by rekindle-transport-veilid's
//! PeerRegistry.
//!
//! The PeerRegistry is the source of truth for known peers. It tracks
//! route blobs with TTL-based staleness and per-peer circuit breakers.
//! This adapter exposes that state via kappa-core's MembershipView trait.

use std::sync::Arc;

use kappa_core::membership::{MembershipView, PeerInfo};
use rekindle_transport_veilid::TransportNode;

/// Veilid-backed MembershipView for kappa-registry federation.
///
/// Reads peer state from TransportNode's PeerRegistry. Does not own
/// the registry -- it reads from the shared Arc<RwLock<PeerRegistry>>.
pub struct VeilidMembershipView {
    node: Arc<TransportNode>,
    self_id: String,
}

impl VeilidMembershipView {
    /// Create from an existing TransportNode and this node's identity.
    pub fn new(node: Arc<TransportNode>, self_id: String) -> Self {
        Self { node, self_id }
    }

    /// Cache a peer's route blob in the PeerRegistry.
    ///
    /// Called by the reconciliation loop or membership protocol when
    /// a new peer is discovered. After caching, the peer appears in
    /// members() and is reachable via PeerTransport.
    pub fn register_peer(&self, peer_id: &str, route_blob: Vec<u8>) {
        self.node.peers().write().cache_route(peer_id, route_blob);
    }

    /// Remove a peer's cached route.
    pub fn remove_peer(&self, peer_id: &str) {
        self.node.peers().write().invalidate_route(peer_id);
    }
}

impl MembershipView for VeilidMembershipView {
    fn members(&self) -> Vec<PeerInfo> {
        let registry = self.node.peers();
        let reg = registry.read();
        reg.snapshot()
            .into_iter()
            .map(|snap| PeerInfo {
                id: snap.key,
                address: String::new(), // route-based, no HTTP address
                healthy: snap.has_route && !snap.circuit_open,
            })
            .collect()
    }

    fn is_member(&self, peer_id: &str) -> bool {
        let registry = self.node.peers();
        let reg = registry.read();
        reg.get_route(peer_id).is_some()
    }

    fn self_id(&self) -> &str {
        &self.self_id
    }
}
