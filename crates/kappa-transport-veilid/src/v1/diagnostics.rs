//! Node health and observability through the Transport trait.

use std::sync::Arc;

use rekindle_transport_veilid::TransportNode;

/// Node status snapshot with all diagnostics.
#[derive(Debug, Clone)]
pub struct NodeStatus {
    pub is_attached: bool,
    pub public_internet_ready: bool,
    pub uptime_secs: u64,
    pub peer_count: usize,
    pub route_allocated: bool,
    pub route_age_secs: Option<u64>,
    pub circuit_total: usize,
    pub circuit_healthy: usize,
    pub circuit_degraded: usize,
    pub circuit_open: usize,
    pub gossip_mesh_peers: usize,
}

/// Read diagnostics from the TransportNode.
pub fn status(node: &Arc<TransportNode>) -> NodeStatus {
    let snapshot = node.status_snapshot();
    let shared = node.shared();

    let (circuit_total, circuit_healthy, circuit_degraded, circuit_open) = {
        let peers = node.peers();
        let reg = peers.read();
        let summary = reg.circuit_summary();
        (
            summary.total,
            summary.healthy,
            summary.degraded,
            summary.circuit_open,
        )
    };

    let gossip_mesh_peers = {
        let broadcast = node.broadcast_mgr();
        let meshes = broadcast.meshes();
        let guard = meshes.read();
        guard.values().map(crate::GossipMesh::peer_count).sum()
    };

    NodeStatus {
        is_attached: shared.is_attached(),
        public_internet_ready: shared.public_internet_ready(),
        uptime_secs: shared.uptime().as_secs(),
        peer_count: snapshot.peer_count,
        route_allocated: snapshot.route_allocated,
        route_age_secs: snapshot.route_age_secs,
        circuit_total,
        circuit_healthy,
        circuit_degraded,
        circuit_open,
        gossip_mesh_peers,
    }
}
