//! Node construction and lifecycle.
//!
//! Owns the TransportNode and VeilidTransport. Provides route allocation
//! and shutdown coordination.
//!
//! `KappaNode::start` returns `(KappaNode, Receiver<InboundEvent>)`,
//! matching `TransportNode::start`'s pattern. The caller owns the
//! receiver and spawns the dispatch loop. No take/Option/ordering games.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::info;

use rekindle_transport_veilid::{TransportConfig, TransportNode, VeilidTransport};
use rekindle_types::transport::{InboundEvent, Transport};

use crate::error::TransportError;

/// Route allocation result.
pub struct RouteAllocation {
    pub route_id: String,
    pub blob: Vec<u8>,
}

/// Owns the Veilid node and the Transport trait implementation.
pub struct KappaNode {
    node: Arc<TransportNode>,
    transport: Arc<VeilidTransport>,
}

impl KappaNode {
    /// Start the Veilid node, attach to the network, construct all
    /// delivery subsystems, and begin the internal dispatch loop.
    ///
    /// Returns the node and the inbound event receiver. The caller
    /// owns the receiver and spawns the dispatch loop.
    pub async fn start(
        config: TransportConfig,
    ) -> Result<(Self, mpsc::Receiver<InboundEvent>), TransportError> {
        let (node, inbound_rx) = TransportNode::start(config)
            .await
            .map_err(TransportError::from)?;

        let node = Arc::new(node);
        let transport = Arc::new(VeilidTransport::new(Arc::clone(&node)));

        info!("kappa node started");

        Ok((Self { node, transport }, inbound_rx))
    }

    /// The Transport trait implementation. Use this for all DHT, messaging,
    /// route, watch, inspect, and bulk transfer operations.
    pub fn transport(&self) -> &Arc<VeilidTransport> {
        &self.transport
    }

    /// Transport as a trait object for consumers that need dyn dispatch.
    pub fn transport_dyn(&self) -> Arc<dyn Transport> {
        Arc::clone(&self.transport) as Arc<dyn Transport>
    }

    /// The underlying TransportNode for primitives that are clean in the
    /// public API: PeerRegistry, RouteManager, SharedState, Sender,
    /// Caller, BroadcastManager, DeliveryEngine, MeshManager, BulkSender.
    pub fn node(&self) -> &Arc<TransportNode> {
        &self.node
    }

    /// Clone the node Arc for sharing with other subsystems.
    pub fn node_arc(&self) -> Arc<TransportNode> {
        Arc::clone(&self.node)
    }

    /// Allocate a private route for receiving inbound messages.
    pub async fn allocate_route(&self) -> Result<RouteAllocation, TransportError> {
        let (route_id, blob) = self
            .transport
            .allocate_route()
            .await
            .map_err(TransportError::from)?;

        info!(
            route_id = route_id.as_str(),
            blob_len = blob.len(),
            "route allocated"
        );

        Ok(RouteAllocation { route_id, blob })
    }

    /// Current route blob if a route is allocated.
    pub fn route_blob(&self) -> Option<Vec<u8>> {
        self.transport.route_blob()
    }

    /// Whether the node is attached and public internet ready.
    pub fn is_ready(&self) -> bool {
        self.node.is_ready()
    }

    /// Node uptime.
    pub fn uptime(&self) -> std::time::Duration {
        self.node.uptime()
    }

    /// Graceful shutdown.
    pub async fn shutdown(&self) {
        self.node.graceful_shutdown().await;
        info!("kappa node shutdown complete");
    }
}
