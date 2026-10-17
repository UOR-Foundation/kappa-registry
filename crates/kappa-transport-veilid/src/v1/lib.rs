#![forbid(unsafe_code)]
//! Veilid P2P transport for kappa-registry federation.
//!
//! This crate consumes rekindle-transport-veilid through the Transport
//! trait. Zero veilid_core types appear anywhere in this crate. If the
//! Transport trait is missing a capability, the fix goes into rekindle,
//! not here.
//!
//! What this crate provides:
//!
//! `error`: typed error taxonomy with retryable classification
//! `node`: construction helper that wires TransportNode to kappa-store
//! `dht`: DHT record persistence through the Transport trait
//! `dispatch`: inbound event routing for reconciliation and watches
//! `reconcile`: MST reconciliation protocol over Veilid app_call
//! `diagnostics`: node health and observability

pub mod dht;
pub mod diagnostics;
pub mod dispatch;
pub mod error;
pub mod node;
pub mod reconcile;

// Re-export the commodity transport types. Consumers use these directly.
// No wrappers, no adapters. If the rekindle API is deficient, fix rekindle.

// Node lifecycle
pub use rekindle_transport_veilid::config::{SafetyConfig, SafetyProfile};
pub use rekindle_transport_veilid::{TransportConfig, TransportNode};

// Transport trait and core types
pub use rekindle_transport_veilid::{
    InboundEvent, InspectResult, OpenRecord, RecordSchema, Transport, VeilidTransport, WatchToken,
};

// Peer messaging
pub use rekindle_transport_veilid::{BroadcastReport, Caller, Sender};

// Peer registry
pub use rekindle_transport_veilid::{CircuitSummary, PeerRegistry, PeerSnapshot, PeerTarget};

// Route resolution
pub use rekindle_transport_veilid::RouteResolver;
pub use rekindle_transport_veilid::resolver::ResolveResult;

// Delivery
pub use rekindle_transport_veilid::DeliveryEngine;
pub use rekindle_transport_veilid::{DeliveryReport, Durability};

// Gossip mesh
pub use rekindle_transport_veilid::BroadcastManager;
pub use rekindle_transport_veilid::gossip::OnlineMember;
pub use rekindle_transport_veilid::{DedupCache, GossipMesh, LamportClock};

// Mesh lifecycle
pub use rekindle_transport_veilid::MeshManager;

// Bulk file transfer
pub use rekindle_transport_veilid::bulk_transfer::{
    BulkSender, TYPEID_BULK_TRANSFER, TransferDirection, TransferError as BulkTransferError,
    TransferFrame, TransferProgress, TransferRegistry, TransferStatus,
};

// Observable shared state
pub use rekindle_transport_veilid::{
    AttachmentState, SharedState, TransportNotification, TransportSnapshot,
};

// Error taxonomy
pub use rekindle_transport_veilid::VeilidTransportError;
