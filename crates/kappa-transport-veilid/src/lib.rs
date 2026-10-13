#![forbid(unsafe_code)]
//! Veilid DHT transport adapter for kappa-registry federation.
//!
//! This crate adapts rekindle-transport-veilid's `TransportNode` to
//! kappa-core's `PeerTransport` and `MembershipView` traits. It does
//! NOT reimplement any Veilid functionality -- it consumes the
//! rekindle-transport-veilid crate directly.
//!
//! Architecture:
//! - `VeilidPeerTransport` wraps `Arc<TransportNode>` and implements
//!   kappa-core's sync `PeerTransport` trait by bridging to the async
//!   `Sender::send_raw` and `Caller::call_raw` methods.
//! - `VeilidMembershipView` wraps `Arc<TransportNode>` and implements
//!   kappa-core's `MembershipView` trait by reading from the
//!   `PeerRegistry` route cache.
//! - Reconciliation protocol messages are postcard-encoded with a
//!   single protocol byte prefix, sent via `Caller::call_raw`.

mod membership_view;
mod peer_transport;
pub mod reconcile;

pub use membership_view::VeilidMembershipView;
pub use peer_transport::VeilidPeerTransport;
pub use reconcile::{handle_reconcile_request, ReconcileLoop};

pub use rekindle_transport_veilid::config::SafetyConfig;
/// Re-export TransportNode and TransportConfig so consumers don't need
/// a direct dependency on rekindle-transport-veilid for node lifecycle.
pub use rekindle_transport_veilid::{TransportConfig, TransportNode};
