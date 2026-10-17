//! Inbound event dispatch.
//!
//! Consumes InboundEvent from the Transport's mpsc channel and routes
//! them to the appropriate handler: reconciliation requests, DHT watch
//! notifications triggering immediate reconciliation, route lifecycle,
//! and bulk transfer progress.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use rekindle_types::transport::{InboundEvent, TransportEvent};

use crate::reconcile;

/// Run the inbound event dispatch loop.
///
/// Consumes every InboundEvent from the transport's channel and routes:
///   Call with recognized protocol byte: reconciliation handler, reply via reply_tx
///   RecordChange: sends record key on reconcile_trigger_tx to trigger
///     immediate reconciliation for the namespace whose epoch root DHT
///     record changed, instead of waiting for the next periodic tick
///   Event::RouteDied: logs for operator awareness (auto-recovery via refresh)
///   TransferComplete/TransferFailed: logs transfer outcomes
///
/// The `store` parameter is the kappa store used by the reconciliation
/// request handler to serve epoch roots and tag diffs.
///
/// `reconcile_trigger_tx`: when a DHT RecordChange arrives for a watched
/// epoch root, sends the record key on this channel. The reconciliation
/// loop receives from the corresponding rx and runs an immediate round
/// for the affected namespace.
///
/// This function runs until the inbound channel closes (transport shutdown).
pub async fn run_dispatch<S>(
    mut inbound_rx: mpsc::Receiver<InboundEvent>,
    store: Arc<S>,
    reconcile_trigger_tx: mpsc::Sender<String>,
) where
    S: kappa_store::traits::KappaStore + ?Sized,
{
    info!("inbound dispatch loop started");

    while let Some(event) = inbound_rx.recv().await {
        match event {
            InboundEvent::Call { data, reply_tx, .. } => {
                let response = match reconcile::handle_reconcile_request(store.as_ref(), &data) {
                    Ok(resp) => resp,
                    Err(e) => {
                        warn!(error = %e, "reconciliation request handler failed");
                        Vec::new()
                    }
                };
                if reply_tx.send(response).is_err() {
                    debug!("reply channel closed before response sent");
                }
            }

            InboundEvent::Message { sender_key, data } => {
                let sender_display = sender_key.as_deref().unwrap_or("unknown");
                debug!(
                    sender = &sender_display[..16.min(sender_display.len())],
                    len = data.len(),
                    "inbound message, no handler registered"
                );
            }

            InboundEvent::RecordChange {
                record_key,
                subkeys,
                count,
                ..
            } => {
                info!(
                    key = &record_key[..20.min(record_key.len())],
                    subkeys = ?subkeys,
                    remaining = count,
                    "DHT record changed, triggering immediate reconciliation"
                );
                if reconcile_trigger_tx.send(record_key).await.is_err() {
                    debug!("reconcile trigger channel closed");
                }
            }

            InboundEvent::Event(transport_event) => match transport_event {
                TransportEvent::Attached => info!("transport attached to network"),
                TransportEvent::Detached => warn!("transport detached from network"),
                TransportEvent::RouteAllocated { route_id } => {
                    info!(route_id = route_id.as_str(), "route allocated");
                }
                TransportEvent::RouteDied { route_id } => {
                    warn!(
                        route_id = route_id.as_str(),
                        "route died, will re-allocate on next refresh"
                    );
                }
                TransportEvent::WatchExpired { record_key } => {
                    debug!(key = record_key.as_str(), "watch expired, needs renewal");
                }
                TransportEvent::PeerCountChanged { count } => {
                    debug!(peers = count, "peer count changed");
                }
                TransportEvent::PublicInternet { available } => {
                    if available {
                        info!("public internet reachable");
                    } else {
                        warn!("public internet not reachable");
                    }
                }
            },

            InboundEvent::TransferComplete {
                transfer_id,
                path,
                hash_match,
            } => {
                info!(
                    id = hex::encode(transfer_id),
                    path = path.as_str(),
                    verified = hash_match,
                    "bulk transfer complete"
                );
            }

            InboundEvent::TransferFailed {
                transfer_id,
                reason,
            } => {
                warn!(
                    id = hex::encode(transfer_id),
                    reason = reason.as_str(),
                    "bulk transfer failed"
                );
            }

            InboundEvent::TransferProgress {
                transfer_id,
                bytes_transferred,
                total_size,
                ..
            } => {
                debug!(
                    id = hex::encode(transfer_id),
                    progress = format!("{}/{}", bytes_transferred, total_size),
                    "transfer progress"
                );
            }

            InboundEvent::TransferOffer {
                transfer_id,
                sender_peer_key,
                filename,
                total_size,
                ..
            } => {
                info!(
                    id = hex::encode(transfer_id),
                    sender = &sender_peer_key[..16.min(sender_peer_key.len())],
                    filename = filename.as_str(),
                    size = total_size,
                    "transfer offer received"
                );
            }
        }
    }

    info!("inbound dispatch loop ended, channel closed");
}
