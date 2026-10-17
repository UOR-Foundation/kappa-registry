//! Veilid transport subsystem: node lifecycle, inbound dispatch,
//! route allocation and DHT publication, epoch root DHT publication
//! and watching, MST reconciliation with watch-driven immediate
//! triggers, federation peer seeding, and blob existence verification.

use std::sync::Arc;

use kappa_store::namespace::NamespaceRef;
use kappa_store::time::Clock;
use kappa_store::traits::KappaStore;
use kappa_store::{StoreError, publish_if_changed};
use kappa_transport_veilid::dispatch;
use kappa_transport_veilid::node::KappaNode;
use kappa_transport_veilid::reconcile::{PeerEntry, PeerSource, ReconcileLoop};
use kappa_transport_veilid::{RecordSchema, Transport};

const DHT_META_RECORD_KEY: &str = "_veilid/dht_record_key";
const DHT_META_WRITER_BYTES: &str = "_veilid/dht_writer_bytes";
const DHT_META_ROUTE_RECORD_KEY: &str = "_veilid/route_record_key";
const DHT_META_ROUTE_WRITER_BYTES: &str = "_veilid/route_writer_bytes";

/// Veilid subsystem handle. Main holds this for shutdown coordination.
pub struct VeilidHandle {
    node: Arc<KappaNode>,
    reconcile_shutdown_tx: tokio::sync::mpsc::Sender<()>,
    dispatch_handle: tokio::task::JoinHandle<()>,
    reconcile_handle: tokio::task::JoinHandle<()>,
    epoch_publish_handle: tokio::task::JoinHandle<()>,
}

impl VeilidHandle {
    /// Shut down reconciliation, epoch publication, dispatch, and the
    /// node in order. Each subsystem is stopped before the next to
    /// prevent in-flight operations against a shutting-down transport.
    pub async fn shutdown(self) {
        let _ = self.reconcile_shutdown_tx.send(()).await;
        let _ = self.reconcile_handle.await;
        self.epoch_publish_handle.abort();
        let _ = self.epoch_publish_handle.await;
        self.dispatch_handle.abort();
        let _ = self.dispatch_handle.await;
        self.node.shutdown().await;
    }

    pub fn node(&self) -> &Arc<KappaNode> {
        &self.node
    }
}

/// Peer source backed by the Veilid PeerRegistry with circuit breaker
/// health classification. Reads the runtime route cache which is seeded
/// by federation peer bootstrap and populated by route resolution during
/// reconciliation rounds.
struct RegistryPeerSource {
    node: Arc<kappa_transport_veilid::TransportNode>,
}

impl PeerSource for RegistryPeerSource {
    fn peers(&self) -> Vec<PeerEntry> {
        let registry = self.node.peers();
        let reg = registry.read();
        reg.snapshot()
            .into_iter()
            .map(|snap| PeerEntry {
                id: snap.key,
                healthy: snap.has_route && !snap.circuit_open,
            })
            .collect()
    }
}

/// Start the Veilid transport subsystem.
///
/// Constructs the node, allocates and publishes a route to DHT, spawns
/// the inbound dispatch loop with watch-driven reconciliation triggers,
/// the reconciliation loop listening on both periodic ticks and
/// immediate triggers, and the epoch root DHT publication and watch
/// setup loop.
pub async fn start_veilid<S>(
    storage_dir: String,
    namespace: String,
    insecure: bool,
    store: Arc<S>,
    clock: Arc<dyn Clock>,
    self_id: String,
    reconcile_interval_secs: u64,
) -> Result<VeilidHandle, kappa_transport_veilid::error::TransportError>
where
    S: KappaStore + ?Sized + 'static,
{
    let transport_config = kappa_transport_veilid::TransportConfig {
        namespace,
        storage_dir,
        allow_insecure_protected_store: insecure,
        ..Default::default()
    };

    let (kappa_node, inbound_rx) = KappaNode::start(transport_config).await?;

    // Allocate route and publish the route blob to a DHT record so peers
    // can discover us via RouteResolver DHT fallback on profile subkey 6.
    match kappa_node.allocate_route().await {
        Ok(route) => {
            tracing::info!(
                route_id = route.route_id.as_str(),
                blob_len = route.blob.len(),
                "veilid route allocated"
            );
            publish_route_blob(
                kappa_node.transport().as_ref(),
                store.as_ref(),
                clock.as_ref(),
                &route.blob,
            )
            .await;
        }
        Err(e) => {
            tracing::warn!(
                error = %e,
                "veilid route allocation failed, outbound-only until next refresh"
            );
        }
    }

    let kappa_node = Arc::new(kappa_node);

    // Watch-driven reconciliation channel: dispatch sends record keys
    // on this channel when a DHT RecordChange fires, the reconciliation
    // loop receives and runs an immediate round.
    let (reconcile_trigger_tx, reconcile_trigger_rx) = tokio::sync::mpsc::channel::<String>(64);

    // Spawn inbound dispatch loop
    let dispatch_store = store.clone();
    let dispatch_trigger = reconcile_trigger_tx.clone();
    let dispatch_handle = tokio::spawn(async move {
        dispatch::run_dispatch(inbound_rx, dispatch_store, dispatch_trigger).await;
    });

    // Spawn epoch root DHT publication and watch setup loop.
    // Publishes local epoch roots to DHT records so peers can detect
    // divergence via DHT read without direct app_call contact. Sets up
    // watches on those records so RecordChange events fire when peers
    // update their epoch roots, triggering immediate reconciliation.
    let epoch_store = store.clone();
    let epoch_clock = clock.clone();
    let epoch_transport = kappa_node.transport().clone();
    let epoch_publish_handle = tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(std::time::Duration::from_secs(reconcile_interval_secs));
        loop {
            interval.tick().await;
            publish_and_watch_epochs(
                epoch_transport.as_ref(),
                epoch_store.as_ref(),
                epoch_clock.as_ref(),
            )
            .await;
        }
    });

    // Spawn reconciliation loop with periodic tick and watch-driven trigger
    let (reconcile_shutdown_tx, reconcile_shutdown_rx) = tokio::sync::mpsc::channel(1);
    let transport = kappa_node.transport().clone();
    let peer_source: Arc<dyn PeerSource> = Arc::new(RegistryPeerSource {
        node: kappa_node.node_arc(),
    });

    let reconcile = Arc::new(ReconcileLoop::new(
        transport,
        store,
        clock,
        self_id,
        reconcile_interval_secs,
    ));

    let reconcile_handle =
        reconcile.spawn(peer_source, reconcile_shutdown_rx, reconcile_trigger_rx);

    tracing::info!(
        "veilid subsystem fully active: dispatch, reconciliation, epoch publication, watch-driven triggers"
    );

    Ok(VeilidHandle {
        node: kappa_node,
        reconcile_shutdown_tx,
        dispatch_handle,
        reconcile_handle,
        epoch_publish_handle,
    })
}

/// Publish the route blob to a DHT record so peers can discover this
/// node via RouteResolver's DHT fallback path. The DHT record key is
/// persisted in the system namespace metadata so it survives restarts.
async fn publish_route_blob<T, S>(transport: &T, store: &S, clock: &dyn Clock, route_blob: &[u8])
where
    T: Transport,
    S: KappaStore + ?Sized,
{
    let system_ns = match store.namespace_resolve("_system", None) {
        Ok(ns) => ns,
        Err(e) => {
            tracing::warn!(error = %e, "route publish: _system namespace not found");
            return;
        }
    };

    let (record_key, writer_bytes) = match get_or_create_dht_record(
        transport,
        store,
        clock,
        &system_ns,
        DHT_META_ROUTE_RECORD_KEY,
        DHT_META_ROUTE_WRITER_BYTES,
    )
    .await
    {
        Some(pair) => pair,
        None => return,
    };

    let record = match transport
        .open_record(&record_key, Some(&writer_bytes))
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "route publish: open record failed");
            return;
        }
    };

    match transport
        .write_record(&record, 0, route_blob, Some(&writer_bytes))
        .await
    {
        Ok(()) => {
            tracing::info!(
                key = record_key.as_str(),
                blob_len = route_blob.len(),
                "route blob published to DHT"
            );
        }
        Err(e) => {
            tracing::warn!(error = %e, "route publish: write failed");
        }
    }
}

/// For each namespace with a sealed epoch, publish the epoch root to a
/// DHT record and set up a watch on subkey 0 so RecordChange events
/// fire when peers update their epoch roots.
async fn publish_and_watch_epochs<T, S>(transport: &T, store: &S, clock: &dyn Clock)
where
    T: Transport,
    S: KappaStore + ?Sized,
{
    use kappa_store::page::{NamespaceFilter, PageRequest};

    let ns_list =
        match store.namespace_list(&NamespaceFilter::default(), &PageRequest::first(10_000)) {
            Ok(page) => page.items,
            Err(e) => {
                tracing::debug!(error = %e, "epoch publish: namespace list failed");
                return;
            }
        };

    for ns_info in &ns_list {
        let (epoch_number, root_kappa) = match store.epoch_current(&ns_info.ns) {
            Ok((n, k)) => (n, k),
            Err(_) => continue,
        };

        if epoch_number == 0 {
            continue;
        }

        let (record_key, writer_bytes) = match get_or_create_dht_record(
            transport,
            store,
            clock,
            &ns_info.ns,
            DHT_META_RECORD_KEY,
            DHT_META_WRITER_BYTES,
        )
        .await
        {
            Some(pair) => pair,
            None => continue,
        };

        let record = match transport
            .open_record(&record_key, Some(&writer_bytes))
            .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(
                    namespace = ns_info.name.as_str(),
                    error = %e,
                    "epoch publish: open record failed"
                );
                continue;
            }
        };

        let epoch_resp = kappa_transport_veilid::reconcile::EpochRootResponse {
            epoch_number,
            root_kappa: root_kappa.to_string(),
        };
        let encoded = match postcard::to_stdvec(&epoch_resp) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    namespace = ns_info.name.as_str(),
                    error = %e,
                    "epoch publish: encode failed"
                );
                continue;
            }
        };

        if let Err(e) = transport
            .write_record(&record, 0, &encoded, Some(&writer_bytes))
            .await
        {
            tracing::debug!(
                namespace = ns_info.name.as_str(),
                error = %e,
                "epoch publish: write failed"
            );
        } else {
            tracing::trace!(
                namespace = ns_info.name.as_str(),
                epoch = epoch_number,
                "epoch root published to DHT"
            );
        }

        // Watch subkey 0 so RecordChange events fire when a peer
        // updates their epoch root on this record. The dispatch loop
        // sends the record key on the reconcile trigger channel,
        // causing an immediate reconciliation round.
        match transport.watch_record(&record, &[0]).await {
            Ok(_token) => {
                tracing::trace!(
                    namespace = ns_info.name.as_str(),
                    "epoch root DHT watch active"
                );
            }
            Err(e) => {
                tracing::debug!(
                    namespace = ns_info.name.as_str(),
                    error = %e,
                    "epoch root watch setup failed"
                );
            }
        }
    }
}

/// Get the DHT record key and writer bytes for a namespace from
/// persisted metadata. Creates the record on first call and persists
/// the key and writer bytes so they survive node restarts.
async fn get_or_create_dht_record<T, S>(
    transport: &T,
    store: &S,
    clock: &dyn Clock,
    ns: &NamespaceRef,
    meta_key_record: &str,
    meta_key_writer: &str,
) -> Option<(String, Vec<u8>)>
where
    T: Transport,
    S: KappaStore + ?Sized,
{
    match (
        kappa_store::absent(store.namespace_get_meta(ns, meta_key_record)),
        kappa_store::absent(store.namespace_get_meta(ns, meta_key_writer)),
    ) {
        (Ok(Some(key_bytes)), Ok(Some(writer_bytes))) => {
            return match String::from_utf8(key_bytes) {
                Ok(key) => Some((key, writer_bytes)),
                Err(error) => {
                    tracing::warn!(
                        namespace = ns.display_name(),
                        %error,
                        "persisted DHT record key is not UTF-8"
                    );
                    None
                }
            };
        }
        (Ok(_), Ok(_)) => {}
        (Err(error), _) | (_, Err(error)) => {
            tracing::warn!(
                namespace = ns.display_name(),
                %error,
                "DHT record metadata read failed"
            );
            return None;
        }
    }

    let schema = RecordSchema::SingleWriter { subkey_count: 1 };
    let (record, writer_bytes) = match transport.create_record(schema).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::warn!(
                namespace = ns.display_name(),
                error = %e,
                "DHT record creation failed"
            );
            return None;
        }
    };

    let record_key = record.key().to_string();

    // The record stays usable for this process even when persistence fails;
    // the next start creates a fresh record.
    let persisted = persist_dht_record(
        store,
        ns,
        [
            (meta_key_record, record_key.as_bytes()),
            (meta_key_writer, writer_bytes.as_slice()),
        ],
        clock,
    );
    match persisted {
        Ok(epoch) => tracing::info!(
            namespace = ns.display_name(),
            key = record_key.as_str(),
            epoch,
            "DHT record created and persisted"
        ),
        Err(error) => tracing::warn!(
            namespace = ns.display_name(),
            %error,
            "failed to persist DHT record key and writer bytes"
        ),
    }

    Some((record_key, writer_bytes))
}

/// Persist the DHT record key and writer bytes as namespace metadata in one
/// execution. Values the namespace already holds publish nothing. Returns
/// the published epoch number, if any.
fn persist_dht_record<S: KappaStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    entries: [(&str, &[u8]); 2],
    clock: &dyn Clock,
) -> Result<Option<u64>, StoreError> {
    let published = publish_if_changed(store, ns, clock, |execution| {
        let mut changed = false;
        for (key, value) in entries {
            if execution.namespace_get_meta(key)?.as_deref() == Some(value) {
                continue;
            }
            execution.namespace_put_meta(key, value)?;
            changed = true;
        }
        Ok(changed)
    })?;
    Ok(published.map(|published| published.epoch_number))
}
