//! Reconciliation loop: periodic and watch-triggered rounds with
//! credit-bounded concurrent fan-out across peers.
//!
//! Peers come from a `kappa_reconcile::PeerSource` as `PeerInfo`: the
//! identity (`id`, a `Kappa` derived from the peer's key) is what the loop
//! compares against its own to skip itself; the locator (`address`) is
//! what the transport is called with. The transport is the one-call
//! `kappa_reconcile::ReconcileTransport`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use kappa_reconcile::{PeerInfo, PeerSource, ReconcileTransport};
use kappa_store::ExecutionStore;
use kappa_store::time::Clock;
use kappa_store::traits::{BlobStore, EpochStore, NamespaceStore, TagStore};
use kappa_types::kappa::Kappa;
use kappa_types::page::{NamespaceFilter, PageRequest};

use super::peer::reconcile_peer;
use super::report::{PeerPhase, PeerReconcileOutcome, ReconcileReport};
use super::{MAX_CONCURRENT_PEERS, PEER_TIMEOUT};

pub struct ReconcileLoop<T: ?Sized, S: ?Sized> {
    transport: Arc<T>,
    store: Arc<S>,
    clock: Arc<dyn Clock>,
    self_id: Kappa,
    interval_secs: u64,
    peer_timeout: Duration,
    max_concurrent: usize,
}

impl<T, S> ReconcileLoop<T, S>
where
    T: ReconcileTransport + ?Sized + 'static,
    S: NamespaceStore
        + TagStore
        + EpochStore
        + BlobStore
        + ExecutionStore
        + Send
        + Sync
        + ?Sized
        + 'static,
{
    pub fn new(
        transport: Arc<T>,
        store: Arc<S>,
        clock: Arc<dyn Clock>,
        self_id: Kappa,
        interval_secs: u64,
    ) -> Self {
        Self {
            transport,
            store,
            clock,
            self_id,
            interval_secs,
            peer_timeout: PEER_TIMEOUT,
            max_concurrent: MAX_CONCURRENT_PEERS,
        }
    }

    #[must_use]
    pub const fn with_peer_timeout(mut self, timeout: Duration) -> Self {
        self.peer_timeout = timeout;
        self
    }

    #[must_use]
    pub const fn with_max_concurrent(mut self, max: usize) -> Self {
        self.max_concurrent = if max == 0 { 1 } else { max };
        self
    }

    /// Run one reconciliation round against every healthy peer that is
    /// not this node, concurrently up to `max_concurrent` at once.
    pub async fn reconcile_once(&self, peers: &[PeerInfo]) -> ReconcileReport {
        let start = Instant::now();
        let mut report = ReconcileReport {
            peers_contacted: 0,
            peers_skipped: 0,
            peers_failed: 0,
            namespaces_reconciled: 0,
            total_tags_pulled: 0,
            total_tags_applied: 0,
            total_tags_skipped: 0,
            total_pull_pages: 0,
            elapsed: Duration::ZERO,
            peer_outcomes: Vec::with_capacity(peers.len()),
        };

        let ns_list = match self
            .store
            .namespace_list(&NamespaceFilter::default(), &PageRequest::first(10_000))
        {
            Ok(page) => page.items,
            Err(e) => {
                warn!(error = %e, "failed to list namespaces for reconciliation");
                report.elapsed = start.elapsed();
                return report;
            }
        };

        if ns_list.is_empty() {
            report.elapsed = start.elapsed();
            return report;
        }

        let mut join_set = JoinSet::new();
        let mut pending = 0usize;

        for peer in peers {
            if peer.id == self.self_id || !peer.healthy || !self.transport.is_operational() {
                report.peers_skipped += 1;
                report.peer_outcomes.push(PeerReconcileOutcome::begin(
                    peer.address.clone(),
                    PeerPhase::Skipped,
                ));
                continue;
            }

            // Credit-bounded concurrency: drain a completed task before spawning
            while pending >= self.max_concurrent {
                if let Some(result) = join_set.join_next().await {
                    pending -= 1;
                    match result {
                        Ok(outcome) => Self::accumulate_outcome(&mut report, outcome),
                        Err(e) => {
                            warn!(error = %e, "peer reconciliation task panicked");
                            report.peers_failed += 1;
                        }
                    }
                }
            }

            let transport = Arc::clone(&self.transport);
            let store = Arc::clone(&self.store);
            let clock = Arc::clone(&self.clock);
            let address = peer.address.clone();
            let peer_timeout = self.peer_timeout;
            let ns_list_clone: Vec<_> = ns_list
                .iter()
                .map(|ns| (ns.name.clone(), ns.ns.clone()))
                .collect();

            join_set.spawn(async move {
                reconcile_peer(
                    transport.as_ref(),
                    store,
                    clock,
                    &address,
                    &ns_list_clone,
                    peer_timeout,
                )
                .await
            });
            pending += 1;
        }

        while let Some(result) = join_set.join_next().await {
            match result {
                Ok(outcome) => Self::accumulate_outcome(&mut report, outcome),
                Err(e) => {
                    warn!(error = %e, "peer reconciliation task panicked");
                    report.peers_failed += 1;
                }
            }
        }

        report.elapsed = start.elapsed();
        report
    }

    fn accumulate_outcome(report: &mut ReconcileReport, outcome: PeerReconcileOutcome) {
        match outcome.phase {
            PeerPhase::Applied | PeerPhase::Comparing => {
                report.peers_contacted += 1;
                report.namespaces_reconciled += outcome.namespaces_divergent;
            }
            PeerPhase::Failed => {
                report.peers_contacted += 1;
                report.peers_failed += 1;
            }
            PeerPhase::Skipped | PeerPhase::Probing | PeerPhase::Pulling => {
                report.peers_contacted += 1;
            }
        }
        report.total_tags_pulled += outcome.tags_pulled;
        report.total_tags_applied += outcome.tags_applied;
        report.total_tags_skipped += outcome.tags_skipped;
        report.total_pull_pages += outcome.pull_pages;
        report.peer_outcomes.push(outcome);
    }

    /// Spawn the background reconciliation loop.
    ///
    /// Runs a reconciliation round on two triggers:
    ///   1. Periodic tick at interval_secs
    ///   2. Immediate trigger from reconcile_trigger_rx when a DHT
    ///      RecordChange event fires for a watched epoch root record
    ///
    /// Both triggers run the same reconcile_once against all healthy peers.
    /// The immediate trigger resets the periodic interval so a tick that
    /// fires right after a triggered round does not run redundantly.
    pub fn spawn(
        self: Arc<Self>,
        peer_source: Arc<dyn PeerSource>,
        mut shutdown_rx: tokio::sync::mpsc::Receiver<()>,
        mut reconcile_trigger_rx: tokio::sync::mpsc::Receiver<String>,
    ) -> tokio::task::JoinHandle<()> {
        let interval_secs = self.interval_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                let trigger_source;
                tokio::select! {
                    _ = interval.tick() => {
                        trigger_source = "periodic";
                    }
                    record_key = reconcile_trigger_rx.recv() => {
                        match record_key {
                            Some(key) => {
                                trigger_source = "watch";
                                info!(
                                    record_key = key.as_str(),
                                    "epoch root DHT change detected, running immediate reconciliation"
                                );
                                interval.reset();
                            }
                            None => {
                                debug!("reconcile trigger channel closed");
                                continue;
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("reconciliation loop shutting down");
                        break;
                    }
                }

                let peers = peer_source.peers();
                let report = self.reconcile_once(&peers).await;
                if report.total_tags_applied > 0 || report.peers_failed > 0 {
                    info!(
                        trigger = trigger_source,
                        peers_contacted = report.peers_contacted,
                        peers_failed = report.peers_failed,
                        namespaces = report.namespaces_reconciled,
                        tags_applied = report.total_tags_applied,
                        tags_skipped = report.total_tags_skipped,
                        pages = report.total_pull_pages,
                        elapsed_ms = report.elapsed.as_millis(),
                        "reconciliation round complete"
                    );
                }
            }
        })
    }
}
