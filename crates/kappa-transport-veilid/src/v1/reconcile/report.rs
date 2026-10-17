//! Reconciliation outcomes.

use std::time::Duration;

/// Per-peer outcome within a reconciliation round.
#[derive(Debug, Clone)]
pub struct PeerReconcileOutcome {
    pub peer_id: String,
    pub phase: PeerPhase,
    pub namespaces_compared: u32,
    pub namespaces_divergent: u32,
    pub tags_pulled: u32,
    pub tags_applied: u32,
    pub tags_skipped: u32,
    pub pull_pages: u32,
    pub elapsed: Duration,
    pub errors: Vec<String>,
}

impl PeerReconcileOutcome {
    /// Outcome of a peer before any work.
    pub(super) const fn begin(peer_id: String, phase: PeerPhase) -> Self {
        Self {
            peer_id,
            phase,
            namespaces_compared: 0,
            namespaces_divergent: 0,
            tags_pulled: 0,
            tags_applied: 0,
            tags_skipped: 0,
            pull_pages: 0,
            elapsed: Duration::ZERO,
            errors: Vec::new(),
        }
    }
}

/// Reconciliation lifecycle phase per peer.
/// Analogous to IPC ConnectionPhase: explicit, logged, exhaustive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerPhase {
    /// Checking circuit breaker, resolving route.
    Probing,
    /// Exchanging epoch roots, comparing state.
    Comparing,
    /// Pulling divergent tags.
    Pulling,
    /// Tags applied to local store.
    Applied,
    /// Reconciliation failed for this peer.
    Failed,
    /// Peer was skipped (circuit open, not healthy, is self).
    Skipped,
}

/// Full reconciliation round report.
#[derive(Debug, Clone)]
pub struct ReconcileReport {
    pub peers_contacted: u32,
    pub peers_skipped: u32,
    pub peers_failed: u32,
    pub namespaces_reconciled: u32,
    pub total_tags_pulled: u32,
    pub total_tags_applied: u32,
    pub total_tags_skipped: u32,
    pub total_pull_pages: u32,
    pub elapsed: Duration,
    pub peer_outcomes: Vec<PeerReconcileOutcome>,
}
