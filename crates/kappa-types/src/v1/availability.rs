//! Blob availability soft state for multi-region deployments.
//!
//! Tracks which nodes hold copies of a given kappa. Used by
//! federation to route reads to the nearest holder and by GC
//! to avoid collecting blobs that are the last copy.

/// Announce and query blob availability across nodes.
pub trait AvailabilityIndex: Send + Sync {
    /// Announce that a node holds the given kappa.
    fn announce(&self, kappa: &str, node_id: &str);
    /// Retract availability (node no longer holds the kappa).
    fn retract(&self, kappa: &str, node_id: &str);
    /// List node identifiers that have announced holding this kappa.
    fn holders(&self, kappa: &str) -> Vec<String>;
    /// Number of distinct nodes holding the kappa.
    fn holder_count(&self, kappa: &str) -> usize;
    /// Whether any node has announced this kappa.
    fn is_available(&self, kappa: &str) -> bool;
}

/// Single-node no-op implementation for testing and standalone mode.
pub struct NoOpAvailabilityIndex;

impl AvailabilityIndex for NoOpAvailabilityIndex {
    fn announce(&self, _kappa: &str, _node_id: &str) {}
    fn retract(&self, _kappa: &str, _node_id: &str) {}
    fn holders(&self, _kappa: &str) -> Vec<String> {
        Vec::new()
    }
    fn holder_count(&self, _kappa: &str) -> usize {
        0
    }
    fn is_available(&self, _kappa: &str) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standalone_index_has_no_remote_observations() {
        let index = NoOpAvailabilityIndex;
        index.announce("blob", "node");
        index.retract("blob", "node");
        assert!(index.holders("blob").is_empty());
        assert_eq!(index.holder_count("blob"), 0);
        assert!(!index.is_available("blob"));
    }
}
