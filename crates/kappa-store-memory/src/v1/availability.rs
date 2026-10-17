//! Process-local availability observations; not authenticated GC authority.
use std::collections::BTreeSet;

use dashmap::DashMap;
use kappa_types::availability::AvailabilityIndex;

#[derive(Default)]
pub struct InMemoryAvailabilityIndex {
    index: DashMap<String, BTreeSet<String>>,
}

impl InMemoryAvailabilityIndex {
    pub fn new() -> Self {
        Self::default()
    }
}

impl AvailabilityIndex for InMemoryAvailabilityIndex {
    fn announce(&self, kappa: &str, node_id: &str) {
        self.index
            .entry(kappa.to_owned())
            .or_default()
            .insert(node_id.to_owned());
    }

    fn retract(&self, kappa: &str, node_id: &str) {
        // Removal and empty-entry cleanup share the shard lock. Releasing a
        // guard before deleting could erase a concurrent announcement.
        self.index.remove_if_mut(kappa, |_, holders| {
            holders.remove(node_id);
            holders.is_empty()
        });
    }

    fn holders(&self, kappa: &str) -> Vec<String> {
        self.index
            .get(kappa)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    fn holder_count(&self, kappa: &str) -> usize {
        self.index.get(kappa).map_or(0, |set| set.len())
    }

    fn is_available(&self, kappa: &str) -> bool {
        self.index.get(kappa).is_some_and(|set| !set.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announcements_are_sorted_and_idempotent() {
        let index = InMemoryAvailabilityIndex::new();
        index.announce("blob", "node-2");
        index.announce("blob", "node-1");
        index.announce("blob", "node-1");
        assert_eq!(index.holders("blob"), ["node-1", "node-2"]);
        assert_eq!(index.holder_count("blob"), 2);
        assert!(index.is_available("blob"));
    }

    #[test]
    fn retraction_preserves_other_holders_and_cleans_last_entry() {
        let index = InMemoryAvailabilityIndex::new();
        index.announce("blob", "node-1");
        index.announce("blob", "node-2");
        index.retract("blob", "node-1");
        assert_eq!(index.holders("blob"), ["node-2"]);
        index.retract("blob", "node-2");
        assert!(!index.is_available("blob"));
        assert_eq!(index.holder_count("blob"), 0);
        assert!(!index.index.contains_key("blob"));
        index.retract("missing", "node-1");
        assert!(index.holders("missing").is_empty());
    }
}
