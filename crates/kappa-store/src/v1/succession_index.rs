//! Admission of one succession link into a backend's successor index.
//!
//! Every anchor has at most one successor, but several anchors may succeed
//! into the same new anchor, so the index is a forest of chains that can
//! join. The store promises that every chain it admits resolves: no chain
//! holds more than `SUCCESSION_CHAIN_MAX` links and none is cyclic. A link
//! `old -> new` lengthens every chain through it to
//! `depth(old) + 1 + forward(new)`, where `depth(x)` is the longest chain
//! ending at `x` and `forward(new)` is the number of links after `new`.
//! Checking only the forward side would admit a link appended at the head
//! of a full chain, or one joining two long chains.
//!
//! Backends keep `depth` as a persisted index beside the successor records
//! and update both in the transaction that admits the link. Admission then
//! costs one depth lookup plus a forward walk bounded by the chain limit.

use kappa_types::error::StoreError;
use kappa_types::identity::{SUCCESSION_CHAIN_MAX, Succession};
use kappa_types::kappa::Kappa;

/// Depth updates for admitting `record`: `(anchor key bytes, depth)` for
/// `record.new_anchor` and every anchor after it, each the maximum of its
/// current depth and its depth through the new link.
///
/// Preconditions, checked by the caller against its own representation:
/// `record.old_anchor != record.new_anchor` and `old_anchor` has no
/// successor yet. `depth_of` returns 0 for an anchor no chain ends at;
/// `successor_of` returns the new anchor of the record indexed under an
/// anchor's key bytes.
///
/// Rejects a link whose forward chain returns to `old_anchor` and a link
/// that would make any chain longer than `SUCCESSION_CHAIN_MAX`.
pub fn plan_succession_link(
    record: &Succession,
    mut depth_of: impl FnMut(&[u8]) -> Result<u64, StoreError>,
    mut successor_of: impl FnMut(&[u8]) -> Result<Option<Kappa>, StoreError>,
) -> Result<Vec<(Vec<u8>, u64)>, StoreError> {
    let limit = u64::try_from(SUCCESSION_CHAIN_MAX)
        .map_err(|_| StoreError::Internal("succession chain limit exceeds u64".into()))?;
    let base = depth_of(&record.old_anchor.key_bytes())?;
    let mut forward = vec![record.new_anchor.key_bytes()];
    let through = |links: usize| -> Result<u64, StoreError> {
        let links = u64::try_from(links)
            .map_err(|_| StoreError::Internal("succession walk length exceeds u64".into()))?;
        base.checked_add(links)
            .ok_or_else(|| StoreError::Internal("succession depth overflow".into()))
    };
    // Each step adds one link after `new`; stop as soon as the bound is
    // crossed, so a damaged index cannot make admission walk unboundedly.
    loop {
        if through(forward.len())? > limit {
            return Err(StoreError::CapacityExceeded(format!(
                "succession chain would exceed {SUCCESSION_CHAIN_MAX} links"
            )));
        }
        let Some(current) = forward.last() else {
            return Err(StoreError::Internal(
                "succession walk lost its start".into(),
            ));
        };
        match successor_of(current)? {
            Some(next) if next == record.old_anchor => {
                return Err(StoreError::Rejected("succession would form a cycle".into()));
            }
            Some(next) => forward.push(next.key_bytes()),
            None => break,
        }
    }
    let mut updates = Vec::with_capacity(forward.len());
    for (index, key) in forward.into_iter().enumerate() {
        let candidate = through(index + 1)?;
        let depth = depth_of(&key)?.max(candidate);
        updates.push((key, depth));
    }
    Ok(updates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn key(index: u8) -> Vec<u8> {
        Kappa::sha256(&[index]).key_bytes()
    }

    fn link(old: u8, new: u8) -> Succession {
        Succession {
            old_anchor: Kappa::sha256(&[old]),
            new_anchor: Kappa::sha256(&[new]),
            reason: kappa_types::identity::SuccessionReason::Rotation,
            effective_at_ms: 0,
            chain_anchor: None,
            prev_identifier: None,
            old_cose_signature: kappa_types::SignedPayload::empty(),
            new_cose_signature: kappa_types::SignedPayload::empty(),
        }
    }

    #[derive(Default)]
    struct Index {
        successor: BTreeMap<Vec<u8>, Kappa>,
        depth: BTreeMap<Vec<u8>, u64>,
    }

    impl Index {
        fn admit(&mut self, old: u8, new: u8) -> Result<(), StoreError> {
            let record = link(old, new);
            let updates = plan_succession_link(
                &record,
                |anchor| Ok(self.depth.get(anchor).copied().unwrap_or(0)),
                |anchor| Ok(self.successor.get(anchor).cloned()),
            )?;
            self.successor.insert(key(old), record.new_anchor);
            self.depth.extend(updates);
            Ok(())
        }
    }

    #[test]
    fn head_origin_and_join_growth_share_one_bound() -> Result<(), StoreError> {
        let mut head = Index::default();
        for index in 0..64 {
            head.admit(index, index + 1)?;
        }
        assert_eq!(head.depth.get(&key(64)), Some(&64));
        assert!(matches!(
            head.admit(64, 65),
            Err(StoreError::CapacityExceeded(_))
        ));

        let mut origin = Index::default();
        for index in 1..65 {
            origin.admit(index, index + 1)?;
        }
        assert!(matches!(
            origin.admit(0, 1),
            Err(StoreError::CapacityExceeded(_))
        ));

        let mut join = Index::default();
        for index in 0..32 {
            join.admit(index, index + 1)?;
            join.admit(100 + index, 101 + index)?;
        }
        assert!(matches!(
            join.admit(32, 100),
            Err(StoreError::CapacityExceeded(_))
        ));
        // A 31-link chain joins the same 32-link chain into exactly 64.
        for index in 50..81 {
            join.admit(index, index + 1)?;
        }
        join.admit(81, 100)?;
        assert_eq!(join.depth.get(&key(132)), Some(&64));
        assert_eq!(join.depth.get(&key(100)), Some(&32));
        Ok(())
    }

    #[test]
    fn cycles_are_rejected_and_depths_take_the_longest_path() -> Result<(), StoreError> {
        let mut index = Index::default();
        index.admit(0, 1)?;
        index.admit(1, 2)?;
        assert!(matches!(index.admit(2, 0), Err(StoreError::Rejected(_))));
        // A short branch joining at 2 does not lower its depth.
        index.admit(9, 2)?;
        assert_eq!(index.depth.get(&key(2)), Some(&2));
        index.admit(2, 3)?;
        assert_eq!(index.depth.get(&key(3)), Some(&3));
        Ok(())
    }

    #[test]
    fn joins_keep_the_longest_depth_downstream() -> Result<(), StoreError> {
        let mut index = Index::default();
        for (old, new) in [(0, 1), (1, 2), (2, 3), (20, 21), (21, 3), (3, 4)] {
            index.admit(old, new)?;
        }
        // 0->1->2->3->4 is longer than 20->21->3->4.
        assert_eq!(index.depth.get(&key(3)), Some(&3));
        assert_eq!(index.depth.get(&key(4)), Some(&4));
        assert_eq!(index.depth.get(&key(21)), Some(&1));
        Ok(())
    }
}
