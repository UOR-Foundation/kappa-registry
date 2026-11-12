//! The succession graph: a constraint shared by every namespace.
//!
//! Each namespace's view holds the succession records it published. The
//! admission predicates of a link read the whole graph: an anchor has at
//! most one successor, no chain is cyclic, and none exceeds
//! `SUCCESSION_CHAIN_MAX` links (`succession_index::plan_succession_link`).
//! Two executions in different namespaces adding disjoint links can still
//! be jointly inadmissible, so admission is coordinated here, by this
//! constraint alone: an execution reserves its link under the graph's lock,
//! against the committed and reserved links of every namespace, and the
//! reservation commits or aborts with its publication.
//!
//! The depth index covers reserved links too, so a reservation pending
//! publication counts against chains through it. Abort invalidates the depth
//! index. Before the next admission, the shared planner rebuilds exact depths
//! from surviving committed and reserved links under the same graph lock.
//!
//! Every admission runs on the reserving execution's allowance: the record
//! and the held row are encoded, and a rebuild planned, under the meter the
//! execution owns, each graph lookup charged as one entry examined. Their
//! encodings are held live in the store's encoding storage while admission
//! runs; the graph keeps the record, not its bytes, so each encoding is
//! released when admission returns.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use kappa_store::succession_index::{SuccessionOutcome, plan_succession_link};
use kappa_types::canonical::bounded_canonical_bytes;
use kappa_types::capacity::CapacityPool;
use kappa_types::error::StoreError;
use kappa_types::identity::Succession;
use kappa_types::kappa::Kappa;
use kappa_types::work::{Dimension, Meter};

use super::view::NamespaceId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Reserved { attempt: u64 },
    Committed,
}

#[derive(Clone)]
struct Link {
    record: Succession,
    owner: NamespaceId,
    state: State,
}

#[derive(Default)]
struct Graph {
    /// Old anchor key bytes to its link.
    links: BTreeMap<Vec<u8>, Link>,
    /// Anchor key bytes to the longest chain ending at it.
    depth: BTreeMap<Vec<u8>, u64>,
    depth_dirty: bool,
}

/// One graph lookup, charged before it is made.
fn examined(meter: &mut dyn Meter) -> Result<(), StoreError> {
    Ok(meter.charge(Dimension::Entries, 1)?)
}

impl Graph {
    /// The successor of the link held under `anchor`, charged on `meter`.
    fn successor_of(
        &self,
        anchor: &[u8],
        meter: &mut dyn Meter,
    ) -> Result<Option<Kappa>, StoreError> {
        examined(meter)?;
        Ok(self
            .links
            .get(anchor)
            .map(|link| link.record.new_anchor.clone()))
    }

    /// Rebuild the depth index after an abort invalidated it, on `meter`,
    /// each link's encoding held in `storage` while it is planned. The
    /// rebuilt index replaces the old one only once it is complete, so a
    /// refusal leaves the index invalid and the next admission rebuilds it.
    fn refresh_depths(
        &mut self,
        meter: &mut dyn Meter,
        storage: &Arc<CapacityPool>,
    ) -> Result<(), StoreError> {
        if !self.depth_dirty {
            return Ok(());
        }
        let mut depth = BTreeMap::new();
        for link in self.links.values() {
            // Rebuild only derived depths: all surviving links remain protected
            // observations, including reservations of other executions.
            let admitted = plan_succession_link(
                &link.record,
                meter,
                storage,
                [],
                |anchor, meter| {
                    examined(meter)?;
                    Ok(depth.get(anchor).copied().unwrap_or(0))
                },
                |anchor, meter| self.successor_of(anchor, meter),
            )?;
            if let SuccessionOutcome::New(updates) = admitted.outcome {
                depth.extend(updates);
            }
        }
        self.depth = depth;
        self.depth_dirty = false;
        Ok(())
    }
}

#[derive(Default)]
pub struct SuccessionGraph {
    graph: Mutex<Graph>,
}

impl SuccessionGraph {
    // The graph is consistent after every statement, so a lock a panicking
    // thread poisoned is still usable.
    fn lock(&self) -> std::sync::MutexGuard<'_, Graph> {
        self.graph.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserve `record` for `namespace`'s execution `attempt`, on `meter`,
    /// the execution's allowance, its encodings held in `storage`. The
    /// identical record, committed or reserved by this attempt, is admitted
    /// without a change and returns false; another record for the same
    /// anchor conflicts.
    pub fn reserve(
        &self,
        record: &Succession,
        namespace: NamespaceId,
        attempt: u64,
        meter: &mut dyn Meter,
        storage: &Arc<CapacityPool>,
    ) -> Result<bool, StoreError> {
        let mut graph = self.lock();
        graph.refresh_depths(meter, storage)?;
        let key = record.old_anchor.key_bytes();
        examined(meter)?;
        let existing = graph
            .links
            .get(&key)
            .map(|link| bounded_canonical_bytes(&link.record, meter, storage))
            .transpose()?;
        let admitted = {
            let graph = &*graph;
            plan_succession_link(
                record,
                meter,
                storage,
                existing.as_ref().map(AsRef::as_ref),
                |anchor, meter| {
                    examined(meter)?;
                    Ok(graph.depth.get(anchor).copied().unwrap_or(0))
                },
                |anchor, meter| graph.successor_of(anchor, meter),
            )?
        };
        let SuccessionOutcome::New(updates) = admitted.outcome else {
            let existing = graph.links.get(&key).ok_or_else(|| {
                StoreError::Internal("idempotent succession lost its protected row".into())
            })?;
            return match existing.state {
                State::Committed => Ok(false),
                State::Reserved { attempt: held }
                    if held == attempt && existing.owner == namespace =>
                {
                    Ok(false)
                }
                State::Reserved { .. } => Err(StoreError::Conflict(
                    "an unpublished execution is admitting this succession".into(),
                )),
            };
        };
        graph.links.insert(
            key,
            Link {
                record: record.clone(),
                owner: namespace,
                state: State::Reserved { attempt },
            },
        );
        for (anchor, depth) in updates {
            let entry = graph.depth.entry(anchor).or_insert(0);
            *entry = (*entry).max(depth);
        }
        drop(graph);
        Ok(true)
    }

    /// Publication of `attempt`: its reserved links become committed.
    pub fn commit(&self, anchors: &[Kappa], namespace: NamespaceId, attempt: u64) {
        let mut graph = self.lock();
        for anchor in anchors {
            if let Some(link) = graph.links.get_mut(&anchor.key_bytes())
                && link.owner == namespace
                && link.state == (State::Reserved { attempt })
            {
                link.state = State::Committed;
            }
        }
    }

    /// Abort of `attempt`: its reserved links are removed.
    pub fn abort(&self, anchors: &[Kappa], namespace: NamespaceId, attempt: u64) {
        let mut graph = self.lock();
        for anchor in anchors {
            let key = anchor.key_bytes();
            if graph.links.get(&key).is_some_and(|link| {
                link.owner == namespace && link.state == (State::Reserved { attempt })
            }) {
                graph.links.remove(&key);
                graph.depth_dirty = true;
            }
        }
    }

    /// The committed successor of `anchor`.
    pub fn successor(&self, anchor: &Kappa) -> Option<Succession> {
        self.lock()
            .links
            .get(&anchor.key_bytes())
            .filter(|link| link.state == State::Committed)
            .map(|link| link.record.clone())
    }

    /// The committed chain starting at `anchor`, bounded by the chain limit
    /// the admission enforced.
    pub fn chain(&self, anchor: &Kappa) -> Result<Vec<Succession>, StoreError> {
        let graph = self.lock();
        kappa_store::succession_ops::walk_chain(anchor, |current| {
            Ok(graph
                .links
                .get(&current.key_bytes())
                .filter(|link| link.state == State::Committed)
                .map(|link| (link.record.new_anchor.clone(), link.record.clone())))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_types::work::{WorkLimit, WorkMeter};

    fn anchor(index: usize) -> Kappa {
        Kappa::sha256(&index.to_be_bytes())
    }

    /// Encoding storage no test exhausts.
    fn storage() -> Arc<CapacityPool> {
        Arc::new(CapacityPool::new("test encodings", u64::MAX))
    }

    /// Reserve on an allowance of its own, as an execution reserves on its.
    fn reserve(
        graph: &SuccessionGraph,
        record: &Succession,
        namespace: NamespaceId,
        attempt: u64,
    ) -> Result<bool, StoreError> {
        graph.reserve(
            record,
            namespace,
            attempt,
            &mut WorkMeter::unbounded(),
            &storage(),
        )
    }

    fn link(index: usize) -> Succession {
        Succession {
            old_anchor: anchor(index),
            new_anchor: anchor(index + 1),
            reason: kappa_types::identity::SuccessionReason::Rotation,
            effective_at_ms: 0,
            chain_anchor: None,
            prev_identifier: None,
            old_cose_signature: kappa_types::SignedPayload::empty(),
            new_cose_signature: kappa_types::SignedPayload::empty(),
        }
    }

    #[test]
    fn aborted_chain_releases_its_depth_capacity() -> Result<(), StoreError> {
        let graph = SuccessionGraph::default();
        let limit = kappa_types::identity::SUCCESSION_CHAIN_MAX;
        let anchors: Vec<_> = (0..limit).map(anchor).collect();
        for index in 0..limit {
            assert!(reserve(&graph, &link(index), [1; 16], 1)?);
        }
        assert!(matches!(
            reserve(&graph, &link(limit), [2; 16], 2),
            Err(StoreError::CapacityExceeded(_))
        ));
        graph.abort(&anchors, [1; 16], 1);
        assert!(reserve(&graph, &link(limit), [2; 16], 2)?);
        graph.commit(&[anchor(limit)], [2; 16], 2);
        assert_eq!(graph.chain(&anchor(limit))?.len(), 1);
        Ok(())
    }

    /// Admission runs on the reserving execution's allowance and the store's
    /// encoding storage: an allowance or a storage that cannot hold the
    /// record's encoding reserves nothing, and the same record then reserves
    /// on ones that can, releasing every encoding when admission returns.
    #[test]
    fn a_refused_allowance_reserves_nothing() -> Result<(), StoreError> {
        let graph = SuccessionGraph::default();
        let pool = storage();
        let mut short = WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, 0));
        assert!(matches!(
            graph.reserve(&link(0), [1; 16], 1, &mut short, &pool),
            Err(StoreError::WorkRefused(_))
        ));
        assert!(graph.lock().links.is_empty());
        let none = Arc::new(CapacityPool::new("no encodings", 0));
        assert!(matches!(
            graph.reserve(&link(0), [1; 16], 1, &mut WorkMeter::unbounded(), &none),
            Err(StoreError::CapacityExceeded(_))
        ));
        assert!(graph.lock().links.is_empty());
        let mut meter = WorkMeter::unbounded();
        assert!(graph.reserve(&link(0), [1; 16], 1, &mut meter, &pool)?);
        assert!(meter.used().get(Dimension::BytesAllocated) > 0);
        assert!(meter.used().get(Dimension::Entries) > 0);
        assert_eq!(pool.used(), 0, "the graph holds the record, not its bytes");
        Ok(())
    }

    #[test]
    fn rollback_preserves_other_reservations_and_rejects_an_overlong_rejoin()
    -> Result<(), StoreError> {
        let graph = SuccessionGraph::default();
        let limit = kappa_types::identity::SUCCESSION_CHAIN_MAX;
        let middle = limit / 2;
        for index in 0..limit {
            let attempt = if index == middle { 1 } else { 2 };
            reserve(&graph, &link(index), [1; 16], attempt)?;
        }
        // Neither a different namespace nor a different attempt can release it.
        graph.abort(&[anchor(middle)], [2; 16], 1);
        graph.abort(&[anchor(middle)], [1; 16], 3);
        assert!(matches!(
            reserve(&graph, &link(limit), [2; 16], 4),
            Err(StoreError::CapacityExceeded(_))
        ));
        graph.abort(&[anchor(middle)], [1; 16], 1);
        assert!(reserve(&graph, &link(limit), [2; 16], 4)?);
        assert!(matches!(
            reserve(&graph, &link(middle), [1; 16], 5),
            Err(StoreError::CapacityExceeded(_))
        ));
        let survivors: Vec<_> = (0..limit)
            .filter(|index| *index != middle)
            .map(anchor)
            .collect();
        graph.commit(&survivors, [1; 16], 2);
        graph.commit(&[anchor(limit)], [2; 16], 4);
        assert_eq!(graph.chain(&anchor(0))?.len(), middle);
        assert_eq!(graph.chain(&anchor(middle + 1))?.len(), limit - middle);
        Ok(())
    }
}
