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
//! publication counts against chains through it. An aborted reservation
//! leaves the depths it raised: a depth is only ever an upper bound on the
//! longest chain ending at an anchor, so the index can refuse a link a
//! precise index would admit after an abort, never admit one it should
//! refuse.

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use kappa_types::canonical::canonical_bytes;
use kappa_types::error::StoreError;
use kappa_types::identity::Succession;
use kappa_types::kappa::Kappa;

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
    /// Anchor key bytes to an upper bound of the longest chain ending at it.
    depth: BTreeMap<Vec<u8>, u64>,
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

    /// Reserve `record` for `namespace`'s execution `attempt`. The identical
    /// record, committed or reserved by this attempt, is admitted without a
    /// change and returns false; another record for the same anchor
    /// conflicts.
    pub fn reserve(
        &self,
        record: &Succession,
        namespace: NamespaceId,
        attempt: u64,
    ) -> Result<bool, StoreError> {
        if record.old_anchor == record.new_anchor {
            return Err(StoreError::Rejected(
                "succession cannot target itself".into(),
            ));
        }
        let mut graph = self.lock();
        let key = record.old_anchor.key_bytes();
        if let Some(existing) = graph.links.get(&key) {
            if canonical_bytes(&existing.record) != canonical_bytes(record) {
                return Err(StoreError::Conflict(
                    "anchor already has another succession record".into(),
                ));
            }
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
        }
        let updates = {
            let graph = &*graph;
            kappa_store::succession_index::plan_succession_link(
                record,
                |anchor| Ok(graph.depth.get(anchor).copied().unwrap_or(0)),
                |anchor| {
                    Ok(graph
                        .links
                        .get(anchor)
                        .map(|link| link.record.new_anchor.clone()))
                },
            )?
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
        let mut chain = Vec::new();
        let mut current = anchor.key_bytes();
        while let Some(link) = graph.links.get(&current) {
            if link.state != State::Committed {
                break;
            }
            if chain.len() >= kappa_types::identity::SUCCESSION_CHAIN_MAX {
                return Err(StoreError::CapacityExceeded(
                    "succession chain exceeds maximum length".into(),
                ));
            }
            current = link.record.new_anchor.key_bytes();
            chain.push(link.record.clone());
            if current == anchor.key_bytes() {
                return Err(StoreError::Internal(
                    "admitted succession chain is cyclic".into(),
                ));
            }
        }
        Ok(chain)
    }
}
