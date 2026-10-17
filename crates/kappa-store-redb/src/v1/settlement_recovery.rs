//! The recovery driver: bounded, resumable steps that reconstruct the
//! obligations a restart finds and settle what publications leave behind.
//!
//! State is kept across steps (`Recovery`), so no step rescans what an
//! earlier step covered. One step spends its budget on two things:
//!
//! 1. obligations already found, in round-robin order and with at most
//!    half the step's entries, so neither a hot or unreadable instance nor
//!    discovery starves the other: an unregistered obligation of readable
//!    storage reconstructs its next slice (`reconstruct_slice`), a missing
//!    or unreadable one is classified again;
//! 2. one cycle over the durable records, advanced incrementally: recorded
//!    retirements (a bounded range read of `RETIRED`, completing any
//!    interrupted removal against exactly the retired instance), then the
//!    creation intents (`creation_intent`), then the pending markers
//!    (`settlement_pending`), each a directory traversal held across steps.
//!
//! The first cycle after open is the enumeration of the obligations present
//! at open. Until it finishes, discovery is incomplete and the unsettled
//! pool is closed by the startup charge: both are released together at the
//! end of a cycle whose traversals each ran to their end without an error
//! or an entry that names no instance, after every obligation found has
//! been recorded with its own charge and gap (`RecoveryObligations`).
//!
//! Completeness of that enumeration: a pending marker present at open is
//! removed only by settlement to its instance's head under the writer gate,
//! by the proof that its instance never committed, or under a recorded
//! retirement of its instance, each of which discharges what it answered
//! for; a marker present throughout the traversal is yielded by it. Markers
//! written after open belong to publications of this process, whose
//! identities are registered before they commit, and whose settlement later
//! cycles schedule. A traversal error abandons the cycle's claim to
//! completeness: the traversal restarts, and the startup barrier stays
//! until a clean cycle. A failed visit records its instance as an
//! unresolved obligation rather than letting the traversal pass it by.

use std::collections::{BTreeSet, VecDeque};
use std::fs::ReadDir;

use kappa_store::StoreError;

use super::Origin;
use super::pending::marker_instance;
use super::work::Work;
use crate::PersistentStore;
use crate::creation_intent;
use crate::storage_instance::StorageInstance;
use crate::unsettled::Charge;

#[cfg(test)]
#[path = "settlement_recovery_tests.rs"]
mod tests;

/// The work one recovery step may do: entries of the durable records and
/// obligations visited, and the epoch reading (`Work`: mutations examined
/// and bytes read) of settlement and reconstruction.
#[derive(Clone, Copy, Debug)]
pub struct StepBudget {
    pub entries: u64,
    pub work: Work,
}

/// Where the cycle over the durable records stands.
enum Phase {
    Retirements,
    Intents,
    Markers,
}

/// What a traversal of the durable records yields next.
enum Entry {
    /// The traversal reached its end.
    End,
    /// An entry that names no instance, or a traversal error: examined,
    /// and the cycle is unclean.
    Unnamed,
    /// An entry naming this instance.
    Instance(StorageInstance),
}

/// Recovery's state across steps.
pub struct Recovery {
    /// The closing charge of the ownership present at open, held until the
    /// first clean cycle has recorded every obligation individually.
    startup: Option<Charge>,
    phase: Phase,
    retired_cursor: Option<StorageInstance>,
    traversal: Option<ReadDir>,
    /// Whether this cycle's traversals have so far run without an error or
    /// an entry naming no instance.
    clean: bool,
    /// Which class a one-unit budget goes to next: queued obligations when
    /// set, discovery otherwise. Flipped by every step that splits a
    /// one-unit budget, so neither class is starved.
    queue_turn: bool,
    queue: VecDeque<StorageInstance>,
    queued: BTreeSet<StorageInstance>,
    #[cfg(test)]
    examined: u64,
}

impl Recovery {
    /// Recovery at open: enumeration not started, the unsettled pool closed
    /// by `startup` until it finishes.
    pub(crate) const fn starting(startup: Charge) -> Self {
        Self {
            startup: Some(startup),
            phase: Phase::Retirements,
            retired_cursor: None,
            traversal: None,
            clean: true,
            queue_turn: true,
            queue: VecDeque::new(),
            queued: BTreeSet::new(),
            #[cfg(test)]
            examined: 0,
        }
    }

    /// Queue `instance` for a visit in a later step, once.
    pub(super) fn enqueue(&mut self, instance: StorageInstance) {
        if self.queued.insert(instance) {
            self.queue.push_back(instance);
        }
    }

    fn dequeue(&mut self) -> Option<StorageInstance> {
        let instance = self.queue.pop_front()?;
        self.queued.remove(&instance);
        Some(instance)
    }
}

impl PersistentStore {
    /// One bounded maintenance step: `limit` entries and `limit` mutations,
    /// within the configured step byte budget. Returns the epochs settled.
    pub(crate) fn settlement_step(&self, limit: u64) -> Result<u64, StoreError> {
        self.recovery_step(StepBudget {
            entries: limit,
            work: Work {
                mutations: limit,
                bytes: self.recovery_step_bytes,
            },
        })
    }

    /// One bounded recovery step within `budget`. Returns the epochs
    /// settled. Steps are serialized; lookups never wait on one.
    ///
    /// The budget is split between queued obligations and discovery, each
    /// class receiving its own entries, mutations and bytes; whatever a
    /// class leaves unused is not taken by the other within the step. A
    /// one-unit dimension goes to each class in turn across steps.
    /// Discovery proceeds with no work left: visits that cannot read epochs
    /// classify what they find and record it as an obligation for later
    /// steps.
    pub(crate) fn recovery_step(&self, budget: StepBudget) -> Result<u64, StoreError> {
        let mut recovery = self
            .recovery
            .lock()
            .map_err(|_| StoreError::Internal("recovery state poisoned".into()))?;
        let (mut queued, mut discovery) = Self::split(&mut recovery, budget);
        self.process_queue(&mut recovery, &mut queued)?;
        let settled = self.advance_cycle(&mut recovery, &mut discovery)?;
        // Compaction keeps its own cursor under its own lock; the recovery
        // state is not held across it.
        drop(recovery);
        // Compaction folds what settlement completed and frees the staging
        // later epochs need, within the step's entry bound.
        let limit = usize::try_from(budget.entries).unwrap_or(usize::MAX);
        let compacted = self.compact_projection(limit)?;
        if compacted.removed > 0 || compacted.reclaimed > 0 {
            tracing::debug!(
                examined = compacted.examined,
                folded = compacted.folded,
                removed = compacted.removed,
                reclaimed = compacted.reclaimed,
                complete = compacted.complete,
                "projection compaction step"
            );
        }
        Ok(settled)
    }

    /// Split `budget` between queued obligations and discovery: halves when
    /// a dimension holds two or more units, the whole unit to the class
    /// whose turn it is when it holds one, everything to discovery when
    /// nothing is queued.
    fn split(recovery: &mut Recovery, budget: StepBudget) -> (StepBudget, StepBudget) {
        if recovery.queue.is_empty() {
            return (
                StepBudget {
                    entries: 0,
                    work: Work {
                        mutations: 0,
                        bytes: 0,
                    },
                },
                budget,
            );
        }
        let to_queue = recovery.queue_turn;
        let (queued_entries, discovery_entries, single_entry) = match budget.entries {
            0 => (0, 0, false),
            1 if to_queue => (1, 0, true),
            1 => (0, 1, true),
            units => (units / 2, units - units / 2, false),
        };
        let (queued_work, discovery_work, single_work) = budget.work.split(to_queue);
        if single_entry || single_work {
            recovery.queue_turn = !recovery.queue_turn;
        }
        (
            StepBudget {
                entries: queued_entries,
                work: queued_work,
            },
            StepBudget {
                entries: discovery_entries,
                work: discovery_work,
            },
        )
    }

    /// Visit queued obligations within `remaining`, in round-robin order
    /// kept across steps. Each visit may spend at most an equal quantum of
    /// the class's work, never less than one mutation's reservation
    /// (`SettlementLimits::mutation_quantum`), so one long reconstruction
    /// cannot take the whole share from the obligations behind it and no
    /// visit is given a share too small to make progress.
    fn process_queue(
        &self,
        recovery: &mut Recovery,
        remaining: &mut StepBudget,
    ) -> Result<(), StoreError> {
        let waiting = u64::try_from(recovery.queue.len()).unwrap_or(u64::MAX);
        let shares = waiting.max(1);
        let quantum = Work {
            mutations: remaining.work.mutations.div_ceil(shares).max(1),
            bytes: remaining
                .work
                .bytes
                .div_ceil(shares)
                .max(self.settlement_limits.mutation_quantum()),
        };
        let mut visited = 0u64;
        while visited < waiting && remaining.entries > 0 {
            let Some(instance) = recovery.dequeue() else {
                break;
            };
            visited += 1;
            remaining.entries -= 1;
            let before = Work {
                mutations: quantum.mutations.min(remaining.work.mutations),
                bytes: quantum.bytes.min(remaining.work.bytes),
            };
            let mut slice = StepBudget {
                entries: 1,
                work: before,
            };
            let keep = match self.visit_obligation(&instance, recovery, &mut slice) {
                Ok(keep) => keep,
                Err(error) => {
                    self.record_unresolved(&instance, Origin::Marker, error.to_string())?;
                    true
                }
            };
            remaining.work.deduct(slice.work.spent_since(before))?;
            if keep {
                recovery.enqueue(instance);
            }
        }
        Ok(())
    }

    /// Advance the cycle over the durable records within `remaining`.
    fn advance_cycle(
        &self,
        recovery: &mut Recovery,
        remaining: &mut StepBudget,
    ) -> Result<u64, StoreError> {
        let mut settled = 0;
        while remaining.entries > 0 {
            match recovery.phase {
                Phase::Retirements => {
                    let limit = usize::try_from(remaining.entries.min(64)).unwrap_or(64);
                    let batch = self.retirements_after(recovery.retired_cursor.as_ref(), limit)?;
                    if batch.is_empty() {
                        recovery.retired_cursor = None;
                        recovery.phase = Phase::Intents;
                        continue;
                    }
                    for instance in batch {
                        remaining.entries = remaining.entries.saturating_sub(1);
                        if let Err(error) = self.complete_retirement(&instance) {
                            tracing::warn!(instance = %instance, %error, "retirement not completed; retried next cycle");
                        }
                        recovery.retired_cursor = Some(instance);
                    }
                }
                Phase::Intents | Phase::Markers => {
                    let entry = self.next_entry(recovery)?;
                    if matches!(entry, Entry::End) {
                        if self.end_traversal(recovery)? {
                            break;
                        }
                        continue;
                    }
                    remaining.entries -= 1;
                    #[cfg(test)]
                    {
                        recovery.examined += 1;
                    }
                    let Entry::Instance(instance) = entry else {
                        continue;
                    };
                    let origin = match recovery.phase {
                        Phase::Intents => Origin::Intent,
                        Phase::Retirements | Phase::Markers => Origin::Marker,
                    };
                    let startup = recovery.startup.is_some();
                    let visited = match origin {
                        Origin::Intent => self.visit_intent(&instance, recovery).map(|()| 0),
                        Origin::Marker => {
                            self.visit_marker(&instance, recovery, remaining, startup)
                        }
                    };
                    settled += match visited {
                        Ok(epochs) => epochs,
                        Err(error) => {
                            self.record_unresolved(&instance, origin, error.to_string())?;
                            recovery.enqueue(instance);
                            0
                        }
                    };
                }
            }
        }
        Ok(settled)
    }

    /// The next entry of the current phase's traversal. A traversal error
    /// restarts the traversal and leaves the cycle unclean.
    fn next_entry(&self, recovery: &mut Recovery) -> Result<Entry, StoreError> {
        if recovery.traversal.is_none() {
            recovery.traversal = match recovery.phase {
                Phase::Intents => creation_intent::traversal(self.namespaces.root())?,
                Phase::Retirements | Phase::Markers => self.pending_traversal()?,
            };
            if recovery.traversal.is_none() {
                return Ok(Entry::End);
            }
        }
        let Some(traversal) = recovery.traversal.as_mut() else {
            return Ok(Entry::End);
        };
        match traversal.next() {
            None => Ok(Entry::End),
            Some(Err(error)) => {
                tracing::warn!(%error, "recovery traversal failed; restarting it");
                recovery.traversal = None;
                recovery.clean = false;
                Ok(Entry::Unnamed)
            }
            Some(Ok(entry)) => {
                let named = match recovery.phase {
                    Phase::Intents => creation_intent::instance(&entry),
                    Phase::Retirements | Phase::Markers => marker_instance(&entry),
                };
                match named {
                    Ok(instance) => Ok(Entry::Instance(instance)),
                    Err(error) => {
                        tracing::error!(%error, "recovery entry names no storage instance; enumeration cannot complete while it remains");
                        recovery.clean = false;
                        Ok(Entry::Unnamed)
                    }
                }
            }
        }
    }

    /// A traversal reached its end: move to the next phase. At the end of
    /// the markers, the cycle is over: the first clean cycle finishes the
    /// enumeration. Returns whether the step should stop (a cycle ended).
    fn end_traversal(&self, recovery: &mut Recovery) -> Result<bool, StoreError> {
        recovery.traversal = None;
        match recovery.phase {
            Phase::Intents => {
                recovery.phase = Phase::Markers;
                Ok(false)
            }
            Phase::Retirements | Phase::Markers => {
                if recovery.clean && recovery.startup.is_some() {
                    // Every obligation this cycle found is recorded with
                    // its own charge and gap; only then are the startup
                    // barrier and charge released, in that order.
                    self.finish_enumeration();
                    drop(recovery.startup.take());
                    self.set_settlement_pass(true)?;
                    tracing::info!(
                        "recovery enumeration of the obligations present at open finished"
                    );
                }
                recovery.phase = Phase::Retirements;
                recovery.clean = true;
                Ok(true)
            }
        }
    }

    /// Entries of the durable records recovery examined since open.
    #[cfg(test)]
    pub(crate) fn recovery_examined(&self) -> Result<u64, StoreError> {
        Ok(self
            .recovery
            .lock()
            .map_err(|_| StoreError::Internal("recovery state poisoned".into()))?
            .examined)
    }
}
