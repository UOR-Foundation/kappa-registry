//! The recovery driver: bounded, resumable steps that reconstruct the
//! obligations a restart finds and settle what publications leave behind.
//!
//! State is kept across steps (`Recovery`), so no step rescans what an
//! earlier step covered. One step runs on one work meter
//! (`kappa_store::work`) and gives it to up to three parts, each under a
//! scoped share of the step (`WorkMeter::scope`) capped by
//! `settlement_work::part_cap`, so a part receives an even share and never
//! less than one indivisible unit of its work while one fits, and the last
//! part borrows what the earlier ones left unused:
//!
//! 1. obligations already found, in round-robin order, so neither a hot or
//!    unreadable instance nor discovery starves the other: an unregistered
//!    obligation of readable storage reconstructs its next slice
//!    (`reconstruct_slice`), a missing or unreadable one is classified
//!    again;
//! 2. one cycle over the durable records, advanced incrementally: recorded
//!    retirements (a bounded range read of `RETIRED`, completing any
//!    interrupted removal against exactly the retired instance), then the
//!    creation intents, then the pending markers (`instance_record`), each
//!    a directory traversal held across steps;
//! 3. compaction of the projections settlement stages
//!    (`projection_compact`), which settlement waits on once staging is
//!    full.
//!
//! The order the parts run in rotates from step to step, so each in turn
//! leads with the whole step before it and no part is stranded by the
//! others, whatever the step's limits. Every unit (a visit, a retirement
//! completion, a traversal entry, an epoch read, a compaction entry) is
//! charged or admitted on the meter before it starts, so no unit starts
//! after the deadline; a unit admitted before it is accounted whenever it
//! finishes.
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
use std::sync::Arc;

use kappa_store::StoreError;
use kappa_store::capacity::{CapacityPool, Reservation};
#[cfg(test)]
use kappa_store::work::WorkMeter;
use kappa_store::work::{Dimension, Meter};

use super::Origin;
#[cfg(test)]
use super::work::EPOCH_SIGNATURES;
use super::work::part_cap;
use crate::PersistentStore;
use crate::instance_record::{self, Kind};
use crate::projection_compact::compaction_unit;
use crate::registry::Standing;
use crate::storage_instance::StorageInstance;
use crate::unsettled::Charge;

#[cfg(test)]
#[path = "settlement_recovery_tests.rs"]
mod tests;

/// What examining one durable record or obligation costs before it starts:
/// the entry, and the storage handle its classification may open.
const VISIT: [(Dimension, u64); 2] = [(Dimension::Entries, 1), (Dimension::Handles, 1)];

/// Recorded retirements one range read of `RETIRED` takes at most.
const RETIREMENT_BATCH: u64 = 64;

/// The reason an obligation recorded for a refused record carries: the
/// truth about it, which says nothing of its storage.
const REFUSED_VISIT: &str = "discovered by recovery; its visit was refused by the step's allowance and continues from the recovery queue";

/// Where the cycle over the durable records stands.
enum Phase {
    Retirements,
    Intents,
    Markers,
    Custody,
}

/// What a traversal of the durable records yields next.
enum Entry {
    /// The traversal reached its end.
    End,
    /// The meter refused opening the traversal's next directory stream.
    Refused,
    /// An entry that names no instance, or a traversal error: examined,
    /// and the cycle is unclean.
    Unnamed,
    /// An entry naming this instance.
    Instance(StorageInstance),
}

/// The parts of a step (see the module documentation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    Queue,
    Discovery,
    Compaction,
}

/// What one recovery step did: the epochs it settled, and whether it left
/// nothing it knows of to do (its cycle over the durable records ended
/// with no obligation queued, and compaction reached the end of its log).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stepped {
    pub settled: u64,
    pub idle: bool,
}

/// Recovery's state across steps. Recovery is the store's own obligation:
/// its state is held by the store whatever any caller resumes, so committed
/// publications stay owed. The one directory stream it holds open between
/// steps is charged to its own pool of one handle for as long as it is
/// open.
pub struct Recovery {
    /// The closing charge of the ownership present at open, held until the
    /// first clean cycle has recorded every obligation individually.
    startup: Option<Charge>,
    phase: Phase,
    retired_cursor: Option<StorageInstance>,
    /// The open traversal and its charge; the stream closes before the
    /// charge is released.
    traversal: Option<(ReadDir, Reservation)>,
    /// The pool the traversal is charged to: one handle.
    traversal_pool: Arc<CapacityPool>,
    /// Whether this cycle's traversals have so far run without an error or
    /// an entry naming no instance.
    clean: bool,
    /// Steps begun: the order of a step's parts is rotated by it.
    turn: u64,
    queue: VecDeque<StorageInstance>,
    queued: BTreeSet<StorageInstance>,
    /// The one record a traversal yielded during the enumeration at open
    /// whose visit the allowance refused before responsibility for it was
    /// accepted, with the origin of the record: while it is held the
    /// traversal yields nothing further and the cycle cannot end. Cleared
    /// once an obligation answers for the instance and the queue holds it
    /// (`PersistentStore::accept_refused`); a traversal restarted by an
    /// error keeps it.
    pending: Option<(StorageInstance, Origin)>,
    #[cfg(test)]
    examined: u64,
}

impl Recovery {
    /// Recovery at open: enumeration not started, the unsettled pool closed
    /// by `startup` until it finishes.
    pub(crate) fn starting(startup: Charge) -> Self {
        Self {
            startup: Some(startup),
            phase: Phase::Retirements,
            retired_cursor: None,
            traversal: None,
            traversal_pool: Arc::new(CapacityPool::new("recovery traversal", 1)),
            clean: true,
            turn: 0,
            queue: VecDeque::new(),
            queued: BTreeSet::new(),
            pending: None,
            #[cfg(test)]
            examined: 0,
        }
    }

    /// A durable record of this cycle could not be examined (a resource it
    /// needed was unavailable): the cycle claims no completeness, so the
    /// enumeration at open does not finish over the record, which stays on
    /// disk and is visited by the next cycle. Nothing is recorded about its
    /// storage, and no obligation, debt or registration changes.
    pub(super) const fn defer(&mut self) {
        self.clean = false;
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

    /// The parts of the next step, in the order this step runs them: the
    /// queue only when something is queued, rotated by the step's turn.
    fn parts(&mut self) -> Vec<Part> {
        let mut parts = Vec::with_capacity(3);
        if !self.queue.is_empty() {
            parts.push(Part::Queue);
        }
        parts.extend([Part::Discovery, Part::Compaction]);
        let shift = usize::try_from(self.turn % parts.len() as u64).unwrap_or(0);
        parts.rotate_left(shift);
        self.turn = self.turn.wrapping_add(1);
        parts
    }
}

impl PersistentStore {
    /// One maintenance step of `limit` entries, handles and epoch reads'
    /// signatures, within the configured step's other dimensions and with
    /// no deadline. Returns the epochs settled.
    #[cfg(test)]
    pub(crate) fn settlement_step(&self, limit: u64) -> Result<u64, StoreError> {
        let signatures = limit.saturating_mul(EPOCH_SIGNATURES);
        let step = self
            .step_limit
            .with(Dimension::Entries, limit)
            .with(Dimension::Handles, limit)
            .with(Dimension::Signatures, signatures);
        let mut meter = WorkMeter::new(step);
        let stepped = self.recovery_step(&mut meter)?;
        Ok(stepped.settled)
    }

    /// One bounded recovery step on `work`; see the module documentation.
    /// Steps are serialized; lookups never wait on one.
    pub(crate) fn recovery_step(&self, work: &mut dyn Meter) -> Result<Stepped, StoreError> {
        let mut recovery = self
            .recovery
            .lock()
            .map_err(|_| StoreError::Internal("recovery state poisoned".into()))?;
        let epoch_unit = self.settlement_limits.epoch_unit();
        let parts = recovery.parts();
        let mut settled = 0;
        let mut cycle_ended = false;
        let mut compaction_complete = false;
        let compaction_unit = compaction_unit();
        for (index, part) in parts.iter().enumerate() {
            let left = (parts.len() - index) as u64;
            let unit = match part {
                Part::Compaction => &compaction_unit,
                Part::Queue | Part::Discovery => &epoch_unit,
            };
            let cap = part_cap(work, left, unit);
            let mut share = work.scope(&cap);
            match part {
                Part::Queue => self.process_queue(&mut recovery, &mut share)?,
                Part::Discovery => {
                    let (epochs, ended) = self.advance_cycle(&mut recovery, &mut share)?;
                    settled += epochs;
                    cycle_ended = ended;
                }
                Part::Compaction => {
                    // A registry commit of unknown outcome is the registry's
                    // condition: nothing is known folded, the step is not
                    // idle, and the other parts' progress stands.
                    let Standing::Ready(compacted) = self.compact_projection(&mut share)? else {
                        compaction_complete = false;
                        continue;
                    };
                    compaction_complete = compacted.complete;
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
                }
            }
        }
        Ok(Stepped {
            settled,
            idle: cycle_ended && recovery.queue.is_empty() && compaction_complete,
        })
    }

    /// Visit queued obligations on `work`, in round-robin order kept across
    /// steps. Each visit is charged its entry and handle before it starts,
    /// and runs under a share of what is left capped by `part_cap` among
    /// the visits still due this step, so one long reconstruction cannot
    /// take the whole part from the obligations behind it and no visit is
    /// given less than one epoch unit while one fits.
    fn process_queue(
        &self,
        recovery: &mut Recovery,
        work: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let waiting = recovery.queue.len();
        let unit = self.settlement_limits.epoch_unit();
        for visited in 0..waiting {
            if work.charge_all(&VISIT).is_err() {
                break;
            }
            let Some(instance) = recovery.dequeue() else {
                break;
            };
            // The obligation's origin as it was dequeued: an obligation
            // discharged elsewhere since it was queued leaves nothing to
            // visit and is not queued again.
            let Some(origin) = self.obligation_origin(&instance) else {
                continue;
            };
            let due = (waiting - visited) as u64;
            let cap = part_cap(work, due, &unit);
            let visited = {
                let mut share = work.scope(&cap);
                self.visit_obligation(&instance, recovery, &mut share)
            };
            match visited {
                Ok(true) => recovery.enqueue(instance),
                Ok(false) => {}
                // The visit's share refused its next unit. Refusal is not
                // evidence that the storage is absent or unreadable: the
                // obligation is queued again with its origin, charge, gap
                // and registrations, and whatever the visit accepted before
                // the refusal stands, as does the work it consumed. A
                // refused share says nothing of the part's own allowance,
                // so the pass continues: the next iteration's `VISIT`
                // charge decides whether another visit can start, and the
                // pass's `waiting` bound keeps a requeued instance from
                // being retried in it.
                Err(StoreError::WorkRefused(_)) => {
                    recovery.defer();
                    recovery.enqueue(instance);
                }
                Err(error) => {
                    // The dequeued obligation is queued again whatever
                    // recording its failure does: the queue never loses an
                    // instance it owned. It is recorded under the origin it
                    // was dequeued with.
                    recovery.enqueue(instance);
                    self.record_unresolved(&instance, origin, error.to_string())?;
                }
            }
        }
        Ok(())
    }

    /// Advance the cycle over the durable records on `work`. Returns the
    /// epochs settled and whether the cycle ended in this step. Every entry
    /// is charged before it is read, so none starts once the meter refuses.
    fn advance_cycle(
        &self,
        recovery: &mut Recovery,
        work: &mut dyn Meter,
    ) -> Result<(u64, bool), StoreError> {
        let mut settled = 0;
        loop {
            match recovery.phase {
                Phase::Retirements => {
                    let entries = work.remaining(Dimension::Entries).min(RETIREMENT_BATCH);
                    if entries == 0 || work.check_deadline().is_err() {
                        return Ok((settled, false));
                    }
                    let limit = usize::try_from(entries).unwrap_or(usize::MAX);
                    let cursor = recovery.retired_cursor.as_ref();
                    let batch = self.retirements_after(cursor, limit)?;
                    if batch.is_empty() {
                        recovery.retired_cursor = None;
                        recovery.phase = Phase::Intents;
                        continue;
                    }
                    for instance in batch {
                        // A completion may remove storage: none starts once
                        // the meter refuses; the rest of the batch is read
                        // again from the cursor next step.
                        if work.charge_all(&VISIT).is_err() {
                            return Ok((settled, false));
                        }
                        if let Err(error) = self.complete_retirement(&instance) {
                            tracing::warn!(instance = %instance, %error, "retirement not completed; retried next cycle");
                        }
                        recovery.retired_cursor = Some(instance);
                    }
                }
                Phase::Intents | Phase::Markers | Phase::Custody => {
                    // A refused record whose responsibility was not yet
                    // accepted is handed over before the stream yields
                    // anything more.
                    if let Some((instance, origin)) = recovery.pending {
                        if !self.accept_refused(recovery, &instance, origin, work)? {
                            return Ok((settled, false));
                        }
                        recovery.pending = None;
                    }
                    // The entry and its visit are charged before the entry
                    // is read from the stream, so an entry read is always
                    // visited.
                    if work.charge_all(&VISIT).is_err() {
                        return Ok((settled, false));
                    }
                    let entry = self.next_entry(recovery, work)?;
                    match entry {
                        Entry::Refused => return Ok((settled, false)),
                        Entry::End => {
                            if self.end_traversal(recovery)? {
                                return Ok((settled, true));
                            }
                            continue;
                        }
                        Entry::Unnamed => {}
                        Entry::Instance(instance) => {
                            match self.visit_entry(recovery, &instance, work)? {
                                Some(epochs) => settled += epochs,
                                // The part stops: a refused custody record
                                // is visited by the next cycle, and a refused
                                // record whose responsibility the allowance
                                // could not accept stays pending.
                                None => return Ok((settled, false)),
                            }
                        }
                    }
                    #[cfg(test)]
                    {
                        recovery.examined += 1;
                    }
                }
            }
        }
    }

    /// Visit the creation intent or pending marker `instance` the current
    /// traversal yielded. A failed visit records its instance as an
    /// unresolved obligation; a refused one is handled by `refused_visit`.
    /// Returns the epochs settled, or `None` when the part must stop: a
    /// custody record whose inventory the allowance refused (it stays on
    /// disk, the cycle is unclean, the next cycle visits it), or a refused
    /// record whose responsibility could not yet be accepted (it stays in
    /// `Recovery::pending`).
    fn visit_entry(
        &self,
        recovery: &mut Recovery,
        instance: &StorageInstance,
        work: &mut dyn Meter,
    ) -> Result<Option<u64>, StoreError> {
        if matches!(recovery.phase, Phase::Custody) {
            match self.inventory_custody(instance, work) {
                Ok(()) => {}
                Err(StoreError::WorkRefused(_)) => {
                    recovery.defer();
                    return Ok(None);
                }
                Err(error) => {
                    tracing::warn!(%instance, %error, "custody ownership inventory deferred");
                    recovery.defer();
                }
            }
            return Ok(Some(0));
        }
        let origin = match recovery.phase {
            Phase::Intents => Origin::Intent,
            Phase::Retirements | Phase::Markers | Phase::Custody => Origin::Marker,
        };
        let startup = recovery.startup.is_some();
        let visited = match origin {
            // The visit records its own deferral (`Recovery::defer`); this
            // traversal counts only settled epochs.
            Origin::Intent => self.visit_intent(instance, recovery, work).map(|_visit| 0),
            Origin::Marker => self.visit_marker(instance, recovery, work, startup),
        };
        match visited {
            Ok(epochs) => Ok(Some(epochs)),
            Err(StoreError::WorkRefused(_)) => self.refused_visit(recovery, instance, origin, work),
            // Evidence that could not be read: the instance is held as an
            // unresolved obligation of the record's origin and queued.
            Err(error) => {
                self.record_unresolved(instance, origin, error.to_string())?;
                recovery.enqueue(*instance);
                Ok(Some(0))
            }
        }
    }

    /// The allowance refused the visit of the record `instance` (of
    /// `origin`) the traversal yielded. Refusal is not evidence that the
    /// storage is absent or unreadable, and whatever the visit accepted
    /// before it stands, as does the work it consumed.
    ///
    /// During the enumeration at open, or when an obligation already
    /// answers for the instance, responsibility moves to the obligation
    /// queue before the traversal advances (`accept_refused`): the record
    /// carries ownership no live state of this process holds, and the
    /// queue continues the visit fairly beside every other obligation. The
    /// record is held in `Recovery::pending` until that is accepted.
    /// Otherwise the live state that wrote the record (a publication's
    /// parked pins and registrations, a creation in progress) answers for
    /// it, and the record stays on disk for the next cycle, which is
    /// unclean. Either way the traversal continues while the part's
    /// allowance admits the next entry, so one refused record does not keep
    /// discovery from the records behind it.
    fn refused_visit(
        &self,
        recovery: &mut Recovery,
        instance: &StorageInstance,
        origin: Origin,
        work: &mut dyn Meter,
    ) -> Result<Option<u64>, StoreError> {
        if recovery.startup.is_none() && self.obligation_origin(instance).is_none() {
            recovery.defer();
            return Ok(Some(0));
        }
        recovery.pending = Some((*instance, origin));
        if !self.accept_refused(recovery, instance, origin, work)? {
            return Ok(None);
        }
        recovery.pending = None;
        Ok(Some(0))
    }

    /// Accept responsibility for the refused record `instance`: an
    /// obligation already held keeps its origin, charge, gap and
    /// registrations; otherwise one entry of obligation bookkeeping is
    /// charged and an unresolved obligation of `origin` is recorded, with
    /// its own closing charge and discovery gap (`record_unresolved`). Then
    /// the queue holds the instance. `false`, with nothing recorded, when
    /// the allowance refuses that entry.
    fn accept_refused(
        &self,
        recovery: &mut Recovery,
        instance: &StorageInstance,
        origin: Origin,
        work: &mut dyn Meter,
    ) -> Result<bool, StoreError> {
        if self.obligation_origin(instance).is_none() {
            if work.charge(Dimension::Entries, 1).is_err() {
                return Ok(false);
            }
            self.record_unresolved(instance, origin, REFUSED_VISIT.into())?;
        }
        recovery.enqueue(*instance);
        Ok(true)
    }

    /// The next entry of the current phase's traversal, opening it (one
    /// storage handle, charged first) when none is open. A traversal error
    /// restarts the traversal and leaves the cycle unclean.
    fn next_entry(
        &self,
        recovery: &mut Recovery,
        work: &mut dyn Meter,
    ) -> Result<Entry, StoreError> {
        if recovery.traversal.is_none() {
            if work.charge(Dimension::Handles, 1).is_err() {
                return Ok(Entry::Refused);
            }
            // Reserved before the handle exists. One traversal is open at a
            // time, so its one-handle pool always admits it; a refusal is a
            // defect of that invariant.
            let charge = recovery
                .traversal_pool
                .reserve(1)
                .map_err(|error| StoreError::Internal(format!("recovery traversal: {error}")))?;
            let kind = match recovery.phase {
                Phase::Intents => Kind::Creating,
                Phase::Custody => Kind::Custody,
                Phase::Retirements | Phase::Markers => Kind::Pending,
            };
            let opened = kind.traversal(self.namespaces.root())?;
            let Some(stream) = opened else {
                return Ok(Entry::End);
            };
            recovery.traversal = Some((stream, charge));
        }
        let Some((traversal, _)) = recovery.traversal.as_mut() else {
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
            Some(Ok(entry))
                if matches!(recovery.phase, Phase::Custody)
                    && instance_record::is_staged(&entry) =>
            {
                Ok(Entry::Unnamed)
            }
            Some(Ok(entry)) => match instance_record::instance(&entry) {
                Ok(instance) => Ok(Entry::Instance(instance)),
                Err(error) => {
                    tracing::error!(%error, "recovery entry names no storage instance; enumeration cannot complete while it remains");
                    recovery.clean = false;
                    Ok(Entry::Unnamed)
                }
            },
        }
    }

    /// A traversal reached its end: move to the next phase. At the end of
    /// the markers, the cycle is over: the first clean cycle finishes the
    /// enumeration. Returns whether the step should stop (a cycle ended).
    fn end_traversal(&self, recovery: &mut Recovery) -> Result<bool, StoreError> {
        // A pending record keeps the traversal from yielding, so no phase
        // ends over one; reaching here with one held is a defect.
        if let Some((instance, _)) = recovery.pending {
            return Err(StoreError::Internal(format!(
                "a recovery traversal ended with {instance} pending its handoff"
            )));
        }
        recovery.traversal = None;
        match recovery.phase {
            Phase::Intents => {
                recovery.phase = Phase::Markers;
                Ok(false)
            }
            Phase::Markers => {
                recovery.phase = Phase::Custody;
                Ok(false)
            }
            Phase::Retirements | Phase::Custody => {
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
