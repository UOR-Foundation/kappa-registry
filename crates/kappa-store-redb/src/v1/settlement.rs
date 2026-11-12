//! Settlement: deriving the registry's projections from namespace epochs.
//!
//! A publication is complete, and acknowledged, when the namespace
//! database committed. Settlement follows asynchronously: it reads each
//! admitted epoch from the namespace database in bounded steps
//! (`settlement_ledger`), stages its effects as versions of the registry's
//! projections under one settlement attempt (`settlement_apply`,
//! `projection_stage`), and once the epoch's ledger and authority are
//! verified completes the attempt together with the namespace's checkpoint
//! (`SETTLED`) in one short registry transaction. A checkpoint therefore
//! never precedes its effects, readers see an epoch's projections whole or
//! not at all (`projection`), and an attempt interrupted by an error or a
//! restart is abandoned for a new one whose versions alone can complete.
//!
//! Every trigger of settlement (recovery and explicit maintenance through
//! `settle_namespace`, a retirement through the same, and admission at its
//! namespace's epoch ceiling through `relieve_epoch_pressure`) runs the one
//! consuming epoch operation ([`PersistentStore::settle_epoch_in`]) under
//! the instance's [`SettlementAttempt`], acquired before the checkpoint is
//! observed. Only a commit known to have happened releases an epoch's
//! ownership; a checkpoint authorizes a release, a discharge or a reduction
//! of admitted backlog only when established (`settlement_pending`). No
//! publication waits on a registry writer or settlement attempt held
//! elsewhere: admission takes both without waiting, and is refused at its
//! ceiling when either is held.
//!
//! Discovery is durable and proportional to the unsettled population, not
//! the namespace population: before its commit, under its writer gate, a
//! publication creates `settlement/pending/{instance}` (file and directory
//! entry synced); settlement removes the entry only while holding the gate
//! itself and after confirming the checkpoint equals the head, so a commit
//! between the two cannot be forgotten. The entry is created before the
//! commit, so a crash after the commit leaves it in place; a crash before
//! leaves a spurious entry that settles to nothing and is removed. Every
//! entry, checkpoint and projected locator names the storage instance
//! (`storage_instance`), so a recreated namespace is never settled against
//! an earlier instance's checkpoint.
//!
//! Protection across the gap between commit and settlement:
//!
//! - while the process lives, the pins the publishing execution held are
//!   parked on the controller keyed by epoch number and released when that
//!   epoch settles, so an allocation admitted but not yet projected is
//!   never unprotected, and its identities are registered for discovery
//!   (`unsettled_index`); a namespace at `max_unsettled_epochs` unsettled
//!   epochs is admitted only once its admission settles enough of them in
//!   one bounded attempt, and any publication whose pins would exceed the
//!   node-wide `unsettled` budget of entries and bytes is refused
//!   (backpressure, never discard);
//! - after a restart those pins and registrations are gone, so recovery
//!   (`settlement_recovery`) reconstructs them in bounded steps: opening
//!   performs one step and returns; until the obligations present at open
//!   are enumerated, discovery is incomplete and the unsettled pool is
//!   closed; each obligation found is settled, reconstructed (measured
//!   debt and registered identities), or held unresolved with its own
//!   closing charge and discovery gap (`RecoveryObligations`). Reclamation
//!   does not wait on any of this: it is decided per allocation by the
//!   installing instance's own committed rows (`content_reclaim`), so an
//!   unsettled or unresolved instance protects exactly its own
//!   allocations.
//!
//! The head a namespace is settled to is read from its database
//! (`EPOCH_CURRENT`, the one source of the epoch number); maintenance takes
//! the namespace's writer gate only to remove its pending entry, never to
//! apply effects. Admission pressure applies effects under the gate its own
//! publication already holds.
//!
//! Projections settled here (`projection::Family`): the content catalog,
//! allocation ownership, epoch root locators, control-plane routing, the
//! directory records and the identity projections. Every row an epoch
//! installed is projected, the records the seal and the executions produced
//! included, so an identity-only read locates every admitted record and no
//! committed external record is left without a settled owner for the
//! inventory to reclaim. A retirement's allocation is reclaimed when
//! compaction folds its completed owner tombstone (`projection_compact`),
//! subject to pins and a claim, and by the inventory sweep otherwise.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use kappa_store::StoreError;
use kappa_store::work::Meter;

use crate::PersistentStore;
use crate::error::CommitFailure;
use crate::projection_stage::{STAGED_BYTES, counter};
use crate::registry::RegistryWrite;
use crate::storage::{NamespaceController, NamespaceStorage};
use crate::storage_instance::StorageInstance;
use crate::tables::PROJECTION_COUNTERS;
use crate::unsettled::{Charge, Closure, UnsettledBudget};
use crate::unsettled_index::Registration;

#[path = "settlement_apply.rs"]
mod apply;
#[path = "settlement_cursors.rs"]
mod cursors;
#[path = "settlement_driver.rs"]
mod driver;
#[path = "settlement_ledger.rs"]
mod ledger;
#[path = "settlement_pending.rs"]
mod pending;
#[path = "settlement_recovery.rs"]
mod recovery;
#[path = "settlement_release.rs"]
mod release;
#[path = "settlement_stage.rs"]
mod stage;
#[path = "settlement_visits.rs"]
mod visits;
#[path = "settlement_work.rs"]
mod work;

#[cfg(test)]
#[path = "settlement_slice_tests.rs"]
mod slice_tests;

#[cfg(test)]
#[path = "settlement_pressure_tests.rs"]
mod pressure_tests;

pub use cursors::EpochCursors;
pub(crate) use pending::{MAX_CHECKPOINT_BYTES, decode_checkpoint};
pub use recovery::Recovery;
pub use release::ReleaseGrant;
#[cfg(test)]
pub(crate) use work::EPOCH_SIGNATURES;
pub use work::SettlementLimits;
pub(crate) use work::{default_preparation_bytes, element_preparation_bytes};

use apply::Apply;
use cursors::{EpochRead, Purpose};

/// Why settlement stopped without advancing an epoch: each is a resource
/// unavailable now, never a failure of the epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettlementStop {
    /// The work allowance does not admit the next unit.
    Budget,
    /// Every epoch cursor of the store is held.
    CursorCapacity,
    /// Every namespace activity of the store is held.
    ActivityCapacity,
    /// Projection staging has no headroom for one more ledger element
    /// until compaction folds completed epochs.
    StagingCapacity,
    /// Another transaction holds the registry writer.
    RegistryBusy,
    /// Another settlement attempt holds the instance.
    AttemptBusy,
    /// Another compaction step holds the compaction cursor.
    CompactionBusy,
    /// A registry commit of this handle has an unknown outcome: no
    /// settlement advances on this handle until a reopen recovers what
    /// persisted.
    RegistryRecoveryRequired,
}

impl std::fmt::Display for SettlementStop {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Budget => "the work allowance is spent",
            Self::CursorCapacity => "every settlement cursor is held",
            Self::ActivityCapacity => "every namespace activity is held",
            Self::StagingCapacity => "projection staging is full until compaction folds it",
            Self::RegistryBusy => "the registry writer is held",
            Self::AttemptBusy => "another settlement attempt holds the namespace",
            Self::CompactionBusy => "another compaction step holds the compaction cursor",
            Self::RegistryRecoveryRequired => {
                "a registry commit's outcome is unknown; reopen the store to recover it"
            }
        })
    }
}

/// What one run of the consuming epoch operation did to its epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EpochStep {
    /// The epoch's projections and checkpoint committed, and its parked
    /// ownership is released.
    Completed,
    /// Part of the epoch was read and staged, committed with its cursor's
    /// position; the resource named stopped the next element (the meter,
    /// or staging without room for the element's versions).
    Partial(SettlementStop),
    /// Nothing was read: the resource named was unavailable.
    Deferred(SettlementStop),
}

/// The one settlement attempt advancing an instance's checkpoint: held
/// from before the checkpoint is observed until what the attempt settled
/// is released. Acquired without waiting; constructed only here, so the
/// consuming epoch operation, which requires one, is reachable only under
/// it.
pub(crate) struct SettlementAttempt {
    controller: Arc<NamespaceController>,
}

impl SettlementAttempt {
    /// The attempt of `controller`'s instance, or `None` while another
    /// holds it.
    fn try_acquire(controller: &Arc<NamespaceController>) -> Option<Self> {
        controller
            .settlement_running
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .ok()?;
        Some(Self {
            controller: Arc::clone(controller),
        })
    }

    pub(crate) const fn controller(&self) -> &Arc<NamespaceController> {
        &self.controller
    }
}

impl Drop for SettlementAttempt {
    fn drop(&mut self) {
        self.controller
            .settlement_running
            .store(false, Ordering::Release);
    }
}

/// A storage instance recovery found holding pre-restart unsettled
/// ownership it has not yet settled: what accounts for that ownership and
/// what makes its identities discoverable.
///
/// While `registered` is false the instance is a discovery gap and its
/// ownership is held by `unmeasured`, the closing charge of ownership not
/// yet measured (`UnsettledBudget::unmeasured`): storage missing or
/// unreadable (`reason`), or a reconstruction in progress. A
/// reconstruction measures and registers bounded slices of the unsettled
/// epochs (`next_epoch` onwards, up to the `head` captured when it began;
/// the instance admits no execution meanwhile, so the head does not move),
/// accumulating `debts` and `registrations`; reaching the head drops the
/// closing charge and sets `registered`, in one update under the
/// obligations lock. Settlement reaching the head discharges the whole
/// obligation.
///
/// `releasing` is set while a [`ReleaseGrant`] for the instance exists: the
/// governed release that ends the obligation's closure publishes through
/// it, one at a time.
pub struct Obligation {
    pub(crate) origin: Origin,
    pub(crate) debts: Vec<Charge>,
    pub(crate) unmeasured: Option<Charge>,
    pub(crate) registrations: Vec<Registration>,
    pub(crate) registered: bool,
    pub(crate) next_epoch: u64,
    pub(crate) head: u64,
    /// External entries and bytes measured so far of `next_epoch`, read
    /// across slices; a measured debt only once the epoch is verified.
    pub(crate) measured: (u64, u64),
    pub(crate) reason: String,
    pub(crate) releasing: bool,
}

/// What durable record an obligation answers for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// The instance's pending marker: committed epochs may be unsettled.
    Marker,
    /// The instance's creation intent: storage a creation left may remain.
    Intent,
}

impl Obligation {
    /// An obligation not yet measured or registered.
    const fn unresolved(origin: Origin, unmeasured: Charge, reason: String) -> Self {
        Self {
            origin,
            debts: Vec::new(),
            unmeasured: Some(unmeasured),
            registrations: Vec::new(),
            registered: false,
            next_epoch: 0,
            head: 0,
            measured: (0, 0),
            reason,
            releasing: false,
        }
    }
}

/// Recovery's obligations by storage instance, with the number not yet
/// registered and whether the enumeration of obligations present at open
/// is still running, kept together under one short lock so discovery
/// coverage is one coherent read and no obligation is visited by a lookup.
/// Filesystem and database work happens outside this lock; it is taken
/// only to install, update or remove completed records.
pub struct RecoveryObligations {
    by_instance: BTreeMap<StorageInstance, Obligation>,
    unregistered: usize,
    enumerating: bool,
}

impl Default for RecoveryObligations {
    /// Enumeration running: until recovery has visited every obligation
    /// present at open, discovery is incomplete.
    fn default() -> Self {
        Self {
            by_instance: BTreeMap::new(),
            unregistered: 0,
            enumerating: true,
        }
    }
}

impl RecoveryObligations {
    /// Hold `instance` as an unresolved obligation from `origin`: its
    /// closing charge, taken from `budget` for this instance, and the
    /// record appear together under the caller's lock. The one place an
    /// unresolved obligation is created.
    pub(crate) fn hold_unresolved(
        &mut self,
        budget: &Arc<UnsettledBudget>,
        instance: StorageInstance,
        origin: Origin,
        reason: String,
    ) -> Result<(), StoreError> {
        let unmeasured = budget.unmeasured(Closure::Obligation(instance))?;
        self.insert(instance, Obligation::unresolved(origin, unmeasured, reason));
        Ok(())
    }

    /// Record `obligation` for `instance`, replacing an earlier record of
    /// it.
    fn insert(&mut self, instance: StorageInstance, obligation: Obligation) {
        if !obligation.registered {
            self.unregistered += 1;
        }
        if let Some(previous) = self.by_instance.insert(instance, obligation) {
            self.release(&previous);
        }
    }

    /// Discharge the obligation of `instance`, returning its record.
    pub(crate) fn remove(&mut self, instance: &StorageInstance) -> Option<Obligation> {
        let removed = self.by_instance.remove(instance)?;
        self.release(&removed);
        Some(removed)
    }

    const fn release(&mut self, obligation: &Obligation) {
        if !obligation.registered {
            self.unregistered -= 1;
        }
    }

    /// Apply `update` to the obligation of `instance`, keeping the count of
    /// unregistered obligations exact. `None` when there is none.
    pub(crate) fn update<T>(
        &mut self,
        instance: &StorageInstance,
        update: impl FnOnce(&mut Obligation) -> T,
    ) -> Option<T> {
        let obligation = self.by_instance.get_mut(instance)?;
        let before = obligation.registered;
        let outcome = update(obligation);
        match (before, obligation.registered) {
            (false, true) => self.unregistered -= 1,
            (true, false) => self.unregistered += 1,
            _ => {}
        }
        Some(outcome)
    }

    pub(crate) fn contains(&self, instance: &StorageInstance) -> bool {
        self.by_instance.contains_key(instance)
    }

    /// Obligations whose identities are not registered.
    pub(crate) const fn unregistered(&self) -> usize {
        self.unregistered
    }

    /// Whether the enumeration of obligations present at open is running.
    pub(crate) const fn enumerating(&self) -> bool {
        self.enumerating
    }

    /// The enumeration finished: every obligation it found is recorded
    /// here, so discovery no longer depends on it.
    pub(crate) const fn finish_enumeration(&mut self) {
        self.enumerating = false;
    }
}

impl PersistentStore {
    /// Whether projection staging has any capacity left, read before a
    /// registry transaction is acquired, so a step that would only wait for
    /// compaction does not take the writer. Each element is admitted against
    /// what its own versions stage (`settlement_apply`), inside the
    /// transaction.
    pub(super) fn staging_headroom(&self) -> Result<bool, StoreError> {
        Ok(self.projection_staged()?.bytes < self.staging_capacity)
    }

    /// Advance the settlement of epoch `epoch` of `attempt`'s instance
    /// within `work`, in `txn`, the registry transaction its caller
    /// acquired: the one settlement of an epoch every trigger runs.
    ///
    /// `epoch` is the successor of the checkpoint the attempt established:
    /// settlement of an instance is sequential, and `Apply::complete`
    /// refuses any other. The effects read are staged under the epoch's
    /// attempt in progress, each element whole or not at all; once the
    /// epoch is read and verified its attempt is completed with the
    /// `SETTLED` checkpoint in the same transaction, so a reader sees all of
    /// the epoch's projections or none. Staging with no capacity left
    /// defers before anything is read; an element whose versions do not fit
    /// what is left stays pending in its cursor, and the step commits what
    /// it staged before it (`Partial`).
    ///
    /// The epoch's cursor stays checked out (`EpochReadGuard`) until the
    /// commit's outcome is known: only a known commit returns it, with its
    /// pending element and that element's retained preparation, for the
    /// next step. A read error, an abort and a commit that does not complete
    /// drop it with everything it retained, so no position or preparation
    /// ahead of what committed is ever kept; the epoch is read again under a
    /// new attempt, and its parked ownership stays. An unknown commit
    /// outcome also leaves the registry recovery-required (`Registry`), so
    /// this handle never treats the checkpoint it may have written as
    /// committed. Only a commit known to have happened raises the instance's
    /// known-settled bound and releases the epoch's ownership; an assignment
    /// that then cannot be inspected or installed leaves the controller
    /// stale, which admission refreshes or refuses, and never reports the
    /// committed epoch unsettled.
    pub(super) fn settle_epoch_in(
        &self,
        attempt: &SettlementAttempt,
        epoch: u64,
        txn: RegistryWrite,
        work: &mut dyn Meter,
    ) -> Result<EpochStep, StoreError> {
        let controller = attempt.controller();
        let instance = controller.instance;
        let staged = {
            let counters = txn
                .open_table(PROJECTION_COUNTERS)
                .map_err(crate::error::redb)?;
            counter(&counters, STAGED_BYTES)?
        };
        if staged >= self.staging_capacity {
            txn.abort()?;
            return Ok(EpochStep::Deferred(SettlementStop::StagingCapacity));
        }
        // A read error drops the guard, and with it the checked-out cursor:
        // no position ahead of what committed is kept.
        let (step, read) = {
            let mut apply = Apply::new(
                &txn,
                instance,
                epoch,
                self.staging_capacity,
                self.settlement_limits,
                &self.encoding_storage,
                &self.settlement_preparation,
            );
            let read = self.read_epoch(&instance, epoch, Purpose::Settle, work, &mut apply)?;
            // The verified epoch's time joins the durable bound of settled
            // epoch times with its checkpoint, so a restart that finds no
            // marker for it still bounds rotation by it.
            let step = match read.outcome() {
                EpochRead::Verified(root) => {
                    apply.complete(root.kappa(), work)?;
                    self.raise_settled_epoch_time_in_txn(&txn, root.timestamp_ms())?;
                    EpochStep::Completed
                }
                EpochRead::Pending(stop) => EpochStep::Partial(*stop),
                EpochRead::Deferred(stop) => EpochStep::Deferred(*stop),
            };
            (step, read)
        };
        if let EpochStep::Deferred(_) = step {
            // No cursor was opened or resumed: nothing was staged.
            txn.abort()?;
            drop(read);
            return Ok(step);
        }
        match txn.commit() {
            Ok(()) => read.committed()?,
            Err(CommitFailure::Known(error)) => {
                drop(read);
                return Err(error);
            }
            // The registry is recovery-required from this commit on: a
            // condition of the registry, not of this instance's storage, so
            // it defers rather than failing the instance. The cursor goes,
            // the parked ownership stays, and a reopen recovers what
            // persisted.
            Err(CommitFailure::Unknown(error)) => {
                drop(read);
                tracing::error!(
                    instance = %instance,
                    epoch,
                    %error,
                    "settlement commit outcome unknown; the registry requires recovery"
                );
                return Ok(EpochStep::Deferred(
                    SettlementStop::RegistryRecoveryRequired,
                ));
            }
        }
        if let EpochStep::Partial(_) = step {
            return Ok(step);
        }
        match self.settled_assignment_changed(controller, epoch, work) {
            Ok(false) => {}
            Ok(true) => {
                if let Err(error) = self.install_assignment(controller) {
                    controller.set_assignment_stale(true);
                    tracing::error!(
                        namespace = %hex::encode(controller.id),
                        epoch,
                        %error,
                        "settled assignment not installed on the open controller; refresh owed"
                    );
                }
            }
            Err(error) => {
                controller.set_assignment_stale(true);
                tracing::error!(
                    namespace = %hex::encode(controller.id),
                    epoch,
                    %error,
                    "settled assignment not inspected; refresh owed"
                );
            }
        }
        controller.raise_known_settled(epoch);
        // The parked pins, their charge on the unsettled budget and the
        // epoch's discovery registration drop together, after the
        // completed projection that replaces them is committed. Retired
        // allocations are reclaimed when compaction folds the completed
        // owner tombstones (`projection_compact`), and by the inventory
        // sweep otherwise.
        controller.release_settled(epoch);
        Ok(EpochStep::Completed)
    }

    /// Whether the completed projection of `controller`'s namespace names
    /// an assignment generation other than the one its controller serves:
    /// the epoch just completed admitted a reassignment. Read on `work`, the
    /// settlement step's meter; a refusal leaves the controller stale, as
    /// any failure to inspect does.
    fn settled_assignment_changed(
        &self,
        controller: &Arc<NamespaceController>,
        epoch: u64,
        work: &mut dyn Meter,
    ) -> Result<bool, StoreError> {
        let Some((_, generation)) =
            self.assigned_plane(&NamespaceStorage::namespace_ref(controller.id), work)?
        else {
            return Ok(false);
        };
        let held = controller
            .plane
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|(_, held)| *held);
        if held != Some(generation) {
            tracing::debug!(
                namespace = %hex::encode(controller.id),
                epoch,
                generation,
                "settled assignment differs from the controller's"
            );
            return Ok(true);
        }
        Ok(false)
    }
}
