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
//! No request waits on the registry writer.
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
//!   (`unsettled_index`); admission refuses a namespace holding
//!   `max_unsettled_epochs` parked epochs, and any publication whose pins
//!   would exceed the node-wide `unsettled` budget of entries and bytes
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
//! (`EPOCH_CURRENT`, the one source of the epoch number); settlement takes
//! the namespace's writer gate only to remove its pending entry, never to
//! apply effects, so it never delays publication.
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

use kappa_store::StoreError;

use crate::PersistentStore;
use crate::storage::{NamespaceController, NamespaceStorage};
use crate::storage_instance::StorageInstance;
use crate::unsettled::{Charge, Closure, UnsettledBudget};
use crate::unsettled_index::Registration;

#[path = "settlement_apply.rs"]
mod apply;
#[path = "settlement_cbor.rs"]
mod cbor;
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

pub use cursors::EpochCursors;
pub use recovery::{Recovery, StepBudget};
pub use release::ReleaseGrant;
pub use work::{SettlementLimits, Work};

use apply::Apply;
use cursors::Purpose;

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
    /// Advance the settlement of epoch `epoch` of `controller`'s instance
    /// within `work`, in one registry write transaction: the effects read
    /// in this step are staged under the epoch's attempt in progress, and
    /// once the epoch is read and verified its attempt is completed with
    /// the `SETTLED` checkpoint in the same transaction, so a reader sees
    /// all of the epoch's projections or none. `None` while the epoch is
    /// not yet verified; `Some(true)` once completed.
    ///
    /// The epoch must follow the checkpoint: settlement of an instance is
    /// sequential. A transaction that fails to commit discards the epoch's
    /// cursor, whose position would otherwise be ahead of what it staged;
    /// the epoch is read again under a new attempt.
    pub(super) fn settle_epoch(
        &self,
        controller: &Arc<NamespaceController>,
        epoch: u64,
        work: &mut Work,
    ) -> Result<Option<bool>, StoreError> {
        let instance = controller.instance;
        // A step that could not stage one more mutation waits for
        // compaction to fold completed epochs, rather than failing midway
        // and losing its cursor.
        let staged = self.projection_staged()?;
        if staged
            .bytes
            .checked_add(self.settlement_limits.mutation_quantum())
            .is_none_or(|needed| needed > self.staging_capacity)
        {
            tracing::debug!(
                instance = %instance,
                epoch,
                staged_bytes = staged.bytes,
                staged_entries = staged.entries,
                capacity = self.staging_capacity,
                "settlement waits for projection compaction"
            );
            return Ok(None);
        }
        let txn = self.registry.begin_write().map_err(crate::error::redb)?;
        let completed = {
            let mut apply = Apply::new(&txn, instance, epoch, self.staging_capacity);
            let read = self.read_epoch(&instance, epoch, Purpose::Settle, work, &mut apply);
            // The verified epoch's time joins the durable bound of settled
            // epoch times with its checkpoint, so a restart that finds no
            // marker for it still bounds rotation by it.
            match read.and_then(|root| {
                root.map(|root| {
                    apply.complete(root.kappa())?;
                    self.raise_settled_epoch_time_in_txn(&txn, root.timestamp_ms())
                })
                .transpose()
            }) {
                Ok(completed) => completed.is_some(),
                Err(error) => {
                    self.forget_cursor(&instance, Purpose::Settle);
                    return Err(error);
                }
            }
        };
        if let Err(error) = txn.commit() {
            self.forget_cursor(&instance, Purpose::Settle);
            return Err(crate::error::redb(error));
        }
        if !completed {
            return Ok(None);
        }
        if self.settled_assignment_changed(controller, epoch)? {
            // A settled reassignment the controller could not install
            // leaves it stale (`install_assignment` marks it); the epoch
            // is settled regardless, and the next admission refreshes or
            // refuses.
            if let Err(error) = self.install_assignment(controller) {
                tracing::error!(
                    namespace = %hex::encode(controller.id),
                    %error,
                    "settled assignment not installed on the open controller"
                );
            }
        }
        // The parked pins, their charge on the unsettled budget and the
        // epoch's discovery registration drop together, after the
        // completed projection that replaces them is visible. Retired
        // allocations are reclaimed when compaction folds the completed
        // owner tombstones (`projection_compact`), and by the inventory
        // sweep otherwise.
        controller.release_settled(epoch);
        Ok(Some(true))
    }

    /// Whether the completed projection of `controller`'s namespace names
    /// an assignment generation other than the one its controller serves:
    /// the epoch just completed admitted a reassignment.
    fn settled_assignment_changed(
        &self,
        controller: &Arc<NamespaceController>,
        epoch: u64,
    ) -> Result<bool, StoreError> {
        let Some((_, generation)) =
            self.assigned_plane(&NamespaceStorage::namespace_ref(controller.id))?
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
