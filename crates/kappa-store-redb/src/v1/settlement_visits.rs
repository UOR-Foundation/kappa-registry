//! What recovery does with one durable record or obligation: classify the
//! storage present for its instance and settle, reconstruct, retire,
//! discharge or hold it unresolved. Driven by `settlement_recovery`.

use kappa_store::StoreError;
use kappa_store::work::Meter;

use super::Origin;
use super::recovery::Recovery;
use crate::PersistentStore;
use crate::instance_record::Kind;
use crate::namespace_snapshot::{InstanceAdmission, NamespaceSnapshot};
use crate::registry::Standing;
use crate::retirement_record::RetirementRecord;
use crate::storage_instance::StorageInstance;

/// What one visit of a durable record did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Visit {
    /// The record was classified and acted on.
    Done,
    /// An unavailable resource deferred it: the record and any obligation
    /// stay as they were, and the cycle is unclean.
    Deferred,
}

/// The storage present for an instance, as settlement may act on it.
enum Found {
    /// Storage the instance's record may have been written for
    /// (`Identification::permits_settlement`), held open.
    Present(NamespaceSnapshot),
    /// No storage settlement may act on for the instance, with the
    /// instance's retirement record if one explains its absence.
    Gone(Option<RetirementRecord>),
    /// Storage that cannot be opened or read.
    Unreadable(StoreError),
    /// The storage was not examined: every namespace activity of the store
    /// is held. The durable record stays for a later visit; nothing about
    /// the storage is implied.
    Deferred,
}

impl PersistentStore {
    /// The storage present for `instance`, by the one classification of a
    /// recorded instance's storage (`admit_instance`).
    fn found(&self, instance: &StorageInstance) -> Found {
        match self.admit_instance(instance) {
            InstanceAdmission::Held {
                snapshot,
                identification,
            } if identification.permits_settlement() => Found::Present(snapshot),
            // Readable storage the instance's record cannot be proven to
            // have been written for: the instance itself is gone.
            InstanceAdmission::Held { snapshot, .. } => {
                drop(snapshot);
                match self.retirement_record(instance) {
                    Ok(record) => Found::Gone(record.filter(RetirementRecord::explains_absence)),
                    Err(error) => Found::Unreadable(error),
                }
            }
            InstanceAdmission::CapacityDeferred { .. } => Found::Deferred,
            InstanceAdmission::Released(record) => Found::Gone(Some(record)),
            InstanceAdmission::Unexplained(_) => Found::Gone(None),
            InstanceAdmission::Unreadable(error) => Found::Unreadable(error),
        }
    }

    /// Visit the pending marker of `instance`: settle what its storage
    /// holds within the budget; a creation proven never committed is
    /// retired; ownership a restart found and the budget did not settle is
    /// reconstructed in later slices; missing or replaced storage is
    /// discharged only under its instance's recorded retirement. A visit an
    /// unavailable resource defers (activity capacity, a settlement attempt
    /// held elsewhere, staging, cursors, the registry writer) leaves the
    /// marker and any obligation as they are, and the cycle unclean, so the
    /// marker is visited again and the enumeration at open does not finish
    /// over it. Returns the epochs settled.
    pub(super) fn visit_marker(
        &self,
        instance: &StorageInstance,
        recovery: &mut Recovery,
        work: &mut dyn Meter,
        startup: bool,
    ) -> Result<u64, StoreError> {
        match self.found(instance) {
            Found::Deferred => {
                recovery.defer();
                Ok(0)
            }
            Found::Gone(record) => {
                self.resolve_gone(instance, record.as_ref(), recovery)?;
                Ok(0)
            }
            Found::Unreadable(error) => {
                self.record_unresolved(
                    instance,
                    Origin::Marker,
                    format!("storage cannot be read: {error}"),
                )?;
                recovery.enqueue(*instance);
                Ok(0)
            }
            Found::Present(snapshot) => {
                let settled = self.settle_namespace(snapshot.controller(), work)?;
                drop(snapshot);
                if settled.empty_creation {
                    self.retire_creation(instance)?;
                } else if settled.deferred.is_some() {
                    // Short of the head, or at it with its finalization
                    // deferred: the marker stays and is visited again.
                    recovery.defer();
                } else if !settled.reached && (startup || self.obligation_held(instance)) {
                    self.record_unresolved(
                        instance,
                        Origin::Marker,
                        "reconstruction in progress".into(),
                    )?;
                    recovery.enqueue(*instance);
                }
                Ok(settled.applied)
            }
        }
    }

    /// The instance of a pending marker has no storage of its own: its
    /// obligation is discharged, and its marker removed, only when its
    /// retirement `record` is verified to release what it held
    /// (`release_verified`); otherwise it stays an unresolved obligation
    /// (restored storage or a governed release of the instance resolves it).
    fn resolve_gone(
        &self,
        instance: &StorageInstance,
        record: Option<&RetirementRecord>,
        recovery: &mut Recovery,
    ) -> Result<(), StoreError> {
        let released = match record {
            Some(record) => self.release_verified(instance, record)?,
            None => false,
        };
        if released {
            Kind::Pending.complete(self.namespaces.root(), instance)?;
            self.discharge(instance, "its instance's retirement is recorded");
            return Ok(());
        }
        self.record_unresolved(
            instance,
            Origin::Marker,
            "storage missing or replaced without a recorded retirement of this instance".into(),
        )?;
        recovery.enqueue(*instance);
        Ok(())
    }

    /// Retire the storage of a creation proven never committed, which its
    /// creation intent owns until then, and remove the intent once it is
    /// retired. Storage in use, or no longer empty, stays with the intent
    /// for a later cycle.
    fn retire_creation(&self, instance: &StorageInstance) -> Result<(), StoreError> {
        if self.retire_empty_creation(instance)? {
            Kind::Creating.complete(self.namespaces.root(), instance)?;
            if self.obligation_origin(instance) == Some(Origin::Intent) {
                self.discharge(instance, "its abandoned creation's storage is retired");
            }
        }
        Ok(())
    }

    /// Visit the creation intent of `instance`. A marker of the instance
    /// completes the handoff; no storage of the instance leaves nothing to
    /// clean; readable storage holding an epoch is owned by settlement
    /// (its marker is restored when epochs are unsettled); readable empty
    /// storage no creation is using is retired; unreadable storage is an
    /// unresolved obligation, whatever its size. A visit an unavailable
    /// resource defers (activity capacity, a registry commit of unknown
    /// outcome) leaves the intent and any obligation as they are and the
    /// cycle unclean.
    pub(super) fn visit_intent(
        &self,
        instance: &StorageInstance,
        recovery: &mut Recovery,
        work: &mut dyn Meter,
    ) -> Result<Visit, StoreError> {
        let root = self.namespaces.root();
        let discharge_intent = |why: &str| {
            if self.obligation_origin(instance) == Some(Origin::Intent) {
                self.discharge(instance, why);
            }
        };
        if Kind::Pending.holds(root, instance)? {
            // The marker is durable discoverability, not the live
            // obligation: an intent obligation becomes the marker's in
            // place, keeping its charge and gap, before the intent goes.
            if self.obligation_origin(instance) == Some(Origin::Intent) {
                self.hand_to_marker(
                    instance,
                    "handed from its creation intent to its marker".into(),
                )?;
                recovery.enqueue(*instance);
            }
            Kind::Creating.complete(root, instance)?;
            return Ok(Visit::Done);
        }
        match self.found(instance) {
            // The intent stays, and the cycle does not claim it visited.
            Found::Deferred => {
                recovery.defer();
                return Ok(Visit::Deferred);
            }
            Found::Gone(_) => {
                Kind::Creating.complete(root, instance)?;
                discharge_intent("no storage of the instance remains");
            }
            Found::Unreadable(error) => {
                self.record_unresolved(
                    instance,
                    Origin::Intent,
                    format!("a creation left storage that cannot be read: {error}"),
                )?;
                recovery.enqueue(*instance);
            }
            Found::Present(snapshot) => {
                let controller = snapshot.controller();
                // The authenticated head, read in the snapshot the storage
                // was classified in, is the sole decision input: no
                // preliminary boolean check that another transaction could
                // disagree with. `None` means no committed epoch; it does
                // not become epoch 0 for a checkpoint comparison.
                match self.head_root_in(
                    snapshot.transaction(),
                    snapshot.view(),
                    &controller.id,
                    work,
                )? {
                    Some(head_root) => {
                        let head = head_root.epoch_number();
                        // Completing the intent is a discharge: only an
                        // established checkpoint at the head authorizes it.
                        // A registry commit of unknown outcome is the
                        // registry's condition: the visit defers.
                        let checkpoint = match self.established_checkpoint_standing(instance)? {
                            Standing::Ready(checkpoint) => {
                                checkpoint.map_or(0, |(number, _)| number)
                            }
                            Standing::RecoveryRequired => {
                                recovery.defer();
                                return Ok(Visit::Deferred);
                            }
                        };
                        if checkpoint < head {
                            // Unsettled epochs with no registration: a
                            // marker obligation (the intent's, handed over
                            // in place, or a new one) holds the gap and its
                            // charge before the durable marker takes the
                            // intent over.
                            self.hand_to_marker(
                                instance,
                                "committed epochs found under a creation intent".into(),
                            )?;
                            recovery.enqueue(*instance);
                            self.mark_unsettled(instance)?;
                        } else {
                            Kind::Creating.complete(root, instance)?;
                            discharge_intent("its committed storage is settled");
                        }
                        return Ok(Visit::Done);
                    }
                    // No head pointer in this snapshot. Retirement below
                    // decides emptiness again under the held slot
                    // (`retire_empty_creation`), refusing storage that
                    // holds a head by then.
                    None => {}
                }
                // A creation in progress holds a grant beside this one; its
                // marker will hand the intent over.
                let in_use = controller.active.load(std::sync::atomic::Ordering::Acquire) > 1;
                drop(snapshot);
                if !in_use {
                    self.retire_creation(instance)?;
                }
            }
        }
        Ok(Visit::Done)
    }

    /// Visit a queued obligation. Returns whether it stays queued.
    pub(super) fn visit_obligation(
        &self,
        instance: &StorageInstance,
        recovery: &mut Recovery,
        work: &mut dyn Meter,
    ) -> Result<bool, StoreError> {
        match self.obligation_origin(instance) {
            None => Ok(false),
            // A deferred visit keeps the queued obligation queued.
            Some(Origin::Intent) => Ok(matches!(
                self.visit_intent(instance, recovery, work)?,
                Visit::Deferred
            )),
            Some(Origin::Marker) => match self.found(instance) {
                // Kept queued with its charge, gap and registrations; the
                // cycle claims nothing about it.
                Found::Deferred => {
                    recovery.defer();
                    Ok(true)
                }
                Found::Gone(record) => {
                    self.resolve_gone(instance, record.as_ref(), recovery)?;
                    Ok(false)
                }
                Found::Unreadable(error) => {
                    self.record_unresolved(
                        instance,
                        Origin::Marker,
                        format!("storage cannot be read: {error}"),
                    )?;
                    Ok(true)
                }
                Found::Present(snapshot) => {
                    if self.obligation_registered(instance) == Some(false)
                        && self
                            .reconstruct_slice(snapshot.controller(), work)?
                            .is_some()
                    {
                        // A resource (registry recovery, cursor or activity
                        // capacity) stopped the slice: the obligation stays
                        // queued as it is and the cycle is unclean.
                        recovery.defer();
                        return Ok(true);
                    }
                    Ok(self.obligation_registered(instance) == Some(false))
                }
            },
        }
    }
}
