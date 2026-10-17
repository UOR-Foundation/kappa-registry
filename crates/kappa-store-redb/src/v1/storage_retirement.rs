//! Governed retirement of namespace storage, and the one verification of
//! what a retirement record authorizes.
//!
//! Releasing a storage instance removes its database directory and with it
//! every row that owned content. The only authority for it is a decision
//! its governing namespace published (`kappa_store::governed_retirement`):
//! the principal's signed request, the target record that authorized it,
//! and the decision, published as one operation. This module drives that
//! protocol over the slot lifecycle (`storage_retiring`):
//!
//! 1. present storage: a durable intent (`RetirementRecord::Intent`) is
//!    recorded and the namespace enters `Retiring` under its writer gate,
//!    so nothing publishes while the head and record are observed and the
//!    decision is published; the release is then recorded
//!    (`RetirementRecord::Released`) once the namespace holds no activity
//!    or publication dependency, and its storage removed;
//! 2. lost storage: the decision is published from the last record the
//!    directory holds and the last settled head, and the release recorded
//!    while no storage of the namespace is present.
//!
//! A creation proven never to have committed is retired on that proof
//! (`RetirementRecord::NeverCommitted`), not on a decision: no principal
//! exists for it. Recovery (`complete_retirement`) resolves every record:
//! an intent is released when its decision verifies and abandoned when none
//! was published; a release removes storage of exactly its instance. A
//! record never authorizes destruction by itself: [`release_verified`]
//! verifies the evidence it locates, every time.
//!
//! [`release_verified`]: PersistentStore::release_verified

use kappa_crypto::Verified;
use kappa_store::governed_retirement::{
    TargetObservation, VerifiedRetirement, retire, verify_retirement,
};
use kappa_store::time::Clock;
use kappa_store::{
    Axis, Disposition, EpochStore, Kappa, NamespaceRef, NamespaceStore, ObservedHead,
    RetirementRequest, StoreError, canonical_bytes,
};

use crate::PersistentStore;
use crate::retirement_record::RetirementRecord;
use crate::settlement::Work;
use crate::storage::{NamespaceController, NamespaceStorage, Recording, StorageEvidence};
use crate::storage_instance::{Incarnation, StorageInstance};

#[path = "storage_retirement_recovery.rs"]
mod recovery;

#[cfg(test)]
#[path = "storage_retirement_tests.rs"]
mod tests;

/// What completing one recorded retirement found.
#[derive(Debug, PartialEq, Eq)]
pub enum RetirementCompletion {
    /// The retired instance's storage was present and is now removed.
    Removed,
    /// No storage of the retired instance remains: nothing to do.
    Complete,
    /// An intent whose decision was never published is given up: the
    /// namespace serves every purpose again.
    Abandoned,
    /// Storage present is another instance, or one whose instance cannot be
    /// proven to be the retired one, or the record does not verify a
    /// release: left untouched.
    Retained,
}

impl PersistentStore {
    /// Retire the storage instance `request` names, governed by
    /// `governing`: publish the decision as the request's operation of
    /// `governing` (a committed one replays from its evidence) and release
    /// the instance.
    ///
    /// Present storage (`Disposition::RetirePresent`) is held `Retiring`
    /// from the intent's record to the release, so the head and record the
    /// principal signed cannot move while the decision publishes. The
    /// release waits for every other activity of the namespace and every
    /// publication dependency to end: while one remains the call returns
    /// `Conflict`, with the decision published and the intent recorded,
    /// and recovery releases the instance once they end. Lost storage
    /// (`Disposition::ReleaseLost`) is released while no storage of the
    /// namespace is present.
    ///
    /// The decision is authorized only for a principal that owns the target
    /// namespace (`governed_retirement`).
    pub fn retire_governed(
        &self,
        governing: &NamespaceRef,
        request: &Verified<RetirementRequest>,
        clock: &dyn Clock,
    ) -> Result<VerifiedRetirement, StoreError> {
        let signed = request.get();
        let instance =
            StorageInstance::new(*signed.target(), Incarnation::Known(*signed.incarnation()));
        match signed.disposition() {
            Disposition::RetirePresent => self.retire_present(governing, request, &instance, clock),
            Disposition::ReleaseLost => self.release_lost(governing, request, &instance, clock),
        }
    }

    /// Storage of `controller` is exactly `instance`, the instance a
    /// retirement names: anything else is never retired for it.
    fn is_named(
        controller: &NamespaceController,
        instance: &StorageInstance,
    ) -> Result<(), StoreError> {
        if controller.instance.identify(instance).permits_destruction() {
            return Ok(());
        }
        Err(StoreError::Conflict(format!(
            "storage of namespace {} is instance {}, not {instance} the retirement names",
            hex::encode(instance.namespace()),
            controller.instance
        )))
    }

    fn retire_present(
        &self,
        governing: &NamespaceRef,
        request: &Verified<RetirementRequest>,
        instance: &StorageInstance,
        clock: &dyn Clock,
    ) -> Result<VerifiedRetirement, StoreError> {
        let target = instance.namespace();
        // Partly read epochs hold the namespace active; if it stays, they
        // are read again from their start.
        self.forget_namespace_cursors(target);
        let intent = if let Some(intent) = self.namespaces.resume_retiring(target)? {
            intent
        } else {
            let record = RetirementRecord::Intent {
                governing: *governing.id(),
                request: Kappa::compute(Axis::Sha256, &canonical_bytes(request.get()))?,
            };
            self.namespaces.begin_retiring(target, |controller| {
                Self::is_named(controller, instance)?;
                self.commit_retirement_record(instance, &record)
                    .map_err(Recording::into_error)
            })?
        };
        Self::is_named(intent.controller(), instance)?;
        let published = self.observe_present(instance).and_then(|observation| {
            retire(
                self,
                governing,
                request,
                &observation,
                clock,
                |namespace, operation, request, clock| {
                    self.begin_operation_with(namespace, operation, request, clock, None)
                },
            )
        });
        let verified = match published {
            Ok(verified) => verified,
            Err(error) => {
                // Without a published decision the intent is given up; with
                // one it stays, and recovery releases the instance.
                let incarnation = request.get().incarnation();
                if verify_retirement(self, governing, target, incarnation)?.is_none() {
                    intent.abandon(|| self.remove_retirement_record(instance))?;
                }
                return Err(error);
            }
        };
        self.release_present(intent, instance, &verified, governing.id())?;
        Ok(verified)
    }

    /// The observation of present storage of `instance`, held by a
    /// retirement intent: its namespace record and head, both read from the
    /// namespace's own database. The writer gate the intent holds keeps the
    /// head from moving, so the record is the target's committed state at
    /// the head observed.
    fn observe_present(&self, instance: &StorageInstance) -> Result<TargetObservation, StoreError> {
        let target_ref = NamespaceStorage::namespace_ref(*instance.namespace());
        let (epoch_number, root) = self.epoch_current(&target_ref)?;
        Ok(TargetObservation {
            record: self.namespace_info(&target_ref)?,
            head: Some(ObservedHead { epoch_number, root }),
        })
    }

    /// Release the present storage `intent` holds under `verified`: settle
    /// it to its head, which releases the publication dependencies its
    /// unsettled epochs hold, then record the release once nothing else
    /// holds the namespace and its head is still the one the decision
    /// names, and remove the storage.
    fn release_present(
        &self,
        intent: crate::storage::RetirementIntent,
        instance: &StorageInstance,
        verified: &VerifiedRetirement,
        governing: &[u8; 16],
    ) -> Result<(), StoreError> {
        let mut work = Work {
            mutations: u64::MAX,
            bytes: self.recovery_step_bytes,
        };
        self.settle_namespace(intent.controller(), &mut work)?;
        self.forget_namespace_cursors(instance.namespace());
        let decided = verified.decision().observed_head().cloned();
        let record = RetirementRecord::Released {
            governing: *governing,
            decision: verified.record().clone(),
        };
        intent.release(
            |controller| {
                Self::is_named(controller, instance)?;
                let head = self.head_root(controller)?.map(|root| ObservedHead {
                    epoch_number: root.epoch_number(),
                    root: root.kappa().clone(),
                });
                if head != decided {
                    return Err(StoreError::Conflict(format!(
                        "the head of {instance} is not the head its retirement decision names"
                    )));
                }
                Ok(())
            },
            || self.commit_retirement_record(instance, &record),
        )
    }

    /// Release `instance` whose storage is lost: the decision is published
    /// from the last record the directory holds and the last settled head,
    /// then the release is recorded while no storage of the namespace is
    /// present. Storage present, of any instance, is refused: present
    /// storage is retired as present.
    ///
    /// A lost instance found by a restart holds an obligation whose
    /// unmeasured charge closes the unsettled pool; the decision publishes
    /// through that obligation's release grant, which admits a publication
    /// taking no charge (`settlement_release`). Without an obligation the
    /// pool is not closed by this instance and the decision is admitted as
    /// any operation.
    fn release_lost(
        &self,
        governing: &NamespaceRef,
        request: &Verified<RetirementRequest>,
        instance: &StorageInstance,
        clock: &dyn Clock,
    ) -> Result<VerifiedRetirement, StoreError> {
        let target_ref = NamespaceStorage::namespace_ref(*instance.namespace());
        let observation = TargetObservation {
            record: self.settled_namespace_info(&target_ref)?,
            head: self
                .settled_epoch(instance)?
                .map(|(epoch_number, root)| ObservedHead { epoch_number, root }),
        };
        let release = self.release_grant(instance)?;
        let verified = retire(
            self,
            governing,
            request,
            &observation,
            clock,
            |namespace, operation, request, clock| {
                self.begin_operation_with(namespace, operation, request, clock, release)
            },
        )?;
        let record = RetirementRecord::Released {
            governing: *governing.id(),
            decision: verified.record().clone(),
        };
        self.namespaces
            .remove_recorded(instance.namespace(), |evidence| match evidence {
                StorageEvidence::Absent => self.commit_retirement_record(instance, &record),
                _ => Err(Recording::Refused(StoreError::Conflict(format!(
                    "storage of namespace {} is present; retire it as present storage",
                    hex::encode(instance.namespace())
                )))),
            })?;
        Ok(verified)
    }

    /// Retire the storage of a creation proven never to have committed:
    /// `instance`'s readable storage, holding no epoch, verified under the
    /// held slot so no execution can commit meanwhile. Returns whether it
    /// was retired; storage of another instance, storage holding an epoch,
    /// and storage that cannot be read (whatever its size: a truncated
    /// database is damage, not proof that nothing committed) are kept.
    pub(crate) fn retire_empty_creation(
        &self,
        instance: &StorageInstance,
    ) -> Result<bool, StoreError> {
        self.forget_namespace_cursors(instance.namespace());
        let outcome = self
            .namespaces
            .remove_recorded(instance.namespace(), |evidence| {
                let empty = match evidence {
                    StorageEvidence::Absent | StorageEvidence::Unopenable { .. } => false,
                    StorageEvidence::Open(_) | StorageEvidence::Closed { .. } => {
                        let same = evidence
                            .instance()
                            .is_some_and(|held| held.identify(instance).permits_destruction());
                        let db = evidence.database().ok_or_else(|| {
                            StoreError::Internal("open storage evidence has no database".into())
                        })?;
                        same && !NamespaceController::holds_head(db, instance.namespace())?
                    }
                };
                if !empty {
                    return Err(Recording::Refused(StoreError::Conflict(format!(
                        "storage of {instance} is not an empty creation"
                    ))));
                }
                self.commit_retirement_record(instance, &RetirementRecord::NeverCommitted)
            });
        match outcome {
            Ok(()) => Ok(true),
            Err(StoreError::Conflict(_)) => Ok(false),
            Err(error) => Err(error),
        }
    }

    /// Whether `record`, verified now, releases what `instance` held: the
    /// one decision every destructive use of a retirement record makes
    /// (removing storage, reclaiming its allocations, discharging its
    /// recovery obligation). A record of an unknown (legacy) instance never
    /// does: it cannot be told apart from another legacy instance's. A
    /// governed release does only while the decision it names verifies from
    /// its governing namespace's published evidence.
    pub(crate) fn release_verified(
        &self,
        instance: &StorageInstance,
        record: &RetirementRecord,
    ) -> Result<bool, StoreError> {
        let Incarnation::Known(incarnation) = instance.incarnation() else {
            return Ok(false);
        };
        match record {
            RetirementRecord::Legacy | RetirementRecord::NeverCommitted => Ok(true),
            RetirementRecord::Intent { .. } => Ok(false),
            RetirementRecord::Released {
                governing,
                decision,
            } => Ok(verify_retirement(
                self,
                &NamespaceStorage::namespace_ref(*governing),
                instance.namespace(),
                &incarnation,
            )?
            .is_some_and(|verified| verified.record() == decision)),
        }
    }
}
