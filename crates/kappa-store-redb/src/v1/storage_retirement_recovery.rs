//! Recovery's completion of recorded retirements: one bounded range read of
//! `RETIRED` at a time, and the resolution of each record against the
//! storage present for its instance. Driven by `settlement_recovery`.

use std::ops::Bound;

use kappa_store::StoreError;
use kappa_store::governed_retirement::verify_retirement;

use super::RetirementCompletion;
use crate::PersistentStore;
use crate::instance_record::Kind;
use crate::retirement_record::RetirementRecord;
use crate::storage::{NamespaceStorage, Recording, StorageEvidence};
use crate::storage_instance::{Incarnation, StorageInstance};
use crate::tables::RETIRED;

impl PersistentStore {
    /// Up to `limit` recorded retirements after `cursor` in key order: one
    /// bounded range read of `RETIRED`, never the whole table.
    pub(crate) fn retirements_after(
        &self,
        cursor: Option<&StorageInstance>,
        limit: usize,
    ) -> Result<Vec<StorageInstance>, StoreError> {
        let txn = self.registry.begin_read()?;
        let table = txn.open_table(RETIRED).map_err(crate::error::redb)?;
        let lower = cursor.map(StorageInstance::key);
        let start = lower.as_deref().map_or(Bound::Unbounded, Bound::Excluded);
        let mut found = Vec::new();
        for entry in table
            .range::<&[u8]>((start, Bound::Unbounded))
            .map_err(crate::error::redb)?
        {
            if found.len() >= limit {
                break;
            }
            let (key, _) = entry.map_err(crate::error::redb)?;
            found.push(StorageInstance::from_key(key.value())?);
        }
        Ok(found)
    }

    /// Complete the recorded retirement of `instance`. An intent is
    /// resolved (`resolve_intent`); a release removes storage present only
    /// when it records exactly that instance and the record verifies a
    /// release (`release_verified`). A creation intent of the instance that
    /// recovery has not yet resolved is resolved with it.
    pub(crate) fn complete_retirement(
        &self,
        instance: &StorageInstance,
    ) -> Result<RetirementCompletion, StoreError> {
        let Some(record) = self.retirement_record(instance)? else {
            return Ok(RetirementCompletion::Complete);
        };
        if let RetirementRecord::Intent { governing, .. } = record {
            return self.resolve_intent(instance, &governing);
        }
        if !self.release_verified(instance, &record)? {
            tracing::warn!(
                instance = %instance,
                "retirement record does not verify a release; its storage is retained"
            );
            return Ok(RetirementCompletion::Retained);
        }
        let mut decided = None;
        self.forget_namespace_cursors(instance.namespace());
        let outcome = self
            .namespaces
            .remove_recorded(instance.namespace(), |evidence| match evidence {
                StorageEvidence::Absent => {
                    decided = Some(RetirementCompletion::Complete);
                    Err(Recording::Refused(StoreError::NotFound(
                        "no storage".into(),
                    )))
                }
                _ => match evidence.instance().map(|held| held.identify(instance)) {
                    Some(identification) if identification.permits_destruction() => {
                        decided = Some(RetirementCompletion::Removed);
                        // The release is already recorded.
                        Ok(())
                    }
                    _ => {
                        decided = Some(RetirementCompletion::Retained);
                        Err(Recording::Refused(StoreError::Conflict(format!(
                            "storage present is not the retired instance {instance}"
                        ))))
                    }
                },
            });
        match outcome {
            Ok(()) | Err(StoreError::NotFound(_) | StoreError::Conflict(_)) => {}
            Err(error) => return Err(error),
        }
        // Refused before its evidence was read (the namespace is active):
        // nothing is decided, and the next cycle retries.
        let found = decided.unwrap_or(RetirementCompletion::Retained);
        if found != RetirementCompletion::Retained {
            Kind::Creating.complete(self.namespaces.root(), instance)?;
        }
        if found == RetirementCompletion::Removed {
            tracing::warn!(
                instance = %instance,
                "completed a storage retirement interrupted before removal"
            );
        }
        Ok(found)
    }

    /// Resolve the recorded intent of `instance` governed by `governing`:
    /// with a decision for the instance published and verified, release it
    /// (its storage if present, retiring under the intent, else the lost
    /// instance alone); with none, give the intent up. A decision of
    /// another request for the same instance is that instance's decision:
    /// at most one is published per instance.
    fn resolve_intent(
        &self,
        instance: &StorageInstance,
        governing: &[u8; 16],
    ) -> Result<RetirementCompletion, StoreError> {
        let Incarnation::Known(incarnation) = instance.incarnation() else {
            return Err(StoreError::Internal(format!(
                "retirement intent of {instance} names an unknown incarnation"
            )));
        };
        let governing_ref = NamespaceStorage::namespace_ref(*governing);
        let verified = verify_retirement(self, &governing_ref, instance.namespace(), &incarnation)?;
        let Some(intent) = self.namespaces.resume_retiring(instance.namespace())? else {
            // No storage of the namespace is retiring: the instance's own
            // storage is gone (another instance's may be present).
            let Some(verified) = verified else {
                self.remove_retirement_record(instance)?;
                return Ok(RetirementCompletion::Abandoned);
            };
            let record = RetirementRecord::Released {
                governing: *governing,
                decision: verified.record().clone(),
            };
            self.commit_retirement_record(instance, &record)
                .map_err(Recording::into_error)?;
            return Ok(RetirementCompletion::Complete);
        };
        Self::is_named(intent.controller(), instance)?;
        let Some(verified) = verified else {
            intent.abandon(|| self.remove_retirement_record(instance))?;
            return Ok(RetirementCompletion::Abandoned);
        };
        self.release_present(intent, instance, &verified, governing)?;
        Kind::Creating.complete(self.namespaces.root(), instance)?;
        Ok(RetirementCompletion::Removed)
    }
}
