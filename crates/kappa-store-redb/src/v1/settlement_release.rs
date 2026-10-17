//! The capability to publish the governed release of an instance whose
//! recovery obligation closes the unsettled pool.
//!
//! A lost instance's obligation holds an unmeasured charge that closes the
//! pool to every ordinary admission (`unsettled::Closure::Obligation`).
//! One of that closure's exits is the instance's governed release, which
//! must publish its decision in the governing namespace; without this
//! grant that publication would be refused by the closure it ends. A
//! [`ReleaseGrant`] is minted only from a held obligation, under the
//! obligations lock, one at a time per instance; the publication it is
//! carried by is admitted as `unsettled::Class::Resolving`, which takes no
//! charge, so the node-wide bound is unchanged.

use kappa_store::StoreError;

use crate::PersistentStore;
use crate::storage_instance::StorageInstance;

#[cfg(test)]
#[path = "settlement_release_tests.rs"]
mod tests;

/// The release of one instance in flight. Only
/// [`PersistentStore::release_grant`] constructs one; dropping it lets the
/// next release of the instance be granted.
pub struct ReleaseGrant<'s> {
    store: &'s PersistentStore,
    instance: StorageInstance,
}

impl ReleaseGrant<'_> {
    /// The instance whose release this grant admits.
    pub(crate) const fn instance(&self) -> &StorageInstance {
        &self.instance
    }
}

impl Drop for ReleaseGrant<'_> {
    fn drop(&mut self) {
        // The obligation may have been discharged meanwhile; then there is
        // no mark to clear, and `update` finds nothing.
        self.store
            .obligations()
            .update(&self.instance, |obligation| obligation.releasing = false);
    }
}

impl PersistentStore {
    /// The grant to publish the governed release of `instance` while its
    /// obligation closes the pool. `None` when no obligation is held for
    /// it: its release is admitted as any publication. `Conflict` while
    /// another grant for it exists.
    pub(crate) fn release_grant(
        &self,
        instance: &StorageInstance,
    ) -> Result<Option<ReleaseGrant<'_>>, StoreError> {
        let minted = self.obligations().update(instance, |obligation| {
            !std::mem::replace(&mut obligation.releasing, true)
        });
        match minted {
            None => Ok(None),
            Some(false) => Err(StoreError::Conflict(format!(
                "the release of {instance} is already in progress"
            ))),
            Some(true) => Ok(Some(ReleaseGrant {
                store: self,
                instance: *instance,
            })),
        }
    }
}
