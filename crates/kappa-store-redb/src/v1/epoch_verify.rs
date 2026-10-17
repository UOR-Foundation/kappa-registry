//! Verification of a sealed transaction before its commit, resolution of
//! a commit whose outcome redb did not report, and installation of an
//! admitted assignment on the open controller.

use redb::{ReadableDatabase, ReadableTable};

use kappa_store::epoch_root::EpochRoot;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;

use super::{epoch_idx_key, pointer_context};
use crate::PersistentStore;
use crate::storage::NamespaceController;
use crate::tables::{BLOB_INDEX, EPOCH_CURRENT, EPOCH_INDEX, MUTATION_BUFFER};

impl PersistentStore {
    /// Install the assignment `controller`'s database admits on the open
    /// controller. The one path every installer takes (commit, settlement,
    /// admission refresh), so a failure marks the controller stale
    /// everywhere and success clears it everywhere. Under test the hook
    /// `refuse_assignment_refresh` stands in for a plane this node stopped
    /// serving.
    pub(crate) fn install_assignment(
        &self,
        controller: &NamespaceController,
    ) -> Result<(), StoreError> {
        #[cfg(test)]
        if self.hooks.assignment_refresh_refused() {
            controller.set_assignment_stale(true);
            return Err(StoreError::Internal(
                "assignment refresh refused by test hook".into(),
            ));
        }
        self.namespaces.reassigned(&controller.id)
    }

    pub(super) fn verify_sealed_transaction(
        &self,
        txn: &redb::WriteTransaction,
        controller: &NamespaceController,
        ns: &NamespaceRef,
        root: &EpochRoot,
    ) -> Result<(), StoreError> {
        if root.namespace_id() != ns.id() || controller.id != *ns.id() {
            return Err(StoreError::Conflict(
                "epoch execution namespace mismatch".into(),
            ));
        }
        let number = root.epoch_number();
        let identity = root.kappa();
        let (digest, count) = self.tag_state_in_txn(txn, ns)?;
        if digest.into_bytes().as_slice() != root.state_digest() || count != root.tag_count() {
            return Err(StoreError::Conflict(
                "transaction changed after epoch sealing".into(),
            ));
        }
        {
            let mutations = txn
                .open_table(MUTATION_BUFFER)
                .map_err(crate::error::redb)?;
            if mutations
                .iter()
                .map_err(crate::error::redb)?
                .next()
                .transpose()
                .map_err(crate::error::redb)?
                .is_some()
            {
                return Err(StoreError::Conflict(
                    "unsealed mutations remain in epoch execution".into(),
                ));
            }
        }
        let index = txn.open_table(EPOCH_INDEX).map_err(crate::error::redb)?;
        let key = epoch_idx_key(ns, number);
        let entry = index
            .get(key.as_slice())
            .map_err(crate::error::redb)?
            .ok_or_else(|| {
                StoreError::Conflict("transaction has no matching epoch publication".into())
            })?;
        if Kappa::from_key_bytes(entry.value())? != *identity {
            return Err(StoreError::Conflict(
                "transaction epoch identity mismatch".into(),
            ));
        }
        let pointers = txn.open_table(EPOCH_CURRENT).map_err(crate::error::redb)?;
        let pointer = pointers
            .get(ns.id().as_slice())
            .map_err(crate::error::redb)?
            .ok_or_else(|| StoreError::Conflict("transaction has no epoch pointer".into()))?;
        if Kappa::from_key_bytes(&self.decrypt_bytes(&pointer_context(ns.id()), pointer.value())?)?
            != *identity
        {
            return Err(StoreError::Conflict(
                "transaction epoch pointer mismatch".into(),
            ));
        }
        let blobs = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        self.read_view_for(controller)
            .epoch_root_from_index(&blobs, identity)?;
        Ok(())
    }

    pub(crate) fn resolve_epoch_publication(
        &self,
        controller: &NamespaceController,
        ns: &NamespaceRef,
        number: u64,
        identity: &Kappa,
    ) -> Result<(), StoreError> {
        let txn = controller.db.begin_read().map_err(crate::error::redb)?;
        let epochs = txn.open_table(EPOCH_INDEX).map_err(crate::error::redb)?;
        let key = epoch_idx_key(ns, number);
        let entry = epochs
            .get(key.as_slice())
            .map_err(crate::error::redb)?
            .ok_or_else(|| StoreError::NotFound("epoch publication outcome".into()))?;
        if Kappa::from_key_bytes(entry.value())? != *identity {
            return Err(StoreError::Conflict(
                "epoch publication outcome differs".into(),
            ));
        }
        let blobs = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        let root = self
            .read_view_for(controller)
            .epoch_root_from_index(&blobs, identity)?;
        if root.namespace_id() != ns.id() || root.epoch_number() != number {
            return Err(StoreError::Conflict(
                "epoch publication coordinates differ".into(),
            ));
        }
        Ok(())
    }
}
