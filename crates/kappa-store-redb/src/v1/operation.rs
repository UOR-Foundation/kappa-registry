//! Durable replay resolves evidence from the authenticated epoch ledger.

use crate::{
    PersistentStore,
    storage::NamespaceController,
    tables::{BLOB_INDEX, OPERATION_RECEIPTS},
};
use kappa_store::{
    EpochRoot, Kappa, NamespaceRef, OperationReceipt, StoreError,
    canonical::{canonical_bytes, from_canonical},
};
use redb::ReadableTable;

#[cfg(test)]
#[path = "operation_tests.rs"]
mod tests;

pub fn operation_key(namespace: &NamespaceRef, identity: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(48);
    key.extend_from_slice(namespace.id());
    key.extend_from_slice(identity);
    key
}

impl PersistentStore {
    /// The authenticated committed outcome of operation `identity` in
    /// `namespace`, if any. A namespace without storage has committed
    /// nothing, so it holds no outcome; evidence a held namespace cannot
    /// produce is an error, never absence.
    pub fn resolve_operation(
        &self,
        namespace: &NamespaceRef,
        identity: &[u8; 32],
        request: &Kappa,
    ) -> Result<Option<(EpochRoot, OperationReceipt)>, StoreError> {
        let snapshot = match self.namespace_snapshot(namespace) {
            Ok(snapshot) => snapshot,
            Err(StoreError::NotFound(_)) => return Ok(None),
            Err(error) => return Err(error),
        };
        self.operation_from_tables(
            snapshot.controller(),
            &snapshot.table(OPERATION_RECEIPTS)?,
            &snapshot.table(BLOB_INDEX)?,
            namespace,
            identity,
            request,
        )
    }

    pub(crate) fn operation_from_tables(
        &self,
        controller: &NamespaceController,
        operations: &impl ReadableTable<&'static [u8], &'static [u8]>,
        blobs: &impl ReadableTable<&'static [u8], &'static [u8]>,
        namespace: &NamespaceRef,
        identity: &[u8; 32],
        request: &Kappa,
    ) -> Result<Option<(EpochRoot, OperationReceipt)>, StoreError> {
        let key = operation_key(namespace, identity);
        let Some(entry) = operations.get(key.as_slice()).map_err(crate::error::redb)? else {
            return Ok(None);
        };
        let coordinates: Vec<Kappa> = from_canonical(
            &self.decrypt_bytes(&crate::encrypted::bound("operation", &key), entry.value())?,
        )?;
        let [root_identity, receipt_identity] = coordinates.as_slice() else {
            return Err(StoreError::Rejected(
                "invalid operation index coordinates".into(),
            ));
        };
        let view = self.read_view_for(controller);
        let epoch = view.epoch_root_from_index(blobs, root_identity)?;
        if epoch.namespace_id() != namespace.id() {
            return Err(StoreError::Rejected(
                "operation epoch crosses namespace".into(),
            ));
        }
        let bytes = view.epoch_content_from_index(
            blobs,
            receipt_identity,
            Some(OperationReceipt::MAX_RESULT_SIZE as u64 + 1024),
        )?;
        let ledger = view.epoch_content_from_index(blobs, epoch.ledger_root(), None)?;
        let receipt = kappa_store::operation::admit_operation_outcome(
            kappa_store::operation::OperationOutcomeInput {
                epoch: &epoch,
                ledger: &ledger,
                receipt_identity,
                receipt_bytes: &bytes,
                namespace,
                identity,
                request,
            },
            &self.authority.load(),
        )?;
        Ok(Some((epoch, receipt)))
    }

    pub(crate) fn store_operation_coordinates(
        &self,
        transaction: &redb::WriteTransaction,
        namespace: &NamespaceRef,
        identity: &[u8; 32],
        root: &Kappa,
        receipt: &Kappa,
    ) -> Result<(), StoreError> {
        let key = operation_key(namespace, identity);
        let bytes = canonical_bytes(&vec![root.clone(), receipt.clone()]);
        let stored = self.encrypt_bytes(&crate::encrypted::bound("operation", &key), &bytes)?;
        transaction
            .open_table(OPERATION_RECEIPTS)
            .map_err(crate::error::redb)?
            .insert(key.as_slice(), stored.as_slice())
            .map_err(crate::error::redb)?;
        Ok(())
    }
}
