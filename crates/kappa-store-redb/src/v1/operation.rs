//! Durable replay resolves evidence from the authenticated epoch ledger.

use crate::{
    PersistentStore,
    storage::{IncarnationUse, NamespaceController},
    tables::{BLOB_INDEX, OPERATION_RECEIPTS},
};
use kappa_store::{
    EpochRoot, Kappa, NamespaceRef, OperationReceipt, StoreError,
    canonical::{canonical_bytes, from_canonical},
    work::{Dimension, Meter},
};
use redb::ReadableTable;

/// Table-encryption context of `OPERATION_RECEIPTS` values.
const OPERATION_CONTEXT: &str = "operation";

/// Bytes of an operation index key: the namespace and the operation.
const OPERATION_KEY_BYTES: u64 = 16 + 32;

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
    /// `namespace`, if any, read on one operation's meter. A namespace
    /// without storage has committed nothing, so it holds no outcome;
    /// evidence a held namespace cannot produce is an error, never absence.
    pub fn resolve_operation(
        &self,
        namespace: &NamespaceRef,
        identity: &[u8; 32],
        request: &Kappa,
    ) -> Result<Option<(EpochRoot, OperationReceipt)>, StoreError> {
        let mut work = self.read_meter();
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
            &mut work,
        )
    }

    /// The outcome of operation `identity` from the operation index and the
    /// content rows of `controller`'s namespace, on `work`: the index row
    /// looked up, read, decrypted and decoded, then the epoch root, its
    /// ledger and the receipt each read once, and the outcome admitted by
    /// the shared rule (`admit_operation_outcome`), which admits the epoch
    /// with its ledger. Each step is charged before it runs.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn operation_from_tables(
        &self,
        controller: &NamespaceController,
        operations: &impl ReadableTable<&'static [u8], &'static [u8]>,
        blobs: &impl ReadableTable<&'static [u8], &'static [u8]>,
        namespace: &NamespaceRef,
        identity: &[u8; 32],
        request: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Option<(EpochRoot, OperationReceipt)>, StoreError> {
        work.charge_all(&[
            (Dimension::BytesAllocated, OPERATION_KEY_BYTES),
            (Dimension::Entries, 1),
        ])?;
        let key = operation_key(namespace, identity);
        let Some(entry) = operations.get(key.as_slice()).map_err(crate::error::redb)? else {
            return Ok(None);
        };
        let stored = entry.value().len() as u64;
        work.charge_all(&[
            (Dimension::BytesRead, stored),
            (
                Dimension::BytesAllocated,
                crate::encrypted::bound_allocation(OPERATION_CONTEXT, key.len()),
            ),
            (Dimension::BytesAllocated, stored),
            (Dimension::BytesDecoded, stored),
            (Dimension::BytesAllocated, stored),
        ])?;
        let coordinates: Vec<Kappa> = from_canonical(&self.decrypt_bytes(
            &crate::encrypted::bound(OPERATION_CONTEXT, &key),
            entry.value(),
        )?)?;
        let [root_identity, receipt_identity] = coordinates.as_slice() else {
            return Err(StoreError::Rejected(
                "invalid operation index coordinates".into(),
            ));
        };
        let view = self.read_view_for(controller);
        let (epoch, _) = view.unadmitted_epoch_root(blobs, root_identity, work)?;
        let receipt = view.verified_epoch_content(
            blobs,
            receipt_identity,
            Some(OperationReceipt::MAX_RESULT_SIZE as u64 + 1024),
            work,
        )?;
        let ledger = view.verified_epoch_content(blobs, epoch.ledger_root(), None, work)?;
        let incarnation = controller.logical_incarnation(IncarnationUse::OperationOutcome)?;
        let receipt = kappa_store::operation::admit_operation_outcome(
            kappa_store::operation::OperationOutcomeInput {
                epoch: &epoch,
                ledger: &ledger,
                receipt: &receipt,
                namespace,
                incarnation: &incarnation,
                identity,
                request,
            },
            &self.authority.load(),
            work,
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
        let stored =
            self.encrypt_bytes(&crate::encrypted::bound(OPERATION_CONTEXT, &key), &bytes)?;
        transaction
            .open_table(OPERATION_RECEIPTS)
            .map_err(crate::error::redb)?
            .insert(key.as_slice(), stored.as_slice())
            .map_err(crate::error::redb)?;
        Ok(())
    }
}
