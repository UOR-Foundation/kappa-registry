//! Per-blob metadata in the execution's transaction, and installation of
//! records the store produces inside an execution (sequence evidence,
//! operation receipts, and the ledger, root and succession evidence the
//! seal writes).
//!
//! Such a record is bytes already in memory with a verified identity. It
//! is prepared through the same path as every other content (inline when
//! its encoded row fits, external otherwise, durability established before
//! the row is written) and installed without a `ContentPublish`
//! commitment: the sealing ledger cannot commit itself, and a mutation
//! recorded after the seal would be refused by `commit_epoch_transaction`.
//! Such content is read in full and verified against its identity; it has
//! no range or stream path.

use std::time::{Duration, Instant};

use kappa_types::work::{Dimension, Meter};
use kappa_types::{Kappa, NamespaceRef, StoreError, VerifiedContent};
use redb::ReadableTable;

use crate::PersistentStore;
use crate::allocation::Pin;
use crate::blob::meta_key;
use crate::blob_rows::record_in_txn;
use crate::content_install::{Installed, install_internal_in_txn};
use crate::encrypted::bound;
use crate::tables::BLOB_META;

#[cfg(test)]
#[path = "epoch_blob_tests.rs"]
mod tests;

/// Bound on establishing durability for an external internal record.
pub const INTERNAL_PREPARATION_TIMEOUT: Duration = Duration::from_secs(30);

/// Table-encryption context of `BLOB_META` values.
const BLOB_META_CONTEXT: &str = "blob_meta";

/// Per-blob metadata from any table view, read or write transaction, on
/// `work`: the row key (`meta_key`: the identity's key, then the row key
/// built from it) and its lookup charged before the lookup; the value's
/// read, its decryption context (`bound`) and its decryption charged at
/// the stored length before decrypting.
pub fn blob_meta_from_table(
    store: &PersistentStore,
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    kappa: &Kappa,
    key: &str,
    work: &mut dyn Meter,
) -> Result<Vec<u8>, StoreError> {
    let row_len = kappa.key_len() + 1 + key.len();
    work.charge_all(&[
        (Dimension::BytesAllocated, kappa.key_len() as u64),
        (Dimension::BytesAllocated, row_len as u64),
        (Dimension::Entries, 1),
    ])?;
    let row = meta_key(kappa, key);
    let guard = table
        .get(row.as_slice())
        .map_err(crate::error::redb)?
        .ok_or_else(|| StoreError::NotFound(format!("meta {kappa}:{key}")))?;
    let stored = guard.value().len() as u64;
    work.charge_all(&[
        (Dimension::BytesRead, stored),
        (Dimension::BytesDecoded, stored),
        (Dimension::BytesAllocated, stored),
        (
            Dimension::BytesAllocated,
            crate::encrypted::bound_allocation(BLOB_META_CONTEXT, row_len),
        ),
    ])?;
    store.decrypt_bytes(&bound(BLOB_META_CONTEXT, &row), guard.value())
}

pub fn blob_meta_put_in_txn(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    kappa: &Kappa,
    key: &str,
    value: &[u8],
) -> Result<(), StoreError> {
    let row = meta_key(kappa, key);
    let stored = store.encrypt_bytes(&bound(BLOB_META_CONTEXT, &row), value)?;
    txn.open_table(BLOB_META)
        .map_err(crate::error::redb)?
        .insert(row.as_slice(), stored.as_slice())
        .map_err(crate::error::redb)?;
    Ok(())
}

pub fn blob_meta_delete_in_txn(
    txn: &redb::WriteTransaction,
    kappa: &Kappa,
    key: &str,
) -> Result<(), StoreError> {
    txn.open_table(BLOB_META)
        .map_err(crate::error::redb)?
        .remove(meta_key(kappa, key).as_slice())
        .map_err(crate::error::redb)?;
    Ok(())
}

/// Install a store-produced record for `ns` inside `txn`. Returns whether
/// the identity was new and the pin of an external allocation, which the
/// execution holds until its publication settles.
pub fn install_record_in_txn(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    ns: &NamespaceRef,
    content: &VerifiedContent,
) -> Result<(bool, Option<Pin>), StoreError> {
    if record_in_txn(store, txn, content.kappa())?.is_some() {
        return Ok((false, None));
    }
    // The record is in memory, so its exact length is the admission bound:
    // the external reservation adds chunk overhead to this bound, which an
    // unbounded maximum would overflow.
    let length = u64::try_from(content.content().len())
        .map_err(|_| StoreError::CapacityExceeded("record exceeds the u64 range".into()))?;
    let prepared = store.prepare_representation(
        content.kappa().axis(),
        Some(content.kappa()),
        &mut content.content(),
        None,
        length,
        Instant::now() + INTERNAL_PREPARATION_TIMEOUT,
    )?;
    let (installed, pin) =
        install_internal_in_txn(store, txn, ns, prepared, store.representation_limits)?;
    Ok((installed == Installed::New, pin))
}

/// Install a record from inside a write helper that has no access to the
/// execution's pin set (edge records, namespace records, identity
/// records). The pin, if any, is parked on the namespace's controller
/// under its writer and drained into the execution when it seals; the
/// controller has one writer, so the parked pins belong to exactly the
/// transaction that is open on it.
pub fn blob_put_in_txn(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    ns: &NamespaceRef,
    content: &VerifiedContent,
) -> Result<bool, StoreError> {
    let (new, pin) = install_record_in_txn(store, txn, ns, content)?;
    if let Some(pin) = pin {
        store
            .controller(ns)?
            .writer_pins
            .lock()
            .map_err(|_| StoreError::Internal("writer pin set poisoned".into()))?
            .push(pin);
    }
    Ok(new)
}
