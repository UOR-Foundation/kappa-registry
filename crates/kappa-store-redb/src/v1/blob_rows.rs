//! The `BLOB_INDEX` row codec: one definition of how a committed
//! representation row is encrypted, written and read.
//!
//! Row values are encrypted under [`BLOB_INDEX_CONTEXT`] bound to the
//! identity's key bytes ([`row_context`]), so an authenticated row cannot
//! be relocated to another identity. A row is content: its inline bytes are
//! the content, and its framing names the rest. In an encrypted store it is
//! therefore read and written only while the blob encryption domain is
//! active, so erasure of the domain revokes every row as it revokes every
//! chunk. Every writer and reader of `BLOB_INDEX` goes through this module,
//! the store's and a retained view's alike ([`decode_sealed`]).

use redb::ReadableTable;

use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;

use crate::PersistentStore;
use crate::blob_encryption::BlobEncryption;
use crate::encrypted::TableEncryptor;
use crate::representation::BlobRecord;
use crate::tables::BLOB_INDEX;

/// Table-encryption context of `BLOB_INDEX` values. The identity's key
/// bytes are appended so a row authenticates only for its own identity.
const BLOB_INDEX_CONTEXT: &str = "blob_index";

/// The encryption context of the row whose key bytes are `key`.
pub fn row_context(key: &[u8]) -> String {
    crate::encrypted::bound(BLOB_INDEX_CONTEXT, key)
}

/// Bytes [`decode_sealed`] allocates for the context of a row whose key is
/// `key_len` bytes long, in a store with table encryption; none without.
pub const fn row_context_allocation(encrypted: bool, key_len: usize) -> u64 {
    if encrypted {
        crate::encrypted::bound_allocation(BLOB_INDEX_CONTEXT, key_len)
    } else {
        0
    }
}

/// Admit an access to a row under `domain`: refused once it is erased.
fn admitted(domain: Option<&BlobEncryption>) -> Result<(), StoreError> {
    domain.map_or(Ok(()), |domain| domain.while_active(|| ()))
}

/// Decrypt and decode a `BLOB_INDEX` value for the identity whose key
/// bytes are `key`, sealed under `table` and admitted under `domain`: the
/// one row decode, for the store and for views that outlive its borrow.
pub fn decode_sealed(
    table: Option<&TableEncryptor>,
    domain: Option<&BlobEncryption>,
    key: &[u8],
    value: &[u8],
) -> Result<BlobRecord, StoreError> {
    admitted(domain)?;
    let plain = match table {
        Some(table) => table
            .decrypt_value(&row_context(key), value)
            .map_err(|error| StoreError::Internal(format!("decrypt: {error}")))?,
        None => value.to_vec(),
    };
    crate::representation_codec::decode(&plain)
}

/// Decrypt and decode a `BLOB_INDEX` value for the identity whose key
/// bytes are `key`, under `store`'s encryption.
pub fn decode_row(
    store: &PersistentStore,
    key: &[u8],
    value: &[u8],
) -> Result<BlobRecord, StoreError> {
    decode_sealed(
        store.table_encryptor.as_deref(),
        store.blob_encryptor.as_deref(),
        key,
        value,
    )
}

/// Committed record of `identity`, read inside `txn`.
pub fn record_in_txn(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    identity: &Kappa,
) -> Result<Option<BlobRecord>, StoreError> {
    let key = identity.key_bytes();
    let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
    index
        .get(key.as_slice())
        .map_err(crate::error::redb)?
        .map(|guard| decode_row(store, &key, guard.value()))
        .transpose()
}

/// Write the row of `identity` inside `txn`.
pub fn write_row(
    store: &PersistentStore,
    txn: &redb::WriteTransaction,
    identity: &Kappa,
    record: &BlobRecord,
) -> Result<(), StoreError> {
    admitted(store.blob_encryptor.as_deref())?;
    let key = identity.key_bytes();
    let value = store.encrypt_bytes(&row_context(&key), record.canonical())?;
    let mut index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
    index
        .insert(key.as_slice(), value.as_slice())
        .map_err(crate::error::redb)?;
    Ok(())
}
