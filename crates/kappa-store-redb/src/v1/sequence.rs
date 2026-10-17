use kappa_store::error::StoreError;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::sequence::SequenceStore;

use crate::PersistentStore;
use crate::tables::SEQUENCES;
use redb::ReadableTable;

/// Binary sequence key: `[ns_uuid:16][name_hash:16]`.
fn seq_key(ns: &NamespaceRef, name: &str) -> Vec<u8> {
    let name_hash = blake3::hash(name.as_bytes());
    let mut k = Vec::with_capacity(32);
    k.extend_from_slice(ns.id());
    k.extend_from_slice(&name_hash.as_bytes()[..16]);
    k
}

// Reservation is `EpochExecution::sequence_next`, which increments through
// `sequence_next_in_txn` and records `SequenceUpdate` evidence in the same
// writer.
impl SequenceStore for PersistentStore {
    fn sequence_current(&self, ns: &NamespaceRef, name: &str) -> Result<u64, StoreError> {
        let snapshot = self.namespace_snapshot(ns)?;
        self.sequence_value(&snapshot.table(SEQUENCES)?, &seq_key(ns, name))
    }
}

/// The AEAD context of the `SEQUENCES` row at `key`.
fn seq_context(key: &[u8]) -> String {
    crate::encrypted::bound("seq", key)
}

impl PersistentStore {
    /// The value of the sequence at `key` in `table`, a snapshot's or an
    /// execution's: 0 before its first reservation.
    fn sequence_value(
        &self,
        table: &impl ReadableTable<&'static [u8], &'static [u8]>,
        key: &[u8],
    ) -> Result<u64, StoreError> {
        table.get(key).map_err(crate::error::redb)?.map_or_else(
            || Ok(0),
            |value| self.decode_seq_value(&seq_context(key), value.value()),
        )
    }

    pub(crate) fn sequence_next_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        name: &str,
    ) -> Result<u64, StoreError> {
        if name.is_empty() {
            return Err(StoreError::Rejected("sequence name is empty".into()));
        }
        let key = seq_key(ns, name);
        let value;
        {
            let mut table = txn.open_table(SEQUENCES).map_err(crate::error::redb)?;
            let current = self.sequence_value(&table, &key)?;
            value = current.checked_add(1).ok_or_else(|| {
                StoreError::CapacityExceeded(format!("sequence exhausted: {ns}:{name}"))
            })?;
            let encoded = self.encode_seq_value(&seq_context(&key), value)?;
            table
                .insert(key.as_slice(), encoded.as_slice())
                .map_err(crate::error::redb)?;
        }
        Ok(value)
    }

    pub(crate) fn sequence_current_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        name: &str,
    ) -> Result<u64, StoreError> {
        let table = txn.open_table(SEQUENCES).map_err(crate::error::redb)?;
        self.sequence_value(&table, &seq_key(ns, name))
    }
}
