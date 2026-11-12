//! Namespace counters. Each advance is applied through the transition
//! boundary as the canonical `SequenceRecord` naming the value issued, so
//! the ledger carries every value.

use kappa_store::error::StoreError;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::sequence::SequenceStore;
use kappa_store::transition::RecordTransition;
use kappa_types::epoch::SequenceRecord;

use crate::PersistentStore;
use crate::tables::SEQUENCES;
use crate::transition_apply::{RedbPayload, TxnWriter};
use redb::ReadableTable;

/// Binary sequence key: `[ns_uuid:16][name_hash:16]`.
fn seq_key(ns: &NamespaceRef, name: &str) -> Vec<u8> {
    let name_hash = blake3::hash(name.as_bytes());
    let mut k = Vec::with_capacity(32);
    k.extend_from_slice(ns.id());
    k.extend_from_slice(&name_hash.as_bytes()[..16]);
    k
}

// Reservation is `EpochExecution::sequence_next`, through
// `TxnWriter::sequence_next` in the execution's writer.
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

impl TxnWriter<'_> {
    /// Advance the namespace counter `name`, applied as the `Sequence`
    /// transition naming the value issued. An exhausted counter refuses
    /// instead of wrapping.
    pub(crate) fn sequence_next(&self, name: &str) -> Result<u64, StoreError> {
        let current = self
            .store
            .sequence_current_in_txn(self.txn, self.ns, name)?;
        let value = kappa_store::traits::sequence::next_value(name, current)?;
        self.apply(
            RecordTransition::Sequence(SequenceRecord {
                namespace_id: self.ns.id().to_vec(),
                name: name.to_owned(),
                value,
            }),
            RedbPayload::NoResources,
        )?;
        Ok(value)
    }

    /// Hold the counter value `record` issues, which must be the successor
    /// of the value held. Called only by `apply`.
    pub(crate) fn apply_sequence(&self, record: &SequenceRecord) -> Result<(), StoreError> {
        let key = seq_key(self.ns, &record.name);
        let mut table = self.txn.open_table(SEQUENCES).map_err(crate::error::redb)?;
        let current = self.store.sequence_value(&table, &key)?;
        let expected = kappa_store::traits::sequence::next_value(&record.name, current)?;
        if record.value != expected {
            return Err(StoreError::Internal(format!(
                "sequence {} issues {}; its successor is {expected}",
                record.name, record.value
            )));
        }
        let encoded = self
            .store
            .encode_seq_value(&seq_context(&key), record.value)?;
        table
            .insert(key.as_slice(), encoded.as_slice())
            .map_err(crate::error::redb)?;
        Ok(())
    }
}
