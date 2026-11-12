//! Namespace counters. Each advance publishes the canonical
//! `SequenceRecord` and records `SequenceUpdate` naming it, as the
//! persistent backend records it, so the ledger carries every value issued.

use kappa_store::traits::sequence::SequenceStore;
use kappa_store::transition::RecordTransition;

use kappa_types::epoch::SequenceRecord;
use kappa_types::error::StoreError;
use kappa_types::namespace::NamespaceRef;

use super::InMemoryStore;
use super::execution::{MemoryPayload, WriteCx};
use super::view::NamespaceView;

impl WriteCx<'_> {
    /// Advance a namespace counter in the candidate. An exhausted counter
    /// refuses instead of wrapping.
    pub fn sequence_next(&mut self, name: &str) -> Result<u64, StoreError> {
        let value =
            kappa_store::traits::sequence::next_value(name, sequence_current_in(self.view, name))?;
        self.apply_record_transition(
            RecordTransition::Sequence(SequenceRecord {
                namespace_id: self.ns.id().to_vec(),
                name: name.to_owned(),
                value,
            }),
            MemoryPayload::NoResources,
        )?;
        Ok(value)
    }

    /// Hold the counter value `record` issued. Called only by `apply_write`.
    pub(super) fn apply_sequence(&mut self, record: SequenceRecord) {
        self.view.sequences.insert(record.name, record.value);
    }
}

pub fn sequence_current_in(view: &NamespaceView, name: &str) -> u64 {
    view.sequences.get(name).copied().unwrap_or(0)
}

impl SequenceStore for InMemoryStore {
    fn sequence_current(&self, ns: &NamespaceRef, name: &str) -> Result<u64, StoreError> {
        Ok(sequence_current_in(&self.view(ns.id()), name))
    }
}
