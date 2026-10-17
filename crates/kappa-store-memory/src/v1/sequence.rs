//! Namespace counters. Each advance publishes the canonical
//! `SequenceRecord` and records `SequenceUpdate` naming it, as the
//! persistent backend records it, so the ledger carries every value issued.

use kappa_store::traits::sequence::SequenceStore;
use kappa_types::canonical::canonical_bytes;
use kappa_types::epoch::{MutationOp, SequenceRecord};
use kappa_types::error::StoreError;
use kappa_types::namespace::NamespaceRef;
use kappa_types::{Axis, VerifiedContent};

use super::InMemoryStore;
use super::execution::WriteCx;
use super::view::NamespaceView;

impl WriteCx<'_> {
    /// Advance a namespace counter in the candidate. An exhausted counter
    /// refuses instead of wrapping.
    pub fn sequence_next(&mut self, name: &str) -> Result<u64, StoreError> {
        let value = sequence_current_in(self.view, name)
            .checked_add(1)
            .ok_or_else(|| StoreError::CapacityExceeded(format!("sequence {name} exhausted")))?;
        self.view.sequences.insert(name.to_owned(), value);
        let evidence = canonical_bytes(&SequenceRecord {
            namespace_id: self.ns.id().to_vec(),
            name: name.to_owned(),
            value,
        });
        let content = VerifiedContent::compute(Axis::Sha256, &evidence)?;
        self.publish_content(&content)?;
        self.record(
            MutationOp::SequenceUpdate,
            content.kappa().clone(),
            Some(name.to_owned()),
        );
        Ok(value)
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
