//! Retained full seal-record reads over a caller's captured index.
use super::ReadView;
use crate::content_stream::ExternalSource;
use crate::representation::Representation;
use kappa_store::capacity::{CapacityPool, Reservation};
use kappa_store::work::{Dimension, Meter, Work};
use kappa_store::{Kappa, StoreError};
use kappa_types::verified::{ContentVerification, VerifiedContent};
use redb::ReadableTable;
use std::sync::Arc;

pub(crate) struct RecordReader {
    verification: ContentVerification,
    source: Option<ExternalSource>,
    next_chunk: u32,
    raw_storage: Arc<CapacityPool>,
    reservation: Reservation,
}

/// Bytes are dropped before their capacity reservation is released.
pub(crate) struct RecordEvidence {
    pub(crate) content: VerifiedContent,
    _reservation: Reservation,
}

impl RecordReader {
    pub(crate) fn locate(
        view: &ReadView,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        limit: u64,
        work: &mut dyn Meter,
    ) -> Result<Self, StoreError> {
        if identity.axis() != kappa_types::Axis::Sha256 {
            return Err(StoreError::Rejected(
                "epoch seal record must use SHA-256".into(),
            ));
        }
        let record = view.record_from_table(index, identity, work)?;
        let (held, record) = view.resolve_alias(index, identity, record, work)?;
        if record.compression().is_some()
            || matches!(
                record.representation(),
                Representation::Composite { .. } | Representation::Manifest { .. }
            )
        {
            return Err(StoreError::Internal("invalid epoch content framing".into()));
        }
        let stored = record.stored_size();
        if stored > limit {
            return Err(StoreError::CapacityExceeded(format!(
                "epoch record {identity} is {stored} bytes, beyond the record limit {limit}"
            )));
        }
        work.charge(Dimension::BytesAllocated, stored)?;
        let reservation = view
            .record_storage
            .raw
            .reserve(stored)
            .map_err(|error| StoreError::CapacityExceeded(error.to_string()))?;
        let buffer = ReadView::reserve(stored)?;
        let extent = usize::try_from(stored).map_err(|_| {
            StoreError::CapacityExceeded("record extent exceeds address space".into())
        })?;
        let mut verification = ContentVerification::new(identity.clone(), buffer, extent)?;
        let source = match record.representation() {
            Representation::Inline { bytes } => {
                work.charge_all(&[
                    (Dimension::BytesRead, bytes.len() as u64),
                    (Dimension::BytesHashed, bytes.len() as u64),
                ])?;
                verification.append(bytes)?;
                None
            }
            Representation::External { .. } => {
                Some(view.open_external(&held, &record, false, work)?)
            }
            _ => return Err(StoreError::Internal("invalid epoch content framing".into())),
        };
        Ok(Self {
            verification,
            source,
            next_chunk: 0,
            raw_storage: Arc::clone(&view.record_storage.raw),
            reservation,
        })
    }

    pub(crate) fn complete(&self) -> bool {
        self.source
            .as_ref()
            .is_none_or(|source| self.next_chunk >= source.chunk_count)
    }

    pub(crate) fn chunk_cost(&self) -> Result<Work, StoreError> {
        let source = self
            .source
            .as_ref()
            .ok_or_else(|| StoreError::Internal("inline record has no next chunk".into()))?;
        let mut cost = source.unverified_chunk_cost(self.next_chunk)?;
        let length = source.plain_len(self.next_chunk);
        cost.checked_add_assign(
            &Work::default()
                .with(Dimension::BytesRead, length)
                .with(Dimension::BytesHashed, length),
        )
        .map_err(|_| StoreError::CapacityExceeded("record chunk work overflows".into()))?;
        Ok(cost)
    }

    pub(crate) fn read_chunk(&mut self, unit: &mut dyn Meter) -> Result<(), StoreError> {
        let next = self.next_chunk.checked_add(1).ok_or_else(|| {
            StoreError::CapacityExceeded("record chunk position overflows".into())
        })?;
        // Frame and decrypted output can coexist. Their allocation requests
        // bound scratch while the raw destination remains separately held.
        let scratch = self.chunk_cost()?.get(Dimension::BytesAllocated);
        let _scratch = self
            .raw_storage
            .reserve(scratch)
            .map_err(|error| StoreError::CapacityExceeded(error.to_string()))?;
        let source = self
            .source
            .as_mut()
            .ok_or_else(|| StoreError::Internal("inline record has no next chunk".into()))?;
        let chunk = source.chunk(self.next_chunk, unit)?;
        unit.account(Dimension::BytesRead, chunk.len() as u64)?;
        unit.account(Dimension::BytesHashed, chunk.len() as u64)?;
        self.verification.append(&chunk)?;
        self.next_chunk = next;
        Ok(())
    }

    pub(crate) fn finish(self) -> Result<RecordEvidence, StoreError> {
        if !self.complete() {
            return Err(StoreError::Internal(
                "epoch record finished before reading completed".into(),
            ));
        }
        Ok(RecordEvidence {
            content: self.verification.finish()?,
            _reservation: self.reservation,
        })
    }

    pub(crate) fn read_to_end(
        mut self,
        work: &mut dyn Meter,
    ) -> Result<RecordEvidence, StoreError> {
        while !self.complete() {
            let cost = self.chunk_cost()?;
            let mut unit = work.admit(&cost.as_bound())?;
            self.read_chunk(&mut unit)?;
        }
        self.finish()
    }
}
