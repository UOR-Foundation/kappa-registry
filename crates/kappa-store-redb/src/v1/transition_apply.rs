//! The one application boundary of redb's namespace transitions.
//!
//! Every write of an execution reaches the namespace's transaction through
//! [`TxnWriter::apply`]: the record is bound to its canonical evidence in
//! the namespace instance (`PreparedTransition::bind`), its private payload
//! checked against that evidence (`PreparedWrite::bind`), and the bundle
//! consumed once. Consumption installs the evidence as a record of the
//! namespace, dispatches the authoritative row effect to the family's
//! native helper, and writes one `MUTATION_BUFFER` row holding the
//! transition's mutation, its derived index change, its evidence bytes and
//! the custody form of its private payload (`custody::CustodyPayload`), so
//! the seal reads exactly the effects this boundary applied, in execution
//! order, and can hold in custody everything needed to apply them again.
//! No family writes rows, evidence or mutations any other way.
//!
//! A row is sealed under the table key bound to its key, so a payload's
//! secrets never reach a page in the clear, and holds `[path:32]
//! [present:1][value:32 when present][mutation length:4 BE][canonical
//! mutation][evidence length:4 BE][evidence][canonical custody payload]`.
//! The buffer is drained by the seal before its transaction commits
//! (`epoch_seal`), so rows never persist.
//!
//! A writer borrows the allowance of the operation it writes for (an
//! execution's own meter, or a custody resolution's attempt) for its whole
//! life: a row effect whose work is metered (succession admission) charges
//! that allowance, never one of its own.

use std::cell::RefCell;
use std::sync::atomic::Ordering;

use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::transition::{
    PreparedResource, PreparedTransition, PreparedWrite, PrivatePayload, RecordTransition,
    TransitionDomain,
};
use kappa_store::work::{Dimension, Meter, WorkMeter};
use kappa_store::{
    Axis, ClockMs, ContentAdmissionEvidence, ContentAdmissionRecord, ContentCommitment, Kappa,
    LogicalIncarnation, MetadataSubject, NamespaceRef, StoreError, VerifiedContent,
};
use kappa_types::epoch::EpochMutation;
use kappa_types::state_index::Change;

use crate::PersistentStore;
use crate::content_install::{PreparedContent, canonical_order};
use crate::custody::CustodyPayload;
use crate::epoch_blob::blob_put_in_txn;
use crate::representation::Representation;
use crate::storage::IncarnationUse;
use crate::tables::MUTATION_BUFFER;

/// redb's prepared-write payload: the shared pairing of transitions to
/// private resources, with redb's prepared content.
pub type RedbPayload = PrivatePayload<Box<PreparedContent>>;

/// Prepared content installs only into the store that prepared it, under
/// the admission of its canonical holder at its size: verified bytes for an
/// inline representation, the chunk commitment of an external one.
impl PreparedResource for Box<PreparedContent> {
    type Context = PersistentStore;

    fn validate_admission(
        &self,
        record: &ContentAdmissionRecord,
        store: &PersistentStore,
    ) -> Result<(), StoreError> {
        if !self.owned_by_store(store) {
            return Err(StoreError::Rejected(
                "prepared content belongs to another store".into(),
            ));
        }
        let admission = record.admission();
        let (holder, _) = canonical_order(self.identity().clone(), self.aliases().to_vec());
        if &holder != admission.identity() || self.record().total_size() != admission.logical_size()
        {
            return Err(StoreError::Rejected(
                "prepared content differs from its admission".into(),
            ));
        }
        let corresponds = match (self.record().representation(), record.evidence()) {
            (
                Representation::External {
                    chunk_size,
                    chunk_root,
                    ..
                },
                ContentAdmissionEvidence::Chunked(commitment),
            ) => *commitment == ContentCommitment::new(holder, *chunk_size, *chunk_root)?,
            (Representation::Inline { .. }, ContentAdmissionEvidence::VerifiedBytes) => true,
            _ => false,
        };
        if !corresponds {
            return Err(StoreError::Rejected(
                "prepared content evidence differs from its representation".into(),
            ));
        }
        Ok(())
    }
}

/// One namespace transaction an execution writes through: its store, its
/// transaction, its namespace instance, its time, and the allowance of the
/// operation it writes for.
pub struct TxnWriter<'t> {
    pub(crate) store: &'t PersistentStore,
    pub(crate) txn: &'t redb::WriteTransaction,
    pub(crate) ns: &'t NamespaceRef,
    pub(crate) now: ClockMs,
    incarnation: LogicalIncarnation,
    /// The operation's allowance, borrowed for this writer's life; row
    /// effects take `&self`, so it is lent one effect at a time.
    meter: RefCell<&'t mut dyn Meter>,
}

impl<'t> TxnWriter<'t> {
    /// A writer over `txn` of `ns` on `meter`, the allowance of the
    /// operation it writes for, binding every transition to the logical
    /// incarnation of the namespace's open controller
    /// (`NamespaceController::logical_incarnation`).
    pub(crate) fn new(
        store: &'t PersistentStore,
        txn: &'t redb::WriteTransaction,
        ns: &'t NamespaceRef,
        now: ClockMs,
        meter: &'t mut dyn Meter,
    ) -> Result<Self, StoreError> {
        let incarnation = store
            .controller(ns)?
            .logical_incarnation(IncarnationUse::Transition)?;
        Ok(Self {
            store,
            txn,
            ns,
            now,
            incarnation,
            meter: RefCell::new(meter),
        })
    }

    /// Run `metered` on the operation's allowance. A row effect that is
    /// already metering cannot lend it again: that is a defect of the
    /// effect, refused rather than double-borrowed.
    pub(crate) fn metered<T>(
        &self,
        metered: impl FnOnce(&mut dyn Meter) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut meter = self.meter.try_borrow_mut().map_err(|_| {
            StoreError::Internal("a transition writer lent its allowance twice".into())
        })?;
        metered(&mut **meter)
    }

    /// The transition domain of this writer's namespace instance.
    pub(crate) const fn domain(&self) -> TransitionDomain {
        TransitionDomain::new(*self.ns.id(), self.incarnation)
    }

    /// The representation of the incarnation this writer's transitions
    /// bind, for the records that carry it.
    pub(crate) const fn incarnation(&self) -> &[u8; 16] {
        self.incarnation.as_bytes()
    }

    /// Bind `record` to its canonical evidence, check `payload` against it,
    /// and consume both (see the module documentation). Returns the
    /// evidence identity the ledger names.
    pub(crate) fn apply(
        &self,
        record: RecordTransition,
        payload: RedbPayload,
    ) -> Result<Kappa, StoreError> {
        let evidence = VerifiedContent::compute(Axis::Sha256, &record.canonical_bytes())?;
        let transition = PreparedTransition::bind(self.domain(), record, evidence, self.now)?;
        let prepared = PreparedWrite::bind(transition, payload, self.store)?;
        self.apply_prepared(prepared)
    }

    /// Consume a bound write, including one decoded from durable custody.
    /// Recovery preserves the original evidence and mutation timestamp.
    pub(crate) fn apply_prepared(
        &self,
        prepared: PreparedWrite<RedbPayload>,
    ) -> Result<Kappa, StoreError> {
        let (record, evidence, mutation, change, payload) =
            prepared.into_parts(self.ns, &self.incarnation)?;
        let identity = evidence.kappa().clone();
        let custodied = CustodyPayload::of(&payload);
        blob_put_in_txn(self.store, self.txn, self.ns, &evidence)?;
        self.apply_row_effect(record, evidence.kappa(), payload)?;
        self.buffer(&Buffered {
            mutation,
            change,
            evidence: evidence.content().to_vec(),
            payload: custodied,
        })?;
        Ok(identity)
    }

    /// Dispatch the authoritative row change of one transition, whose
    /// evidence is `evidence`, to its family's native helper, consuming the
    /// payload. The helpers emit no evidence, mutation or index change.
    fn apply_row_effect(
        &self,
        record: RecordTransition,
        evidence: &Kappa,
        payload: RedbPayload,
    ) -> Result<(), StoreError> {
        match (record, payload) {
            (RecordTransition::TagSet(entry), PrivatePayload::NoResources) => {
                self.apply_tag_set(&entry)
            }
            (RecordTransition::TagDelete(entry), PrivatePayload::NoResources) => {
                self.apply_tag_delete(&entry)
            }
            (RecordTransition::EdgePut(input), PrivatePayload::NoResources) => {
                self.apply_edge_put(evidence, &input)
            }
            (RecordTransition::EdgeDelete(input), PrivatePayload::NoResources) => {
                self.apply_edge_delete(evidence, &input)
            }
            (RecordTransition::Sequence(record), PrivatePayload::NoResources) => {
                self.apply_sequence(&record)
            }
            (RecordTransition::Metadata(meta), PrivatePayload::NoResources) => {
                match meta.subject() {
                    MetadataSubject::Namespace => {
                        self.apply_namespace_meta(meta.key(), meta.value())
                    }
                    MetadataSubject::Blob(identity) => {
                        self.apply_blob_meta(identity, meta.key(), meta.value())
                    }
                }
            }
            (RecordTransition::NamespaceUpdate(info), PrivatePayload::NoResources) => {
                self.apply_namespace_record(&info)
            }
            (RecordTransition::Assertion(assertion), PrivatePayload::NoResources) => {
                self.apply_assertion(evidence, &assertion)
            }
            (RecordTransition::Revocation(revocation), PrivatePayload::NoResources) => {
                self.apply_revocation(evidence, &revocation)
            }
            (RecordTransition::Watermark(watermark), PrivatePayload::NoResources) => {
                self.apply_watermark(evidence, &watermark)
            }
            (RecordTransition::Succession(succession), PrivatePayload::NoResources) => {
                self.apply_succession(&succession)
            }
            (RecordTransition::Member(member), PrivatePayload::NoResources) => {
                self.apply_member(&member)
            }
            (RecordTransition::Session(session), PrivatePayload::SessionMetadata(metadata)) => {
                self.apply_session_set(&session, &metadata)
            }
            (RecordTransition::Session(session), PrivatePayload::NoResources) => {
                self.apply_session_delete(&session)
            }
            (
                RecordTransition::Credential(credential),
                PrivatePayload::CredentialSecrets {
                    secret_hash,
                    grace_secret_hash,
                },
            ) => self.apply_credential_set(&credential, &secret_hash, grace_secret_hash.as_deref()),
            (RecordTransition::Credential(credential), PrivatePayload::NoResources) => {
                self.apply_credential_delete(&credential)
            }
            (RecordTransition::Trust(position), PrivatePayload::NoResources) => {
                self.apply_trust(&position)
            }
            (
                RecordTransition::ContentPublish(record),
                PrivatePayload::PreparedContent(prepared),
            ) => self.apply_prepared_admission(&record, *prepared),
            (
                RecordTransition::ContentPublish(record) | RecordTransition::RecordPublish(record),
                PrivatePayload::ExplicitRecord(content),
            ) => self.apply_record_admission(&record, &content),
            (RecordTransition::ContentAlias(record), PrivatePayload::NoResources) => {
                self.apply_alias_admission(&record)
            }
            (RecordTransition::ContentCompose(record), PrivatePayload::NoResources) => {
                self.apply_composite_admission(&record)
            }
            (RecordTransition::ContentRetire(record), PrivatePayload::NoResources) => {
                self.apply_retirement(&record)
            }
            // The receipt changes no row here; its root lookup is stored
            // once the seal names the root (`store_operation_coordinates`).
            (RecordTransition::OperationPublish(_), PrivatePayload::NoResources) => Ok(()),
            (_, _) => Err(StoreError::Internal(
                "a transition reached application with a payload binding refused".into(),
            )),
        }
    }

    /// Write the buffer row of one applied transition, and raise the
    /// namespace's committed time floor to its time.
    fn buffer(&self, buffered: &Buffered) -> Result<(), StoreError> {
        self.store.record_time_in_txn(self.txn, self.now)?;
        let controller = self.store.controller(self.ns)?;
        let sequence = controller
            .mutation_seq
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| StoreError::Internal("mutation sequence exhausted".into()))?;
        let mut key = Vec::with_capacity(24);
        key.extend_from_slice(self.ns.id());
        key.extend_from_slice(&sequence.to_be_bytes());
        let sealed = self
            .store
            .encrypt_bytes(&row_context(&key), &buffered.encode()?)?;
        self.txn
            .open_table(MUTATION_BUFFER)
            .map_err(crate::error::redb)?
            .insert(key.as_slice(), sealed.as_slice())
            .map_err(crate::error::redb)?;
        Ok(())
    }
}

/// The AEAD context of the `MUTATION_BUFFER` row at `key`.
fn row_context(key: &[u8]) -> String {
    crate::encrypted::bound("mutation_buffer", key)
}

/// One applied transition as the buffer holds it: its ledger entry, the
/// index change it derived, its evidence bytes, and the custody form of its
/// private payload.
pub(crate) struct Buffered {
    pub(crate) mutation: EpochMutation,
    pub(crate) change: Change,
    pub(crate) evidence: Vec<u8>,
    pub(crate) payload: CustodyPayload,
}

/// A length prefix of a buffer row's part.
fn length_prefix(part: &[u8]) -> Result<[u8; 4], StoreError> {
    u32::try_from(part.len())
        .map(u32::to_be_bytes)
        .map_err(|_| StoreError::CapacityExceeded("mutation buffer part exceeds u32".into()))
}

/// The part of `rest` its 4-byte big-endian length prefix delimits, and
/// what follows it.
fn length_prefixed(rest: &[u8]) -> Option<(&[u8], &[u8])> {
    let (length, rest) = rest.split_first_chunk::<4>()?;
    let length = usize::try_from(u32::from_be_bytes(*length)).ok()?;
    (rest.len() >= length).then(|| rest.split_at(length))
}

impl Buffered {
    /// The row layout of the module documentation.
    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mutation = canonical_bytes(&self.mutation);
        let payload = canonical_bytes(&self.payload);
        let (path, value) = self.change;
        let mut row =
            Vec::with_capacity(73 + mutation.len() + 4 + self.evidence.len() + payload.len());
        row.extend_from_slice(&path);
        match value {
            Some(value) => {
                row.push(1);
                row.extend_from_slice(&value);
            }
            None => row.push(0),
        }
        row.extend_from_slice(&length_prefix(&mutation)?);
        row.extend_from_slice(&mutation);
        row.extend_from_slice(&length_prefix(&self.evidence)?);
        row.extend_from_slice(&self.evidence);
        row.extend_from_slice(&payload);
        Ok(row)
    }

    fn decode(row: &[u8]) -> Result<Self, StoreError> {
        let malformed = || StoreError::Internal("mutation buffer row is malformed".into());
        let (path, rest) = row.split_first_chunk::<32>().ok_or_else(malformed)?;
        let (present, rest) = rest.split_first().ok_or_else(malformed)?;
        let (value, rest) = match present {
            0 => (None, rest),
            1 => {
                let (value, rest) = rest.split_first_chunk::<32>().ok_or_else(malformed)?;
                (Some(*value), rest)
            }
            _ => return Err(malformed()),
        };
        let (mutation, rest) = length_prefixed(rest).ok_or_else(malformed)?;
        let (evidence, payload) = length_prefixed(rest).ok_or_else(malformed)?;
        Ok(Self {
            mutation: from_canonical(mutation)?,
            change: (*path, value),
            evidence: evidence.to_vec(),
            payload: from_canonical(payload)?,
        })
    }
}

impl PersistentStore {
    /// The applied transitions buffered in `txn` for namespace `uuid`, in
    /// execution order: what the seal commits and holds in custody. Each
    /// row is charged to `meter` before it is decrypted and decoded: one
    /// entry, and its sealed length read, allocated for the plaintext and
    /// decoded.
    pub(crate) fn buffered_transitions(
        &self,
        txn: &redb::WriteTransaction,
        uuid: &[u8; 16],
        meter: &mut WorkMeter,
    ) -> Result<Vec<Buffered>, StoreError> {
        use redb::ReadableTable;
        let buffer = txn
            .open_table(MUTATION_BUFFER)
            .map_err(crate::error::redb)?;
        let prefix = uuid.as_slice();
        let end = Self::prefix_successor(prefix);
        let range = match &end {
            Some(end) => buffer
                .range(prefix..end.as_slice())
                .map_err(crate::error::redb)?,
            None => buffer.range(prefix..).map_err(crate::error::redb)?,
        };
        let mut rows = Vec::new();
        for entry in range {
            let (key, value) = entry.map_err(crate::error::redb)?;
            let sealed = value.value().len() as u64;
            meter.charge_all(&[
                (Dimension::Entries, 1),
                (Dimension::BytesRead, sealed),
                (Dimension::BytesAllocated, sealed),
                (Dimension::BytesDecoded, sealed),
            ])?;
            let row = self.decrypt_bytes(&row_context(key.value()), value.value())?;
            rows.push(Buffered::decode(&row)?);
        }
        Ok(rows)
    }
}
