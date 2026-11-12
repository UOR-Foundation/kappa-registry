//! Reads over committed representations.
//!
//! A read starts from the identity's `BLOB_INDEX` row (a projection of
//! epoch-committed installation, [`crate::content_install`]) and selects by
//! representation: inline bytes are the row; an alias is one hop to the
//! row that holds the bytes; external bytes are an allocation pinned for
//! the duration of the read, every delivered chunk verified against the
//! epoch-committed chunk root; composite bytes are the logical
//! concatenation of their components (manifest nodes one level down),
//! located by binary search over cumulative lengths. Full reads verify the
//! whole identity afterwards; range and streaming reads rely on per-chunk
//! verification.
//!
//! Every read runs on the operation's meter: each row looked up, decoded and
//! held, each buffer allocated, each byte read or copied, and each byte
//! hashed is charged before it is done, so a refusal leaves nothing started
//! and is never mistaken for absence. Alias targets and composite members
//! are read on the same meter as the identity that names them.
//!
//! The chunk root a range reader checks is authenticated by epoch state,
//! not by the row (`commitments`, `ReadView::resolve_commitment`). Content
//! without a commitment (records the store produced while sealing) is read
//! in full and verified; it has no range or stream path.
//!
//! [`ReadView`] holds the store parts a reader needs by `Arc`, so a
//! streaming reader outlives the borrow of the store that opened it. The
//! positional and streaming readers are in `content_stream`.

use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;
use redb::{ReadableDatabase, ReadableTable};

use kappa_store::work::{Dimension, Meter, Work};
use kappa_store::{ContentCommitment, Kappa, StoreError, VerifiedContent};

#[cfg(test)]
#[path = "content_read_tests.rs"]
mod tests;

use crate::allocation::Protection;
use crate::content_stream::Opened;
use crate::representation::{BlobRecord, Representation};
use crate::tables::BLOB_INDEX;

mod record;
use crate::PersistentStore;
pub(crate) use record::{RecordEvidence, RecordReader};

/// Largest epoch root blob admitted when loading authenticated history.
pub const MAX_EPOCH_ROOT_BYTES: u64 = 8 * 1024 * 1024;
/// Bytes an encrypted chunk adds to its plaintext: the publication salt
/// (32), frame nonce (8), plaintext size (8), and one AEAD tag.
pub const ENVELOPE_OVERHEAD: u64 = 48 + kappa_crypto::aead::FRAME_TAG_SIZE as u64;

/// Separate ownership for raw inputs and constructed values. Both pools
/// survive with every view and reservation that uses them.
#[derive(Clone)]
pub(crate) struct RecordStorage {
    pub(crate) raw: Arc<kappa_store::capacity::CapacityPool>,
    pub(crate) decoded: Arc<kappa_store::capacity::CapacityPool>,
}

impl RecordStorage {
    pub(crate) fn new(config: &crate::PersistentStoreConfig) -> Result<Self, StoreError> {
        let scratch = (crate::BLOB_CHUNK_SIZE as u64)
            .checked_mul(2)
            .and_then(|bytes| bytes.checked_add(ENVELOPE_OVERHEAD))
            .ok_or_else(|| StoreError::Rejected("record scratch bound overflows".into()))?;
        let one = config
            .settlement_record_bytes
            .checked_add(scratch)
            .ok_or_else(|| StoreError::Rejected("record read bound overflows".into()))?;
        let raw = match config.settlement_read_bytes {
            Some(bytes) => bytes,
            None => one
                .checked_mul(config.max_epoch_cursors as u64)
                .ok_or_else(|| StoreError::Rejected("record read capacity overflows".into()))?,
        };
        if raw < one || config.settlement_decoded_bytes == 0 {
            return Err(StoreError::Rejected(
                "record storage must fit one raw record and have positive decoded capacity".into(),
            ));
        }
        Ok(Self {
            raw: Arc::new(kappa_store::capacity::CapacityPool::new(
                "raw record reads",
                raw,
            )),
            decoded: Arc::new(kappa_store::capacity::CapacityPool::new(
                "decoded records",
                config.settlement_decoded_bytes,
            )),
        })
    }
}

/// The most [`ReadView::sized_record`] charges for one row of at most `row`
/// bytes, in a store with table encryption (the larger case): the key built
/// and the entry examined, then the row read and decoded, its three
/// row-sized buffers and its decryption context. `None` when the bound does
/// not fit in `u64`.
pub(crate) fn record_lookup_cost(row: u64) -> Option<Work> {
    let key = kappa_store::kappa::MAX_KEY_BYTES;
    Work::total(&[
        (Dimension::BytesAllocated, key as u64),
        (Dimension::Entries, 1),
        (Dimension::BytesRead, row),
        (Dimension::BytesDecoded, row),
        (Dimension::BytesAllocated, row.checked_mul(3)?),
        (
            Dimension::BytesAllocated,
            crate::blob_rows::row_context_allocation(true, key),
        ),
    ])
    .ok()
}

/// The most reading `maximum` stored bytes of one inline or external
/// representation charges ([`ReadView::read_stored`] of a non-composite
/// record), in a store with blob encryption (the larger case): the output
/// buffer and the copy into it, and for an external allocation its handle
/// and every chunk's framed buffer and read and decrypted buffer, in chunks
/// of `BLOB_CHUNK_SIZE`. `None` when the bound does not fit in `u64`.
pub(crate) fn stored_read_cost(maximum: u64) -> Option<Work> {
    let chunk = crate::BLOB_CHUNK_SIZE as u64;
    let chunks = maximum.div_ceil(chunk);
    let framed = chunks.checked_mul(chunk.checked_add(ENVELOPE_OVERHEAD)?)?;
    Work::total(&[
        (Dimension::Handles, 1),
        (Dimension::BytesAllocated, maximum),
        (Dimension::BytesAllocated, framed),
        (Dimension::BytesAllocated, maximum),
        (Dimension::BytesRead, framed),
        (Dimension::BytesRead, maximum),
        (Dimension::BytesDecoded, maximum),
    ])
    .ok()
}

/// The most a verified read of one non-composite record of at most
/// `maximum` stored bytes, whose rows are at most `row` bytes, charges
/// (`ReadView::verified_epoch_content`): its row and its alias target's
/// row, its stored bytes, and their hash. `None` when the bound does not
/// fit in `u64`.
pub(crate) fn verified_content_cost(maximum: u64, row: u64) -> Option<Work> {
    let mut cost = record_lookup_cost(row)?;
    cost.checked_add_assign(&record_lookup_cost(row)?).ok()?;
    cost.checked_add_assign(&stored_read_cost(maximum)?).ok()?;
    cost.checked_add_assign(&Work::default().with(Dimension::BytesHashed, maximum))
        .ok()?;
    Some(cost)
}

/// The parts of the store a reader needs over one namespace database,
/// held independently of the store borrow. `retain` keeps the namespace
/// active for a reader that outlives the call that opened it; a view
/// built inside an execution or settlement, which hold their own grant,
/// carries none.
#[derive(Clone)]
pub struct ReadView {
    pub(crate) db: Arc<redb::Database>,
    pub(crate) retain: Option<Arc<crate::storage::Active>>,
    pub(crate) blob_encryptor: Option<Arc<crate::blob_encryption::BlobEncryption>>,
    pub(crate) table_encryptor: Option<Arc<crate::encrypted::TableEncryptor>>,
    pub(crate) protection: Arc<Protection>,
    pub(crate) blob_root: PathBuf,
    pub(crate) commitments: Arc<DashMap<Kappa, ContentCommitment>>,
    pub(crate) authority: Arc<arc_swap::ArcSwap<kappa_store::EpochAuthority>>,
    pub(crate) record_storage: RecordStorage,
}

impl PersistentStore {
    /// A view over the namespace database of `controller`, for a caller
    /// that holds the namespace active itself.
    pub(crate) fn read_view_for(
        &self,
        controller: &crate::storage::NamespaceController,
    ) -> ReadView {
        ReadView {
            db: Arc::clone(&controller.db),
            retain: None,
            blob_encryptor: self.blob_encryptor.clone(),
            table_encryptor: self.table_encryptor.clone(),
            protection: Arc::clone(&self.protection),
            blob_root: self.blob_root.clone(),
            commitments: Arc::clone(&self.commitments),
            authority: Arc::clone(&self.authority),
            record_storage: self.record_storage.clone(),
        }
    }

    /// A view that keeps `active`'s namespace open for its own life.
    pub(crate) fn read_view_retaining(&self, active: crate::storage::Active) -> ReadView {
        let mut view = self.read_view_for(active.controller());
        view.retain = Some(Arc::new(active));
        view
    }

    /// A retained view over `ns`, for reads that open their own
    /// transactions; `namespace_snapshot` adds one transaction to it.
    pub(crate) fn read_view_ns(
        &self,
        ns: &kappa_store::NamespaceRef,
    ) -> Result<ReadView, StoreError> {
        Ok(self.read_view_retaining(self.namespaces.admit_read(ns.id())?))
    }

    /// The committed record of `identity` in a namespace holding it
    /// (`store_access::with_holder`), its candidates located on `work`.
    pub(crate) fn blob_record(
        &self,
        identity: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<BlobRecord, StoreError> {
        self.with_holder(identity, work, |view, work| view.record(identity, work))
    }
}

impl ReadView {
    /// `stored` decrypted under `context`, or a copy of it in a store
    /// without table encryption. The caller charges the output first.
    pub(crate) fn decrypt(&self, context: &str, stored: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.table_encryptor.as_ref().map_or_else(
            || Ok(stored.to_vec()),
            |enc| {
                enc.decrypt_value(context, stored)
                    .map_err(|e| StoreError::Internal(format!("decrypt: {e}")))
            },
        )
    }

    fn decode_row(&self, key: &[u8], value: &[u8]) -> Result<BlobRecord, StoreError> {
        crate::blob_rows::decode_sealed(
            self.table_encryptor.as_deref(),
            self.blob_encryptor.as_deref(),
            key,
            value,
        )
    }

    /// The record of `identity` in `index` and the length of the stored row
    /// it was decoded from: the one metered row read. The key and its
    /// lookup are charged before the lookup; before decoding
    /// (`blob_rows::decode_sealed`, the row-format owner), the row's read
    /// and decoding, the row's decryption context (`blob_rows::row_context`)
    /// in an encrypted store, and the three buffers decoding allocates: the
    /// decrypted plaintext and the record's cached re-encoding
    /// (`BlobRecord::build`), each at most the stored length, and the
    /// decoded representation, charged at the stored length. The decoded
    /// representation's heap is bounded by the format ceilings the decoder
    /// enforces (`MAX_RECORD_BYTES`, `MAX_COMPONENTS`), not proven within
    /// the stored length: the decoder is a symbolic construction.
    pub(crate) fn sized_record(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<(BlobRecord, u64), StoreError> {
        work.charge_all(&[
            (Dimension::BytesAllocated, identity.key_len() as u64),
            (Dimension::Entries, 1),
        ])?;
        let key = identity.key_bytes();
        let guard = index
            .get(key.as_slice())
            .map_err(crate::error::redb)?
            .ok_or_else(|| StoreError::NotFound(format!("blob {identity}")))?;
        let row = guard.value().len() as u64;
        work.charge_all(&[
            (Dimension::BytesRead, row),
            (Dimension::BytesDecoded, row),
            (Dimension::BytesAllocated, row),
            (Dimension::BytesAllocated, row),
            (Dimension::BytesAllocated, row),
            (
                Dimension::BytesAllocated,
                crate::blob_rows::row_context_allocation(self.table_encryptor.is_some(), key.len()),
            ),
        ])?;
        Ok((self.decode_row(&key, guard.value())?, row))
    }

    /// The record of `identity` in `index` ([`Self::sized_record`]).
    pub(crate) fn record_from_table(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<BlobRecord, StoreError> {
        self.sized_record(index, identity, work)
            .map(|(record, _)| record)
    }

    pub(crate) fn record(
        &self,
        identity: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<BlobRecord, StoreError> {
        let txn = self.db.begin_read().map_err(crate::error::redb)?;
        let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        self.record_from_table(&index, identity, work)
    }

    /// Follow an alias to the row holding the bytes. Returns the holding
    /// identity and its record; a non-alias returns itself.
    pub(crate) fn resolve_alias(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        record: BlobRecord,
        work: &mut dyn Meter,
    ) -> Result<(Kappa, BlobRecord), StoreError> {
        match record.representation() {
            Representation::Alias { target } => {
                let held = self.record_from_table(index, target, work)?;
                if matches!(held.representation(), Representation::Alias { .. }) {
                    return Err(StoreError::Internal(format!(
                        "alias {identity} resolves to another alias"
                    )));
                }
                if held.total_size() != record.total_size() {
                    return Err(StoreError::Internal(format!(
                        "alias {identity} disagrees with its target's size"
                    )));
                }
                Ok((target.clone(), held))
            }
            _ => Ok((identity.clone(), record)),
        }
    }

    /// An empty buffer with room for `size` bytes, refused rather than
    /// aborting when the allocation cannot be made. The caller charges it.
    pub(crate) fn reserve(size: u64) -> Result<Vec<u8>, StoreError> {
        let size = usize::try_from(size)
            .map_err(|_| StoreError::CapacityExceeded("blob exceeds address space".into()))?;
        let mut content = Vec::new();
        content
            .try_reserve_exact(size)
            .map_err(|error| StoreError::CapacityExceeded(format!("blob allocation: {error}")))?;
        Ok(content)
    }

    /// Complete stored bytes of `identity` as `index` records them, bounded
    /// by `maximum` before allocation, on `work`. Not verified against the
    /// identity; compressed representations return their compressed bytes.
    /// A manifest node is not addressable content and is refused.
    pub(crate) fn read_stored(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        record: &BlobRecord,
        maximum: Option<u64>,
        work: &mut dyn Meter,
    ) -> Result<Vec<u8>, StoreError> {
        if maximum.is_some_and(|limit| record.stored_size() > limit) {
            return Err(StoreError::CapacityExceeded(format!(
                "blob {identity} exceeds the read limit"
            )));
        }
        let size = record.stored_size();
        match record.representation() {
            Representation::Inline { bytes } => {
                let length = bytes.len() as u64;
                work.charge_all(&[
                    (Dimension::BytesAllocated, length),
                    (Dimension::BytesRead, length),
                ])?;
                let mut content = Self::reserve(length)?;
                content.extend_from_slice(bytes);
                Ok(content)
            }
            Representation::Alias { .. } => {
                let (held_identity, held) =
                    self.resolve_alias(index, identity, record.clone(), work)?;
                self.read_stored(index, &held_identity, &held, maximum, work)
            }
            Representation::External { .. } => {
                work.charge(Dimension::BytesAllocated, size)?;
                let mut source = self.open_external(identity, record, false, work)?;
                let mut content = Self::reserve(size)?;
                for chunk in 0..source.chunk_count {
                    let bytes = source.chunk(chunk, work)?;
                    work.charge(Dimension::BytesRead, bytes.len() as u64)?;
                    content.extend_from_slice(&bytes);
                }
                Ok(content)
            }
            Representation::Manifest { .. } => Err(StoreError::NotFound(format!(
                "{identity} is a manifest node, not addressable content"
            ))),
            Representation::Composite { components, .. } => {
                work.charge(Dimension::BytesAllocated, size)?;
                let mut content = Self::reserve(size)?;
                for component in components {
                    let child = self.record_from_table(index, &component.identity, work)?;
                    if child.total_size() != component.length {
                        return Err(StoreError::Internal(format!(
                            "composite component {} size disagrees with its membership",
                            component.identity
                        )));
                    }
                    let member = self.read_member(index, &component.identity, &child, work)?;
                    work.charge(Dimension::BytesRead, member.len() as u64)?;
                    content.extend_from_slice(&member);
                }
                Ok(content)
            }
        }
    }

    /// Bytes of one composite member: a manifest node yields its leaves'
    /// bytes in order, each leaf verified against its identity.
    fn read_member(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        record: &BlobRecord,
        work: &mut dyn Meter,
    ) -> Result<Vec<u8>, StoreError> {
        if let Representation::Manifest { components, .. } = record.representation() {
            work.charge(Dimension::BytesAllocated, record.stored_size())?;
            let mut content = Self::reserve(record.stored_size())?;
            for component in components {
                let leaf = self.record_from_table(index, &component.identity, work)?;
                if leaf.total_size() != component.length {
                    return Err(StoreError::Internal(format!(
                        "manifest component {} size disagrees with its membership",
                        component.identity
                    )));
                }
                let bytes = self.read_stored(index, &component.identity, &leaf, None, work)?;
                work.charge_all(&[
                    (Dimension::BytesHashed, bytes.len() as u64),
                    (Dimension::BytesRead, bytes.len() as u64),
                ])?;
                let (_, bytes) =
                    VerifiedContent::verify_owned(&component.identity, bytes)?.into_parts();
                content.extend_from_slice(&bytes);
            }
            Ok(content)
        } else {
            let bytes = self.read_stored(index, identity, record, None, work)?;
            work.charge(Dimension::BytesHashed, bytes.len() as u64)?;
            Ok(VerifiedContent::verify_owned(identity, bytes)?
                .into_parts()
                .1)
        }
    }

    /// Bytes `[offset, offset + length)` of `identity`'s logical content,
    /// clipped to its end, on `work`. Composites read only the components
    /// the range touches; external chunks are verified against the
    /// committed root.
    pub(crate) fn range(
        &self,
        identity: &Kappa,
        offset: u64,
        length: u64,
        work: &mut dyn Meter,
    ) -> Result<Vec<u8>, StoreError> {
        let txn = self.db.begin_read().map_err(crate::error::redb)?;
        let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        let record = self.record_from_table(&index, identity, work)?;
        let (identity, record) = self.resolve_alias(&index, identity, record, work)?;
        match record.representation() {
            Representation::Inline { bytes } => {
                let start = usize::try_from(offset.min(bytes.len() as u64)).map_err(|_| {
                    StoreError::Rejected("range offset exceeds address space".into())
                })?;
                let end = usize::try_from(offset.saturating_add(length).min(bytes.len() as u64))
                    .map_err(|_| StoreError::Rejected("range end exceeds address space".into()))?;
                let taken = (end - start) as u64;
                work.charge_all(&[
                    (Dimension::BytesAllocated, taken),
                    (Dimension::BytesRead, taken),
                ])?;
                let mut out = Self::reserve(taken)?;
                out.extend_from_slice(&bytes[start..end]);
                Ok(out)
            }
            Representation::External { .. } => self
                .open_external(&identity, &record, true, work)?
                .range(offset, length, work),
            Representation::Alias { .. } => {
                Err(StoreError::Internal("alias resolved to an alias".into()))
            }
            Representation::Manifest { .. } => Err(StoreError::NotFound(format!(
                "{identity} is a manifest node, not addressable content"
            ))),
            Representation::Composite { .. } => {
                drop(index);
                drop(txn);
                self.member_range(&identity, &record, offset, length, work)
            }
        }
    }

    /// Range over the members of a composite or manifest node, component
    /// by component, each through its own verified read on `work`.
    fn member_range(
        &self,
        identity: &Kappa,
        record: &BlobRecord,
        offset: u64,
        length: u64,
        work: &mut dyn Meter,
    ) -> Result<Vec<u8>, StoreError> {
        let representation = record.representation();
        let components = representation.components();
        let end = offset.saturating_add(length).min(record.total_size());
        let total = end.saturating_sub(offset);
        work.charge(Dimension::BytesAllocated, total)?;
        let mut out = Self::reserve(total)?;
        let mut cursor = offset;
        while cursor < end {
            let Some((position, start)) = representation.component_at(cursor) else {
                break;
            };
            let component = &components[position];
            let within = cursor - start;
            let take = (end - cursor).min(component.length - within);
            let child = self.record(&component.identity, work)?;
            let bytes = if matches!(child.representation(), Representation::Manifest { .. }) {
                self.member_range(&component.identity, &child, within, take, work)?
            } else {
                self.range(&component.identity, within, take, work)?
            };
            if bytes.len() as u64 != take {
                return Err(StoreError::Internal(format!(
                    "component {} of {identity} delivered {} of {take} bytes",
                    component.identity,
                    bytes.len()
                )));
            }
            work.charge(Dimension::BytesRead, take)?;
            out.extend_from_slice(&bytes);
            cursor += take;
        }
        Ok(out)
    }

    /// What a stream over `identity`'s logical content reads, located on
    /// `work`. The caller moves the operation's remaining meter into the
    /// reader made from it (`Opened::reader`).
    pub(crate) fn open(
        &self,
        identity: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Opened, StoreError> {
        let txn = self.db.begin_read().map_err(crate::error::redb)?;
        let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        let record = self.record_from_table(&index, identity, work)?;
        let (identity, record) = self.resolve_alias(&index, identity, record, work)?;
        match record.representation() {
            Representation::Inline { bytes } => {
                let length = bytes.len() as u64;
                work.charge_all(&[
                    (Dimension::BytesAllocated, length),
                    (Dimension::BytesRead, length),
                ])?;
                let mut held = Self::reserve(length)?;
                held.extend_from_slice(bytes);
                Ok(Opened::inline(held, self.blob_encryptor.clone()))
            }
            Representation::External { .. } => Ok(Opened::External(
                self.open_external(&identity, &record, true, work)?,
            )),
            Representation::Alias { .. } => {
                Err(StoreError::Internal("alias resolved to an alias".into()))
            }
            Representation::Manifest { .. } => Err(StoreError::NotFound(format!(
                "{identity} is a manifest node, not addressable content"
            ))),
            Representation::Composite { .. } => Ok(Opened::Composite {
                view: self.clone(),
                size: record.total_size(),
                identity,
            }),
        }
    }
}
