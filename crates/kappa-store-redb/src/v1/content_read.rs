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
//! The chunk root a range reader checks is authenticated by epoch state,
//! not by the row: `COMMITMENTS` maps the identity to the epoch that
//! published its `ContentCommitment` and to the commitment's identity; the
//! epoch root is admitted through its signature, its ledger must carry the
//! `ContentPublish` of that commitment, and the commitment content must
//! hash to its identity and name this identity with the row's framing.
//! Admitted commitments are cached per process. Content without a
//! commitment (records the store produced while sealing) is read in full
//! and verified; it has no range or stream path.
//!
//! [`ReadView`] holds the store parts a reader needs by `Arc`, so a
//! streaming reader outlives the borrow of the store that opened it. The
//! positional and streaming readers are in `content_stream`.

use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;
use redb::{ReadableDatabase, ReadableTable};

use kappa_store::epoch::{EpochMutation, MutationOp};
use kappa_store::traits::blob::BlobReader;
use kappa_store::{ContentCommitment, EpochRoot, Kappa, StoreError, VerifiedContent};

#[cfg(test)]
#[path = "content_read_tests.rs"]
mod tests;

use crate::PersistentStore;
use crate::allocation::Protection;
use crate::commitments::{COMMITMENTS_CONTEXT, split_commitment_entry};
use crate::content_stream::{CompositeReader, InlineReader};
use crate::representation::{BlobRecord, Representation};
use crate::tables::{BLOB_INDEX, COMMITMENTS};

/// Largest epoch root blob admitted when loading authenticated history.
pub const MAX_EPOCH_ROOT_BYTES: u64 = 8 * 1024 * 1024;
/// Bytes an encrypted chunk adds to its plaintext: the publication salt
/// (32), frame nonce (8), plaintext size (8), and one AEAD tag.
pub const ENVELOPE_OVERHEAD: u64 = 48 + kappa_crypto::aead::FRAME_TAG_SIZE as u64;

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
    /// (`store_access::with_holder`).
    pub(crate) fn blob_record(&self, identity: &Kappa) -> Result<BlobRecord, StoreError> {
        self.with_holder(identity, |view| view.record(identity))
    }
}

impl ReadView {
    fn decrypt(&self, context: &str, stored: &[u8]) -> Result<Vec<u8>, StoreError> {
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

    pub(crate) fn record_from_table(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
    ) -> Result<BlobRecord, StoreError> {
        let key = identity.key_bytes();
        let guard = index
            .get(key.as_slice())
            .map_err(crate::error::redb)?
            .ok_or_else(|| StoreError::NotFound(format!("blob {identity}")))?;
        self.decode_row(&key, guard.value())
    }

    /// The record of `identity` in `index`, with the length of the stored
    /// row it was decoded from: the bytes the lookup read.
    pub(crate) fn sized_record(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
    ) -> Result<(BlobRecord, u64), StoreError> {
        let key = identity.key_bytes();
        let guard = index
            .get(key.as_slice())
            .map_err(crate::error::redb)?
            .ok_or_else(|| StoreError::NotFound(format!("blob {identity}")))?;
        let row = guard.value().len() as u64;
        Ok((self.decode_row(&key, guard.value())?, row))
    }

    pub(crate) fn record(&self, identity: &Kappa) -> Result<BlobRecord, StoreError> {
        let txn = self.db.begin_read().map_err(crate::error::redb)?;
        let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        self.record_from_table(&index, identity)
    }

    /// Follow an alias to the row holding the bytes. Returns the holding
    /// identity and its record; a non-alias returns itself.
    pub(crate) fn resolve_alias(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        record: BlobRecord,
    ) -> Result<(Kappa, BlobRecord), StoreError> {
        match record.representation() {
            Representation::Alias { target } => {
                let held = self.record_from_table(index, target)?;
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
    /// aborting when the allocation cannot be made.
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
    /// by `maximum` before allocation. Not verified against the identity;
    /// compressed representations return their compressed bytes. A
    /// manifest node is not addressable content and is refused.
    pub(crate) fn read_stored(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        record: &BlobRecord,
        maximum: Option<u64>,
    ) -> Result<Vec<u8>, StoreError> {
        if maximum.is_some_and(|limit| record.stored_size() > limit) {
            return Err(StoreError::CapacityExceeded(format!(
                "blob {identity} exceeds the read limit"
            )));
        }
        match record.representation() {
            Representation::Inline { bytes } => Ok(bytes.clone()),
            Representation::Alias { .. } => {
                let (held_identity, held) = self.resolve_alias(index, identity, record.clone())?;
                self.read_stored(index, &held_identity, &held, maximum)
            }
            Representation::External { .. } => {
                let mut reader = self.open_external(identity, record, false)?;
                let mut content = Self::reserve(record.stored_size())?;
                for chunk in 0..reader.chunk_count {
                    content.extend_from_slice(&reader.chunk(chunk)?);
                }
                Ok(content)
            }
            Representation::Manifest { .. } => Err(StoreError::NotFound(format!(
                "{identity} is a manifest node, not addressable content"
            ))),
            Representation::Composite { components, .. } => {
                let mut content = Self::reserve(record.stored_size())?;
                for component in components {
                    let child = self.record_from_table(index, &component.identity)?;
                    if child.total_size() != component.length {
                        return Err(StoreError::Internal(format!(
                            "composite component {} size disagrees with its membership",
                            component.identity
                        )));
                    }
                    content.extend_from_slice(&self.read_member(
                        index,
                        &component.identity,
                        &child,
                    )?);
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
    ) -> Result<Vec<u8>, StoreError> {
        if let Representation::Manifest { components, .. } = record.representation() {
            let mut content = Self::reserve(record.stored_size())?;
            for component in components {
                let leaf = self.record_from_table(index, &component.identity)?;
                if leaf.total_size() != component.length {
                    return Err(StoreError::Internal(format!(
                        "manifest component {} size disagrees with its membership",
                        component.identity
                    )));
                }
                let bytes = self.read_stored(index, &component.identity, &leaf, None)?;
                VerifiedContent::verify(&component.identity, &bytes)?;
                content.extend_from_slice(&bytes);
            }
            Ok(content)
        } else {
            let bytes = self.read_stored(index, identity, record, None)?;
            VerifiedContent::verify(identity, &bytes)?;
            Ok(bytes)
        }
    }

    /// Uncompressed content `identity`, verified against its identity.
    pub(crate) fn epoch_content_from_index(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        maximum: Option<u64>,
    ) -> Result<Vec<u8>, StoreError> {
        let record = self.record_from_table(index, identity)?;
        if record.compression().is_some() {
            return Err(StoreError::Internal("invalid epoch content framing".into()));
        }
        let bytes = self.read_stored(index, identity, &record, maximum)?;
        VerifiedContent::verify(identity, &bytes)?;
        Ok(bytes)
    }

    pub(crate) fn epoch_root_from_index(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
    ) -> Result<EpochRoot, StoreError> {
        let (root, _) = self.unadmitted_epoch_root(index, identity)?;
        let ledger = self.epoch_content_from_index(index, root.ledger_root(), None)?;
        kappa_store::epoch_publication::verify_persisted_epoch(
            &root,
            &self.authority.load(),
            &ledger,
        )?;
        Ok(root)
    }

    /// The epoch root `identity` decoded from verified bytes, with the
    /// number of bytes read. Neither its authority nor its ledger is
    /// admitted: the caller admits both before trusting it
    /// (`epoch_root_from_index` does so over the whole ledger; settlement
    /// does so incrementally, `settlement_ledger`).
    pub(crate) fn unadmitted_epoch_root(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
    ) -> Result<(EpochRoot, u64), StoreError> {
        let bytes = self.epoch_content_from_index(index, identity, Some(MAX_EPOCH_ROOT_BYTES))?;
        let root = EpochRoot::from_bytes(&bytes)
            .map_err(|error| StoreError::Internal(error.to_string()))?;
        Ok((root, bytes.len() as u64))
    }

    /// The epoch-authenticated commitment for `identity`, admitted once per
    /// process. Absent when no published epoch commits it.
    pub(crate) fn resolve_commitment(
        &self,
        identity: &Kappa,
    ) -> Result<Option<ContentCommitment>, StoreError> {
        if let Some(cached) = self.commitments.get(identity) {
            return Ok(Some(cached.clone()));
        }
        let txn = self.db.begin_read().map_err(crate::error::redb)?;
        let table = txn.open_table(COMMITMENTS).map_err(crate::error::redb)?;
        let key = identity.key_bytes();
        let Some(entry) = table.get(key.as_slice()).map_err(crate::error::redb)? else {
            return Ok(None);
        };
        let value = self.decrypt(
            &crate::encrypted::bound(COMMITMENTS_CONTEXT, &key),
            entry.value(),
        )?;
        drop(entry);
        let (epoch_key, commitment_key) = split_commitment_entry(&value)?;
        let epoch_identity = Kappa::from_key_bytes(epoch_key)?;
        let commitment_identity = Kappa::from_key_bytes(commitment_key)?;
        let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        let root = self.epoch_root_from_index(&index, &epoch_identity)?;
        let ledger = self.epoch_content_from_index(&index, root.ledger_root(), None)?;
        let mutations: Vec<EpochMutation> = kappa_store::canonical::from_canonical(&ledger)?;
        if !mutations.iter().any(|mutation| {
            mutation.op == MutationOp::ContentPublish && mutation.kappa == commitment_identity
        }) {
            return Err(StoreError::Internal(format!(
                "epoch {epoch_identity} does not commit content {identity}"
            )));
        }
        let bytes = self.epoch_content_from_index(&index, &commitment_identity, None)?;
        let commitment: ContentCommitment = kappa_store::canonical::from_canonical(&bytes)?;
        if commitment.identity() != identity {
            return Err(StoreError::Internal(format!(
                "commitment {commitment_identity} names {} not {identity}",
                commitment.identity()
            )));
        }
        self.commitments
            .insert(identity.clone(), commitment.clone());
        Ok(Some(commitment))
    }

    /// Bytes `[offset, offset + length)` of `identity`'s logical content,
    /// clipped to its end. Composites read only the components the range
    /// touches; external chunks are verified against the committed root.
    pub(crate) fn range(
        &self,
        identity: &Kappa,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        let txn = self.db.begin_read().map_err(crate::error::redb)?;
        let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        let record = self.record_from_table(&index, identity)?;
        let (identity, record) = self.resolve_alias(&index, identity, record)?;
        match record.representation() {
            Representation::Inline { bytes } => {
                let start = usize::try_from(offset.min(bytes.len() as u64)).map_err(|_| {
                    StoreError::Rejected("range offset exceeds address space".into())
                })?;
                let end = usize::try_from(offset.saturating_add(length).min(bytes.len() as u64))
                    .map_err(|_| StoreError::Rejected("range end exceeds address space".into()))?;
                Ok(bytes[start..end].to_vec())
            }
            Representation::External { .. } => self
                .open_external(&identity, &record, true)?
                .range(offset, length),
            Representation::Alias { .. } => {
                Err(StoreError::Internal("alias resolved to an alias".into()))
            }
            Representation::Manifest { .. } => Err(StoreError::NotFound(format!(
                "{identity} is a manifest node, not addressable content"
            ))),
            Representation::Composite { .. } => {
                drop(index);
                drop(txn);
                self.member_range(&identity, &record, offset, length)
            }
        }
    }

    /// Range over the members of a composite or manifest node, component
    /// by component, each through its own verified read.
    fn member_range(
        &self,
        identity: &Kappa,
        record: &BlobRecord,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        let representation = record.representation();
        let components = representation.components();
        let end = offset.saturating_add(length).min(record.total_size());
        let mut out = Vec::new();
        let mut cursor = offset;
        while cursor < end {
            let Some((position, start)) = representation.component_at(cursor) else {
                break;
            };
            let component = &components[position];
            let within = cursor - start;
            let take = (end - cursor).min(component.length - within);
            let child = self.record(&component.identity)?;
            let bytes = if matches!(child.representation(), Representation::Manifest { .. }) {
                self.member_range(&component.identity, &child, within, take)?
            } else {
                self.range(&component.identity, within, take)?
            };
            if bytes.len() as u64 != take {
                return Err(StoreError::Internal(format!(
                    "component {} of {identity} delivered {} of {take} bytes",
                    component.identity,
                    bytes.len()
                )));
            }
            out.extend_from_slice(&bytes);
            cursor += take;
        }
        Ok(out)
    }

    /// Streaming reader over `identity`'s logical content.
    pub(crate) fn open(&self, identity: &Kappa) -> Result<Box<dyn BlobReader>, StoreError> {
        let txn = self.db.begin_read().map_err(crate::error::redb)?;
        let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        let record = self.record_from_table(&index, identity)?;
        let (identity, record) = self.resolve_alias(&index, identity, record)?;
        match record.representation() {
            Representation::Inline { bytes } => Ok(Box::new(InlineReader::new(
                bytes.clone(),
                self.blob_encryptor.clone(),
            ))),
            Representation::External { .. } => {
                Ok(Box::new(self.open_external(&identity, &record, true)?))
            }
            Representation::Alias { .. } => {
                Err(StoreError::Internal("alias resolved to an alias".into()))
            }
            Representation::Manifest { .. } => Err(StoreError::NotFound(format!(
                "{identity} is a manifest node, not addressable content"
            ))),
            Representation::Composite { .. } => Ok(Box::new(CompositeReader::new(
                self.clone(),
                identity,
                record.total_size(),
            ))),
        }
    }
}
