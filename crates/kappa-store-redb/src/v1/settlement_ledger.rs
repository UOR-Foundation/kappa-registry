//! Bounded reading of one committed epoch for settlement and recovery.
//!
//! An [`EpochCursor`] reads one epoch of one storage instance across as
//! many steps as its budget requires, never more than a step's [`Work`]:
//!
//! 1. the seal's own records (root, ledger, rotation evidence, predecessor)
//!    are resolved against the instance's rows;
//! 2. the ledger is read in bounded units, split into its canonical
//!    elements, and each element decoded, hashed and folded into the
//!    mutation tree, and staged (`settlement_stage`) as it is decoded;
//! 3. the `EDGE_FWD` targets sourced at the root are resolved through one
//!    retained value iterator, advanced across steps;
//! 4. the epoch is verified: the root's authority is admitted when the
//!    cursor opens, and when the last element is decoded the ledger identity
//!    and mutation root computed over every persisted byte must equal the
//!    root's (`check_ledger_digests`).
//!
//! Everything the cursor emits before [`Advance::Verified`] is unadmitted:
//! its consumer stages it as disposable work and admits it only on
//! verification. The cursor holds no population of the epoch: its decode
//! state is one element (at most `record_bytes`) plus one read unit, the
//! hash state and the tree's peaks.
//!
//! The cursor owns, until it is verified or discarded, one snapshot of the
//! instance's namespace (`namespace_snapshot`: its activity grant, taken
//! once when it opens, and one read transaction of its database), and the
//! table and edge iterator opened in it, so every read of the epoch comes
//! from one snapshot and the database can be neither evicted nor retired
//! under it. The storage must be storage the instance's records may have
//! been written for (`Identification::permits_settlement`). Fields drop in
//! declaration order: iterator, table, then the snapshot (its transaction,
//! then its grant). Cursors live inside the store
//! (`PersistentStore::epoch_cursors`), whose filesystem owner is released
//! after every cursor. A cursor is process state: after a restart its
//! position is gone and the epoch is read again from the authenticated
//! evidence.

use redb::{MultimapValue, ReadOnlyTable, ReadTransaction};

use kappa_store::canonical::from_canonical;
use kappa_store::epoch::EpochMutation;
use kappa_store::epoch_authority::EpochAuthority;
use kappa_store::epoch_publication::{check_ledger_digests, verify_epoch_authority};
use kappa_store::{EpochRoot, Kappa, NamespaceRef, StoreError};
use kappa_types::canonical::canonical_bytes;
use kappa_types::kappa_streaming::IncrementalHasher;
use kappa_types::merkle::StreamingTree;

use super::cbor::{head, item_len};
use super::stage::{Reads, Staged, admit, stage_mutation};
use super::work::{SettlementLimits, Work};
use crate::PersistentStore;
use crate::epoch::epoch_idx_key;
use crate::namespace_snapshot::{InstanceAdmission, NamespaceSnapshot};
use crate::representation::{BlobRecord, Representation};
use crate::storage::NamespaceStorage;
use crate::storage_instance::StorageInstance;
use crate::tables::{BLOB_INDEX, EDGE_FWD, EPOCH_INDEX};

/// Bytes of ledger one read takes at most.
const READ_UNIT: u64 = crate::BLOB_CHUNK_SIZE as u64;

/// What one advance of a cursor reached.
pub enum Advance {
    /// The budget ran out first; the cursor keeps its position.
    Pending,
    /// The epoch is read and verified: everything emitted is admitted.
    Verified,
}

enum Phase {
    Seal(usize),
    Ledger,
    Edges,
    Verified,
}

/// One epoch of one storage instance being read; see the module docs.
pub struct EpochCursor {
    /// Owns its transaction guard and pages: redb's value iterator needs
    /// no table retained beside it.
    edges: Option<MultimapValue<'static, &'static [u8]>>,
    index: ReadOnlyTable<&'static [u8], &'static [u8]>,
    snapshot: NamespaceSnapshot,
    epoch: u64,
    root_identity: Kappa,
    root: EpochRoot,
    seal: Vec<Kappa>,
    ledger: BlobRecord,
    ledger_size: u64,
    phase: Phase,
    position: u64,
    buffer: Vec<u8>,
    consumed: usize,
    remaining: Option<u64>,
    hasher: Option<IncrementalHasher>,
    tree: Option<StreamingTree>,
}

/// Retained across steps under the recovery lock: it must move between the
/// threads that run steps.
const _: fn() = || {
    const fn send<T: Send>() {}
    send::<EpochCursor>();
};

impl EpochCursor {
    /// Open epoch `epoch` of `instance`: take the namespace's activity
    /// grant, refuse storage of another instance, read and decode the root
    /// the epoch index names, admit its authority, and capture its ledger
    /// row. Requires `limits.mutation_quantum()` of `work`, which covers the
    /// root and the ledger row; `None` when the budget does not.
    pub(super) fn open(
        store: &PersistentStore,
        instance: &StorageInstance,
        epoch: u64,
        limits: SettlementLimits,
        work: &mut Work,
    ) -> Result<Option<Self>, StoreError> {
        if !work.admits(limits.mutation_quantum()) {
            return Ok(None);
        }
        let snapshot = match store.admit_instance(instance) {
            InstanceAdmission::Held {
                snapshot,
                identification,
            } if identification.permits_settlement() => snapshot,
            InstanceAdmission::Held { snapshot, .. } => {
                return Err(StoreError::Conflict(format!(
                    "storage of {} is instance {}, not {instance}",
                    hex::encode(instance.namespace()),
                    snapshot.controller().instance
                )));
            }
            InstanceAdmission::Released(_) => {
                return Err(StoreError::NotFound(format!(
                    "storage of {instance} is retired"
                )));
            }
            InstanceAdmission::Unexplained(error) | InstanceAdmission::Unreadable(error) => {
                return Err(error);
            }
        };
        let ns = NamespaceStorage::namespace_ref(snapshot.controller().id);
        let root_identity = indexed_root(snapshot.transaction(), &ns, epoch)?;
        let index = snapshot.table(BLOB_INDEX)?;
        let (root, root_bytes) = snapshot
            .view()
            .unadmitted_epoch_root(&index, &root_identity)?;
        if root.namespace_id() != ns.id() || root.epoch_number() != epoch {
            return Err(StoreError::Conflict(
                "epoch index coordinates differ from authenticated root".into(),
            ));
        }
        verify_epoch_authority(&root, &store.authority.load())?;
        let (ledger, ledger_row) = snapshot.view().sized_record(&index, root.ledger_root())?;
        if ledger.compression().is_some() {
            return Err(StoreError::Internal("invalid epoch content framing".into()));
        }
        work.charge_mutation()?;
        work.charge_bytes(
            root_bytes.checked_add(ledger_row).ok_or_else(|| {
                StoreError::Internal("epoch root and ledger row exceed u64".into())
            })?,
        )?;
        let seal = [
            Some(root_identity.clone()),
            Some(root.ledger_root().clone()),
            root.rotation_kappa().cloned(),
            root.prev_identifier().cloned(),
        ]
        .into_iter()
        .flatten()
        .collect();
        let hasher = IncrementalHasher::new(root.ledger_root().axis());
        Ok(Some(Self {
            edges: None,
            index,
            snapshot,
            epoch,
            root_identity,
            ledger_size: ledger.total_size(),
            root,
            seal,
            ledger,
            phase: Phase::Seal(0),
            position: 0,
            buffer: Vec::new(),
            consumed: 0,
            remaining: None,
            hasher: Some(hasher),
            tree: Some(StreamingTree::new()),
        }))
    }

    pub(super) const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The root read and admitted at open; verified once [`Advance::Verified`]
    /// is reached.
    pub(super) const fn epoch_root(&self) -> &EpochRoot {
        &self.root
    }

    /// Advance within `work`, emitting what the epoch admits to `sink`.
    /// An error leaves the cursor unusable: its owner discards it, and the
    /// epoch is read again from the start.
    pub(super) fn advance(
        &mut self,
        limits: SettlementLimits,
        authority: &EpochAuthority,
        work: &mut Work,
        sink: &mut dyn FnMut(Staged) -> Result<(), StoreError>,
    ) -> Result<Advance, StoreError> {
        loop {
            match self.phase {
                Phase::Seal(next) => {
                    let Some(identity) = self.seal.get(next).cloned() else {
                        self.phase = Phase::Ledger;
                        continue;
                    };
                    if !work.admits(limits.record_bytes()) {
                        return Ok(Advance::Pending);
                    }
                    work.charge_mutation()?;
                    admit(&self.reads(limits), &identity, work, sink)?;
                    self.phase = Phase::Seal(next + 1);
                }
                Phase::Ledger => {
                    if !self.advance_ledger(limits, authority, work, sink)? {
                        return Ok(Advance::Pending);
                    }
                }
                Phase::Edges => {
                    if self.edges.is_none() {
                        self.open_edges()?;
                    }
                    if !work.admits(limits.record_bytes()) {
                        return Ok(Advance::Pending);
                    }
                    let next = self.edges.as_mut().and_then(Iterator::next);
                    let Some(entry) = next else {
                        self.phase = Phase::Verified;
                        continue;
                    };
                    let target = Kappa::from_key_bytes(entry.map_err(crate::error::redb)?.value())?;
                    work.charge_mutation()?;
                    admit(&self.reads(limits), &target, work, sink)?;
                }
                Phase::Verified => return Ok(Advance::Verified),
            }
        }
    }

    /// The namespace whose activity this cursor holds.
    fn namespace(&self) -> NamespaceRef {
        NamespaceStorage::namespace_ref(self.snapshot.controller().id)
    }

    fn reads(&self, limits: SettlementLimits) -> Reads<'_> {
        Reads {
            view: self.snapshot.view(),
            txn: self.snapshot.transaction(),
            index: &self.index,
            ns: self.namespace(),
            limit: limits.record_bytes(),
        }
    }

    /// One unit of ledger progress: the array head, one element, or one
    /// read. Returns false when the budget stops it; moves to the edges
    /// once the last element is decoded and the digests correspond.
    fn advance_ledger(
        &mut self,
        limits: SettlementLimits,
        authority: &EpochAuthority,
        work: &mut Work,
        sink: &mut dyn FnMut(Staged) -> Result<(), StoreError>,
    ) -> Result<bool, StoreError> {
        let available = &self.buffer[self.consumed..];
        match self.remaining {
            None => match head(available)? {
                Some((4, count, length)) => {
                    self.consumed += length;
                    self.remaining = Some(count);
                    Ok(true)
                }
                Some(_) => Err(StoreError::Rejected("epoch ledger is not an array".into())),
                None => self.read_more(work),
            },
            Some(0) => {
                self.finish_ledger(authority)?;
                Ok(true)
            }
            Some(remaining) => match item_len(available)? {
                Some(length) if length as u64 > limits.record_bytes() => {
                    Err(StoreError::CapacityExceeded(format!(
                        "an element of the ledger of epoch {} is {length} bytes, beyond the settlement record limit {}",
                        self.epoch,
                        limits.record_bytes()
                    )))
                }
                Some(length) => {
                    // The quantum reserves, before anything is allocated,
                    // one record each for the decoded mutation and its
                    // re-encoded leaf (both bounded by the element, itself
                    // within the record limit and the splitter's nesting
                    // limit) and every read of its staging; the charges
                    // below reconcile actual use against it.
                    if !work.admits(limits.mutation_quantum()) {
                        return Ok(false);
                    }
                    let mutation: EpochMutation = from_canonical(&available[..length])?;
                    let leaf = canonical_bytes(&mutation);
                    // The decoding and the re-encoded leaf, under the
                    // quantum just admitted.
                    work.charge_bytes((length as u64).checked_add(leaf.len() as u64).ok_or_else(
                        || StoreError::Internal("ledger element decoding exceeds u64".into()),
                    )?)?;
                    let tree = self
                        .tree
                        .take()
                        .ok_or_else(|| StoreError::Internal("mutation tree consumed".into()))?;
                    self.tree = Some(
                        match tree.push(&leaf, |_, _| Ok::<(), std::convert::Infallible>(())) {
                            Ok(tree) => tree,
                            Err(never) => match never {},
                        },
                    );
                    self.consumed += length;
                    self.remaining = Some(remaining - 1);
                    work.charge_mutation()?;
                    stage_mutation(&self.reads(limits), &mutation, work, sink)?;
                    Ok(true)
                }
                None if available.len() as u64 >= limits.record_bytes() => {
                    Err(StoreError::CapacityExceeded(format!(
                        "an element of the ledger of epoch {} exceeds the settlement record limit {}",
                        self.epoch,
                        limits.record_bytes()
                    )))
                }
                None => self.read_more(work),
            },
        }
    }

    /// Read the next unit of the ledger into the decode buffer, hashing it,
    /// within the bytes `work` has left. Returns false when none are left.
    fn read_more(&mut self, work: &mut Work) -> Result<bool, StoreError> {
        let left = self.ledger_size - self.position;
        if left == 0 {
            return Err(StoreError::Rejected(format!(
                "the ledger of epoch {} ends inside its elements",
                self.epoch
            )));
        }
        let length = READ_UNIT.min(left).min(work.bytes);
        if length == 0 {
            return Ok(false);
        }
        let bytes = self.read_ledger(self.position, length)?;
        if bytes.len() as u64 != length {
            return Err(StoreError::Internal(format!(
                "ledger read delivered {} of {length} bytes",
                bytes.len()
            )));
        }
        work.charge_bytes(length)?;
        self.hasher
            .as_mut()
            .ok_or_else(|| StoreError::Internal("ledger hasher consumed".into()))?
            .update(&bytes);
        self.buffer.drain(..self.consumed);
        self.consumed = 0;
        self.buffer.extend_from_slice(&bytes);
        self.position += length;
        Ok(true)
    }

    /// Bytes `[offset, offset + length)` of the ledger, from the captured
    /// row: inline bytes, external chunks (unverified here; every byte is
    /// hashed and checked against the root), or a composite's verified
    /// component ranges. An alias is followed one hop.
    fn read_ledger(&self, offset: u64, length: u64) -> Result<Vec<u8>, StoreError> {
        let view = self.snapshot.view();
        let (identity, record) =
            view.resolve_alias(&self.index, self.root.ledger_root(), self.ledger.clone())?;
        match record.representation() {
            Representation::Inline { bytes } => {
                let start = usize::try_from(offset).map_err(|_| {
                    StoreError::Internal("ledger offset exceeds address space".into())
                })?;
                let end = usize::try_from(offset + length)
                    .map_err(|_| StoreError::Internal("ledger end exceeds address space".into()))?;
                bytes
                    .get(start..end)
                    .map(<[u8]>::to_vec)
                    .ok_or_else(|| StoreError::Internal("ledger read past its inline row".into()))
            }
            Representation::External { .. } => view
                .open_external(&identity, &record, false)?
                .range(offset, length),
            Representation::Composite { .. } => view.range(&identity, offset, length),
            Representation::Alias { .. } | Representation::Manifest { .. } => Err(
                StoreError::Internal(format!("ledger {identity} is not addressable content")),
            ),
        }
    }

    /// The last element is decoded: nothing may follow it, and the identity
    /// and mutation root computed over the persisted ledger must be the
    /// root's. The root's authority was admitted at open.
    fn finish_ledger(&mut self, authority: &EpochAuthority) -> Result<(), StoreError> {
        if self.consumed != self.buffer.len() || self.position != self.ledger_size {
            return Err(StoreError::Rejected(format!(
                "the ledger of epoch {} holds bytes after its last element",
                self.epoch
            )));
        }
        let ledger = self
            .hasher
            .take()
            .ok_or_else(|| StoreError::Internal("ledger hasher consumed".into()))?
            .finalize()?;
        let tree = self
            .tree
            .take()
            .ok_or_else(|| StoreError::Internal("mutation tree consumed".into()))?;
        check_ledger_digests(&self.root, &ledger, &tree.root())?;
        // The authority admitted at open is admitted again against the
        // history in force now: a rotation committed meanwhile cannot
        // leave an epoch verified against a superseded history.
        verify_epoch_authority(&self.root, authority)?;
        self.buffer = Vec::new();
        self.phase = Phase::Edges;
        Ok(())
    }

    /// Open the `EDGE_FWD` values sourced at the root, once, in the
    /// retained transaction.
    fn open_edges(&mut self) -> Result<(), StoreError> {
        let table = self.snapshot.multimap(EDGE_FWD)?;
        let mut source = self.namespace().id().to_vec();
        source.extend_from_slice(&self.root_identity.key_bytes());
        self.edges = Some(table.get(source.as_slice()).map_err(crate::error::redb)?);
        Ok(())
    }
}

/// The root identity `EPOCH_INDEX` records for epoch `epoch` of `ns`.
fn indexed_root(txn: &ReadTransaction, ns: &NamespaceRef, epoch: u64) -> Result<Kappa, StoreError> {
    let epochs = txn.open_table(EPOCH_INDEX).map_err(crate::error::redb)?;
    let key = epochs
        .get(epoch_idx_key(ns, epoch).as_slice())
        .map_err(crate::error::redb)?
        .ok_or_else(|| {
            StoreError::NotFound(format!(
                "epoch {epoch} of namespace {} is not indexed",
                hex::encode(ns.id())
            ))
        })?
        .value()
        .to_vec();
    Ok(Kappa::from_key_bytes(&key)?)
}
