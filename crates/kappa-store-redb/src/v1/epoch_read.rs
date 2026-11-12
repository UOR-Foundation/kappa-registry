//! Reads of committed epochs: the authenticated content and roots a
//! namespace database holds, the head of a namespace, recovery of a
//! controller's head state, and the `EpochStore` contract.

use redb::{ReadableDatabase, ReadableTable, ReadableTableMetadata};

use kappa_store::epoch::EpochMutation;
use kappa_store::epoch_root::EpochRoot;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::epoch::EpochStore;
use kappa_store::work::{Dimension, Meter};
use kappa_store::VerifiedContent;

use super::{epoch_idx_key, POINTER_CONTEXT, POINTER_KEY_BYTES};
use crate::content_read::{ReadView, RecordReader, MAX_EPOCH_ROOT_BYTES};
use crate::representation::Representation;
use crate::storage::NamespaceController;
use crate::tables::{BLOB_INDEX, EPOCH_CURRENT, EPOCH_INDEX, MUTATION_BUFFER};
use crate::PersistentStore;

/// Whether a namespace database holds durable history in `txn`: an epoch
/// pointer, a buffered transition or a tag. The tables are probed in that
/// order, each probe charged one entry on `work` just before it runs, and
/// probing stops at the first table holding a row, so the work accounted
/// is the probes made.
fn holds_history(txn: &redb::ReadTransaction, work: &mut dyn Meter) -> Result<bool, StoreError> {
    work.charge(Dimension::Entries, 1)?;
    if !txn
        .open_table(EPOCH_CURRENT)
        .map_err(crate::error::redb)?
        .is_empty()
        .map_err(crate::error::redb)?
    {
        return Ok(true);
    }
    work.charge(Dimension::Entries, 1)?;
    if !txn
        .open_table(MUTATION_BUFFER)
        .map_err(crate::error::redb)?
        .is_empty()
        .map_err(crate::error::redb)?
    {
        return Ok(true);
    }
    work.charge(Dimension::Entries, 1)?;
    Ok(!txn
        .open_table(crate::tables::TAGS)
        .map_err(crate::error::redb)?
        .is_empty()
        .map_err(crate::error::redb)?)
}

impl ReadView {
    /// The root's state reference read from this transaction, with its raw
    /// reservation retained until bounded construction completes.
    pub(crate) fn namespace_state_from_index(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<kappa_store::canonical::Record<kappa_store::NamespaceState>, StoreError> {
        let evidence = RecordReader::locate(
            self,
            index,
            identity,
            kappa_store::NamespaceState::MAX_ENCODED_LEN,
            work,
        )?
        .read_to_end(work)?;
        kappa_store::canonical::bounded_record(
            &evidence.content,
            work,
            &self.record_storage.decoded,
        )
    }

    /// Uncompressed inline or external content `identity`, verified against
    /// its identity, on `work`: its row, its alias target's row, and its
    /// bytes read (`read_stored`), and its hash charged before it is
    /// computed; at most `content_read::verified_content_cost`. Evidence is
    /// never composite: a composite or manifest representation is invalid
    /// framing. The bytes move into the verification.
    pub(crate) fn verified_epoch_content(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        maximum: Option<u64>,
        work: &mut dyn Meter,
    ) -> Result<VerifiedContent, StoreError> {
        let record = self.record_from_table(index, identity, work)?;
        let (held, record) = self.resolve_alias(index, identity, record, work)?;
        if record.compression().is_some()
            || matches!(
                record.representation(),
                Representation::Composite { .. } | Representation::Manifest { .. }
            )
        {
            return Err(StoreError::Internal("invalid epoch content framing".into()));
        }
        let bytes = self.read_stored(index, &held, &record, maximum, work)?;
        work.charge(Dimension::BytesHashed, bytes.len() as u64)?;
        Ok(VerifiedContent::verify_owned(identity, bytes)?)
    }

    /// The bytes of [`Self::verified_epoch_content`].
    pub(crate) fn epoch_content_from_index(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        maximum: Option<u64>,
        work: &mut dyn Meter,
    ) -> Result<Vec<u8>, StoreError> {
        Ok(self
            .verified_epoch_content(index, identity, maximum, work)?
            .into_parts()
            .1)
    }

    /// The epoch root `identity` and its ledger's mutations, admitted
    /// together on `work` by the shared admission of a persisted epoch
    /// (`admit_persisted_epoch`) against this view's authority. The ledger
    /// is read and hashed once (`verified_epoch_content`, which establishes
    /// its identity) and decoded once, by the admission.
    pub(crate) fn admitted_epoch(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<(EpochRoot, Vec<EpochMutation>), StoreError> {
        let (root, _) = self.unadmitted_epoch_root(index, identity, work)?;
        let ledger = self.verified_epoch_content(index, root.ledger_root(), None, work)?;
        let mutations = kappa_store::epoch_publication::admit_persisted_epoch(
            &root,
            &self.authority.load(),
            &ledger,
            work,
        )?;
        Ok((root, mutations))
    }

    /// The epoch root `identity`, admitted with its whole ledger
    /// ([`Self::admitted_epoch`]).
    pub(crate) fn epoch_root_from_index(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<EpochRoot, StoreError> {
        self.admitted_epoch(index, identity, work)
            .map(|(root, _)| root)
    }

    /// The epoch root `identity` decoded from verified bytes, with the
    /// number of bytes read. Neither its authority nor its ledger is
    /// admitted: the caller admits both before trusting it
    /// (`admitted_epoch` does so over the whole ledger; settlement does so
    /// incrementally, `settlement_ledger`).
    pub(crate) fn unadmitted_epoch_root(
        &self,
        index: &impl ReadableTable<&'static [u8], &'static [u8]>,
        identity: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<(EpochRoot, u64), StoreError> {
        let evidence = RecordReader::locate(self, index, identity, MAX_EPOCH_ROOT_BYTES, work)?
            .read_to_end(work)?;
        let verified = &evidence.content;
        let root = EpochRoot::from_verified(verified, 1, work, &self.record_storage.decoded)?;
        Ok((root, verified.len() as u64))
    }
}

impl PersistentStore {
    /// The authenticated root `kappa`, cached or located through the shared
    /// settled/unsettled content discovery path. Cache eviction cannot hide
    /// a committed epoch awaiting settlement. Discovery, storage admission,
    /// and verification all consume this operation's meter.
    pub(crate) fn load_epoch_root(
        &self,
        kappa: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<EpochRoot, StoreError> {
        if let Some(cached) = self.epoch_cache.get(kappa, work)? {
            return Ok(cached);
        }
        let root = self.with_holder(kappa, work, |view, work| {
            let txn = view.db.begin_read().map_err(crate::error::redb)?;
            let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
            view.epoch_root_from_index(&index, kappa, work)
        })?;
        // Optional cache maintenance cannot undo a completed verified read.
        let _ = self.epoch_cache.insert(root.clone(), work);
        Ok(root)
    }

    /// The head root of `namespace` as `txn` holds it, read through `view`
    /// on `work`: the one head read every caller delegates to, over a
    /// transaction it supplies and never reopens. The pointer lookup, the
    /// stored pointer read with its context built, its plaintext allocated
    /// and decrypted, and the authenticated root read and its verification
    /// are each charged before they run. `None` when the transaction holds
    /// no pointer; an error when any step fails or is refused.
    pub(crate) fn head_root_in(
        &self,
        txn: &redb::ReadTransaction,
        view: &ReadView,
        namespace: &[u8; 16],
        work: &mut dyn Meter,
    ) -> Result<Option<EpochRoot>, StoreError> {
        work.charge(Dimension::Entries, 1)?;
        let table = txn.open_table(EPOCH_CURRENT).map_err(crate::error::redb)?;
        let Some(pointer) = table
            .get(namespace.as_slice())
            .map_err(crate::error::redb)?
        else {
            return Ok(None);
        };
        let stored = pointer.value().len() as u64;
        work.charge_all(&[
            (Dimension::BytesRead, stored),
            (
                Dimension::BytesAllocated,
                crate::encrypted::bound_allocation(POINTER_CONTEXT, POINTER_KEY_BYTES),
            ),
            (Dimension::BytesAllocated, stored),
            (Dimension::BytesDecoded, stored),
        ])?;
        let decrypted = self.decrypt_bytes(&super::pointer_context(namespace), pointer.value())?;
        let kappa = Kappa::from_key_bytes(&decrypted)?;
        let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        let root = view.epoch_root_from_index(&index, &kappa, work)?;
        if root.namespace_id() != namespace {
            return Err(StoreError::Conflict(
                "epoch pointer crosses namespace identity".into(),
            ));
        }
        Ok(Some(root))
    }

    /// The head root of `controller`'s namespace from its own database, on
    /// `work` ([`Self::head_root_in`]). The pointer lookup, the head read's
    /// first unit, is admitted before the transaction it runs in is opened.
    pub(crate) fn head_root(
        &self,
        controller: &NamespaceController,
        work: &mut dyn Meter,
    ) -> Result<Option<EpochRoot>, StoreError> {
        work.admits(&[(Dimension::Entries, 1)])?;
        let txn = controller.db.begin_read().map_err(crate::error::redb)?;
        self.head_root_in(&txn, &self.read_view_for(controller), &controller.id, work)
    }

    /// Recover `controller`'s head once on `work`: its epoch number, the
    /// latest epoch time it bounds rotation by, and its committed time
    /// floor, all read in one read transaction: the floor
    /// (`committed_floor_in`), each history probe (`holds_history`) and the
    /// head (`head_root_in`), each charged before it runs. The floor
    /// lookup, the first unit, is admitted before the transaction is
    /// opened. Called under the controller's writer gate, so no other
    /// execution moves the head meanwhile; no replay. The controller's
    /// recovered state changes only once every read succeeded.
    pub(crate) fn recover_namespace_head(
        &self,
        controller: &NamespaceController,
        work: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        use std::sync::atomic::Ordering;
        if controller.head_recovered.load(Ordering::Acquire) {
            return Ok(());
        }
        work.admits(&[(Dimension::Entries, 1)])?;
        let txn = controller.db.begin_read().map_err(crate::error::redb)?;
        let floor = self.committed_floor_in(&txn, work)?;
        let has_history = holds_history(&txn, work)?;
        if has_history && floor.is_none() {
            return Err(StoreError::Internal(format!(
                "namespace {} has durable history without time continuity state",
                hex::encode(controller.id)
            )));
        }
        let head =
            self.head_root_in(&txn, &self.read_view_for(controller), &controller.id, work)?;
        drop(txn);
        if let Some(floor) = floor {
            self.committed_floor_ms
                .fetch_max(floor.encoded().as_i64(), Ordering::SeqCst);
        }
        if let Some(root) = head {
            #[cfg(test)]
            self.hooks.reach(crate::test_hooks::Point::RecoveryHeadRead);
            // Heads carry the latest timestamp of their namespace: epoch
            // timestamps never regress along a chain.
            self.latest_epoch_ms
                .fetch_max(root.timestamp_ms(), Ordering::SeqCst);
            controller
                .epoch_number
                .fetch_max(root.epoch_number(), Ordering::AcqRel);
        }
        controller.head_recovered.store(true, Ordering::Release);
        Ok(())
    }
}

impl EpochStore for PersistentStore {
    fn epoch_state(&self, ns: &NamespaceRef) -> Result<([u8; 32], u64), StoreError> {
        self.persisted_tag_state(ns)
    }

    // Epochs are sealed only by publishing an execution
    // (`EpochExecution::publish` -> `prepare_epoch_transaction` ->
    // `PreparedEpochPublication::publish`), which seals the ledger written by
    // the same writer.
    /// The head of `ns` on one read operation's meter: the namespace's
    /// acquisition (one handle) admitted before its snapshot is taken, and
    /// the head read through that snapshot's own transaction and view.
    fn epoch_current(&self, ns: &NamespaceRef) -> Result<(u64, Kappa), StoreError> {
        let mut work = self.read_meter();
        work.charge(Dimension::Handles, 1)?;
        let snapshot = self.namespace_snapshot(ns)?;
        let root = self
            .head_root_in(snapshot.transaction(), snapshot.view(), ns.id(), &mut work)?
            .ok_or_else(|| StoreError::NotFound(format!("no epoch for namespace {ns}")))?;
        let epoch_num = root.epoch_number();
        Ok((epoch_num, root.kappa().clone()))
    }

    fn epoch_get(&self, kappa: &Kappa) -> Result<EpochRoot, StoreError> {
        self.load_epoch_root(kappa, &mut self.read_meter())
    }

    fn epoch_get_by_number(
        &self,
        ns: &NamespaceRef,
        epoch_number: u64,
    ) -> Result<Kappa, StoreError> {
        let mut work = self.read_meter();
        // The namespace's acquisition (one handle) admitted before its
        // snapshot is taken.
        work.charge(Dimension::Handles, 1)?;
        let snapshot = self.namespace_snapshot(ns)?;
        // The index lookup, charged before it runs; its key is inline and
        // allocates nothing.
        work.charge(Dimension::Entries, 1)?;
        let idx_key = epoch_idx_key(ns, epoch_number);
        let table = snapshot.table(EPOCH_INDEX)?;
        let raw = table
            .get(idx_key.as_slice())
            .map_err(crate::error::redb)?
            .ok_or_else(|| {
                StoreError::NotFound(format!("epoch {epoch_number} not found in namespace {ns}"))
            })?;
        work.charge(Dimension::BytesRead, raw.value().len() as u64)?;
        let identity = Kappa::from_key_bytes(raw.value())?;
        let root = snapshot.view().epoch_root_from_index(
            &snapshot.table(BLOB_INDEX)?,
            &identity,
            &mut work,
        )?;
        if root.namespace_id() != ns.id() || root.epoch_number() != epoch_number {
            return Err(StoreError::Conflict(
                "epoch index coordinates differ from authenticated root".into(),
            ));
        }
        Ok(identity)
    }
}
