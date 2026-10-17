//! Reconstruction of `REFERRERS` from authoritative committed state.
//!
//! Every entry the incremental writers establish is re-derived from the
//! state it projects, by the same rule each writer applies:
//!
//! - a direct tag (no symbolic reference) refers to its content, as
//!   `tag_write` establishes;
//! - an edge record owns its own content, and a retaining edge refers to
//!   its target, as `edge_write` establishes;
//! - the namespace's current epoch root is its head, as the seal
//!   establishes;
//! - a representation (alias, manifest node, composite) refers to every
//!   identity it is assembled from, as `content_install` establishes;
//! - a namespace pin refers to the content its `_pin/{kappa}` key names,
//!   as `namespace_write` establishes; the key is stored in the clear
//!   (`[ns_uuid:16][key bytes]`), so the committed table names the content
//!   directly, as the collector's root set reads it.
//!
//! The rebuild runs in one write transaction over committed tables only:
//! the index is emptied and refilled, readers observe either the previous
//! index or the rebuilt one, and no publication can commit in between. Its
//! cost is one pass over each source table; no history is replayed.

use redb::{ReadableMultimapTable, ReadableTable, ReadableTableMetadata};

use kappa_store::canonical::from_canonical;
use kappa_store::{EdgeInput, Kappa, NamespaceRef, StoreError, TagEntry};

use super::{Referrer, rebuild};
use crate::PersistentStore;
use crate::storage::{Maintenance, Refusal};
use crate::tables::{BLOB_INDEX, EDGES, EPOCH_CURRENT, NAMESPACE_CONFIG, REFERRERS, TAGS};

/// The namespace a `[ns_uuid:16]...` key belongs to. The display name is
/// the UUID: a referrer carries only the namespace identity.
fn namespace_of(key: &[u8]) -> Result<NamespaceRef, StoreError> {
    let id: [u8; 16] = key
        .get(..16)
        .and_then(|prefix| prefix.try_into().ok())
        .ok_or_else(|| {
            StoreError::Internal("namespace-scoped key shorter than its namespace".into())
        })?;
    Ok(NamespaceRef::resolved(id, hex::encode(id), None))
}

/// Remove every entry of the index.
fn clear(txn: &redb::WriteTransaction) -> Result<(), StoreError> {
    let mut table = txn
        .open_multimap_table(REFERRERS)
        .map_err(crate::error::redb)?;
    let keys = table
        .iter()
        .map_err(crate::error::redb)?
        .map(|entry| {
            entry
                .map(|(key, _)| key.value().to_vec())
                .map_err(crate::error::redb)
        })
        .collect::<Result<Vec<Vec<u8>>, StoreError>>()?;
    for key in keys {
        drop(
            table
                .remove_all(key.as_slice())
                .map_err(crate::error::redb)?,
        );
    }
    Ok(())
}

impl PersistentStore {
    /// Rebuild `ALLOCATIONS` and `REFERRERS` of every namespace on disk,
    /// one write transaction per namespace, when a mutation recorded
    /// divergence (`PersistentStore::index_diverged`). Returns the entries
    /// the rebuilt indexes hold, or `None` when nothing was recorded. The
    /// record is taken atomically before the rebuild: each namespace's
    /// rebuild waits for that namespace's writer, so a divergence recorded
    /// by a mutation that held it is repaired by this rebuild, and one
    /// recorded after it is recorded again for the next. A failed rebuild
    /// restores the record. The divergence names no namespace, so every
    /// namespace is rebuilt; the cost is one pass per namespace and is
    /// paid only after a divergence. A namespace being retired, or whose
    /// release is recorded, is skipped: its storage is going, with every
    /// derived index in it.
    pub(crate) fn repair_derived_indexes(&self) -> Result<Option<u64>, StoreError> {
        use std::sync::atomic::Ordering;
        if !self.indexes_diverged.swap(false, Ordering::AcqRel) {
            return Ok(None);
        }
        let rebuilt = (|| {
            let mut total = 0u64;
            for id in self.namespaces.on_disk()? {
                let maintenance = match self.namespaces.maintain(&id)? {
                    Ok(maintenance) => maintenance,
                    Err(Refusal::Retiring | Refusal::Released) => continue,
                    Err(refusal @ Refusal::Unresolved) => return Err(refusal.into_error(&id)),
                };
                let entries = self.rebuild_indexes_of(&maintenance)?;
                maintenance.finish();
                total = total.checked_add(entries).ok_or_else(|| {
                    StoreError::CapacityExceeded("index entry count overflow".into())
                })?;
            }
            Ok(total)
        })();
        match rebuilt {
            Ok(entries) => {
                tracing::warn!(entries, "derived indexes rebuilt after divergence");
                Ok(Some(entries))
            }
            Err(error) => {
                self.indexes_diverged.store(true, Ordering::Release);
                Err(error)
            }
        }
    }

    /// Rebuild both derived indexes of one namespace in one transaction of
    /// its database, under the maintenance that holds its writer gate so
    /// no execution interleaves.
    fn rebuild_indexes_of(&self, maintenance: &Maintenance) -> Result<u64, StoreError> {
        let txn = maintenance
            .controller()
            .db
            .begin_write()
            .map_err(crate::error::redb)?;
        let allocations = crate::content_reclaim::rebuild_allocations(self, &txn)?;
        let referrers = self.rebuild_referrers_in_txn(&txn)?;
        txn.commit().map_err(crate::error::redb)?;
        allocations
            .checked_add(referrers)
            .ok_or_else(|| StoreError::CapacityExceeded("index entry count overflow".into()))
    }

    /// Replace `ns`'s `REFERRERS` with the entries derived from its
    /// authoritative committed state. Returns the number of entries the
    /// rebuilt index holds. Changes no epoch-committed state and
    /// publishes nothing. Refused while the namespace is retiring or
    /// retired.
    pub fn rebuild_referrers(&self, ns: &NamespaceRef) -> Result<u64, StoreError> {
        let maintenance = self
            .namespaces
            .maintain(ns.id())?
            .map_err(|refusal| refusal.into_error(ns.id()))?;
        let txn = maintenance
            .controller()
            .db
            .begin_write()
            .map_err(crate::error::redb)?;
        let entries = self.rebuild_referrers_in_txn(&txn)?;
        txn.commit().map_err(crate::error::redb)?;
        maintenance.finish();
        Ok(entries)
    }

    /// Empty `REFERRERS` inside `txn` and re-derive every entry. Returns
    /// the number of entries it then holds.
    fn rebuild_referrers_in_txn(&self, txn: &redb::WriteTransaction) -> Result<u64, StoreError> {
        clear(txn)?;
        self.rebuild_tags(txn)?;
        self.rebuild_edges(txn)?;
        self.rebuild_heads(txn)?;
        self.rebuild_representations(txn)?;
        rebuild_pins(txn)?;
        txn.open_multimap_table(REFERRERS)
            .map_err(crate::error::redb)?
            .len()
            .map_err(crate::error::redb)
    }

    fn rebuild_tags(&self, txn: &redb::WriteTransaction) -> Result<(), StoreError> {
        let tags = txn.open_table(TAGS).map_err(crate::error::redb)?;
        for entry in tags.iter().map_err(crate::error::redb)? {
            let (key, value) = entry.map_err(crate::error::redb)?;
            let key = key.value();
            let ns = namespace_of(key)?;
            let name = std::str::from_utf8(&key[16..])
                .map_err(|error| StoreError::Internal(format!("tag name: {error}")))?;
            let tag: TagEntry =
                from_canonical(&self.decrypt_bytes(&crate::tag::tag_context(key), value.value())?)?;
            if tag.symref.is_none() {
                rebuild(txn, &tag.kappa, &Referrer::tag(&ns, name)?)?;
            }
        }
        Ok(())
    }

    fn rebuild_edges(&self, txn: &redb::WriteTransaction) -> Result<(), StoreError> {
        let edges = txn.open_table(EDGES).map_err(crate::error::redb)?;
        for entry in edges.iter().map_err(crate::error::redb)? {
            let (key, value) = entry.map_err(crate::error::redb)?;
            let key = key.value();
            let ns = namespace_of(key)?;
            let identity = Kappa::from_key_bytes(&key[16..])?;
            let input: EdgeInput = from_canonical(
                &self.decrypt_bytes(&crate::encrypted::bound("edge", key), value.value())?,
            )?;
            rebuild(txn, &identity, &Referrer::edge_record(&ns, &identity))?;
            if input.relation.gc_reachable() {
                rebuild(txn, &input.target, &Referrer::edge_target(&ns, &identity))?;
            }
        }
        Ok(())
    }

    /// Re-derive every namespace's epoch head from `EPOCH_CURRENT`.
    fn rebuild_heads(&self, txn: &redb::WriteTransaction) -> Result<(), StoreError> {
        let pointers = txn.open_table(EPOCH_CURRENT).map_err(crate::error::redb)?;
        for entry in pointers.iter().map_err(crate::error::redb)? {
            let (key, value) = entry.map_err(crate::error::redb)?;
            if key.value().len() != 16 {
                return Err(StoreError::Internal(
                    "invalid persisted epoch namespace key".into(),
                ));
            }
            let ns = namespace_of(key.value())?;
            let root = Kappa::from_key_bytes(
                &self.decrypt_bytes(&crate::epoch::pointer_context(ns.id()), value.value())?,
            )?;
            rebuild(txn, &root, &Referrer::epoch_head(&ns))?;
        }
        Ok(())
    }

    fn rebuild_representations(&self, txn: &redb::WriteTransaction) -> Result<(), StoreError> {
        let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        for entry in index.iter().map_err(crate::error::redb)? {
            let (key, value) = entry.map_err(crate::error::redb)?;
            let record = crate::blob_rows::decode_row(self, key.value(), value.value())?;
            let owner = Kappa::from_key_bytes(key.value())?;
            for child in crate::content_install::referenced(&record) {
                rebuild(txn, &child, &Referrer::representation(&owner))?;
            }
        }
        Ok(())
    }
}

/// Re-derive every pin from `NAMESPACE_CONFIG`, whose keys are
/// `[ns_uuid:16][key bytes]` in the clear. Only the key is needed; the
/// encrypted value (the pin's expiry) does not decide retention, as the
/// writer establishes the referrer for every `_pin/` key it inserts.
fn rebuild_pins(txn: &redb::WriteTransaction) -> Result<(), StoreError> {
    let config = txn
        .open_table(NAMESPACE_CONFIG)
        .map_err(crate::error::redb)?;
    for entry in config.iter().map_err(crate::error::redb)? {
        let (key, _) = entry.map_err(crate::error::redb)?;
        let key = key.value();
        let ns = namespace_of(key)?;
        let name = std::str::from_utf8(&key[16..])
            .map_err(|error| StoreError::Internal(format!("metadata key: {error}")))?;
        if let Some(pinned) = crate::namespace_write::pinned_content(name)? {
            rebuild(txn, &pinned, &Referrer::pin(&ns))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use redb::{ReadableDatabase, ReadableMultimapTable};

    use kappa_store::{BuiltinRelation, ClockMs, EdgeRelation, Kappa, NamespaceRef, TagUpdate};

    use crate::PersistentStore;
    use crate::representation::{BlobRecord, Component};
    use crate::tables::REFERRERS;

    type Snapshot = BTreeSet<(Vec<u8>, Vec<u8>)>;

    fn snapshot(
        store: &PersistentStore,
        ns: &NamespaceRef,
    ) -> Result<Snapshot, Box<dyn std::error::Error>> {
        let (db, _active) = store.namespace_db(ns)?;
        let txn = db.begin_read()?;
        let table = txn.open_multimap_table(REFERRERS)?;
        let mut entries = BTreeSet::new();
        for entry in table.iter()? {
            let (key, values) = entry?;
            for value in values {
                entries.insert((key.value().to_vec(), value?.value().to_vec()));
            }
        }
        Ok(entries)
    }

    /// One epoch holding every referrer kind: a direct tag, a retaining
    /// edge, a pin, the epoch head, and the representations of a composite
    /// over two inline components.
    fn publish_every_kind(
        store: &PersistentStore,
        ns: &NamespaceRef,
        now: ClockMs,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let limits = store.representation_limits;
        let writer = store.test_writer(ns)?;
        let write = &writer.txn;
        let mut components = Vec::new();
        for part in [&b"hello "[..], &b"world"[..]] {
            let identity = Kappa::sha256(part);
            let prepared = crate::PreparedContent::unallocated(
                identity.clone(),
                BlobRecord::inline(part.to_vec(), None, limits)?,
            )?
            .owned_by(&store.protection);
            crate::content_install::install_in_txn(store, write, ns, prepared, now, limits)?;
            components.push(Component {
                identity,
                length: part.len() as u64,
            });
        }
        let composite = crate::PreparedContent::unallocated(
            Kappa::sha256(b"hello world"),
            BlobRecord::composite(components, true, limits)?,
        )?
        .owned_by(&store.protection);
        crate::content_install::install_in_txn(store, write, ns, composite, now, limits)?;
        let tagged = Kappa::sha256(b"tagged");
        store.tag_put_in_txn(
            write,
            ns,
            "latest",
            &TagUpdate::Set {
                kappa: tagged.clone(),
            },
            now,
        )?;
        store.edge_mutation_put_in_txn(
            write,
            ns,
            &kappa_store::EdgeInput {
                source: Kappa::sha256(b"source"),
                target: tagged,
                relation: EdgeRelation::Builtin(BuiltinRelation::Owns),
                asserter: Kappa::sha256(b"asserter"),
                created_at_ms: now.as_i64(),
                metadata: None,
            },
            now,
        )?;
        let pinned = Kappa::sha256(b"pinned");
        store.namespace_put_meta_in_txn(write, ns, &format!("_pin/{pinned}"), b"{}", now)?;
        store.publish_test_writer(writer, ns, now)?;
        store.settle_all()?;
        Ok(())
    }

    #[test]
    fn rebuild_reproduces_the_incremental_index_and_repairs_divergence()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = crate::test_support::persistent_store()?.into_store();
        let ns = NamespaceRef::deterministic("referrer-rebuild");
        publish_every_kind(&store, &ns, ClockMs::from_raw(1000))?;
        // A second epoch moves the head: the rebuild must index the
        // current root, not the first.
        publish_every_kind(&store, &ns, ClockMs::from_raw(2000))?;
        let incremental = snapshot(&store, &ns)?;
        let kinds: BTreeSet<u8> = incremental.iter().map(|(_, value)| value[16]).collect();
        assert_eq!(kinds, BTreeSet::from([0, 1, 2, 3, 4, 5]), "{incremental:?}");

        let count = store.rebuild_referrers(&ns)?;
        assert_eq!(snapshot(&store, &ns)?, incremental);
        assert_eq!(count, incremental.len() as u64);

        // Divergence in both directions: an entry the state implies is
        // missing and an entry nothing implies is present. The rebuild
        // removes the second and restores the first.
        let (missing_key, missing_value) =
            incremental.iter().next().cloned().ok_or("index is empty")?;
        let (db, _active) = store.namespace_db(&ns)?;
        let write = db.begin_write()?;
        {
            let mut table = write.open_multimap_table(REFERRERS)?;
            assert!(table.remove(missing_key.as_slice(), missing_value.as_slice())?);
            let stray = super::Referrer::pin(&NamespaceRef::deterministic("stray")).encode();
            let content = Kappa::sha256(b"unreferenced").key_bytes();
            assert!(!table.insert(content.as_slice(), stray.as_slice())?);
        }
        write.commit()?;
        assert_ne!(snapshot(&store, &ns)?, incremental);
        store.rebuild_referrers(&ns)?;
        assert_eq!(snapshot(&store, &ns)?, incremental);
        Ok(())
    }

    fn diverged(store: &PersistentStore) -> bool {
        store
            .indexes_diverged
            .load(std::sync::atomic::Ordering::Acquire)
    }

    /// A mutation that finds `REFERRERS` diverged refuses to commit and
    /// records it; maintenance rebuilds the index and the retried mutation
    /// commits. A healthy store repairs nothing.
    #[test]
    fn a_referrer_divergence_is_recorded_repaired_and_the_mutation_retried()
    -> Result<(), Box<dyn std::error::Error>> {
        use kappa_store::MaintenanceStore;
        let store = crate::test_support::persistent_store()?.into_store();
        let ns = NamespaceRef::deterministic("referrer-repair");
        let now = ClockMs::from_raw(1000);
        publish_every_kind(&store, &ns, now)?;
        let incremental = snapshot(&store, &ns)?;
        assert_eq!(
            store.repair_indexes()?,
            kappa_store::IndexRepair::default(),
            "no divergence recorded, nothing rebuilt"
        );

        let tagged = Kappa::sha256(b"tagged");
        {
            let (db, _active) = store.namespace_db(&ns)?;
            let write = db.begin_write()?;
            {
                let mut table = write.open_multimap_table(REFERRERS)?;
                let entry = super::Referrer::tag(&ns, "latest")?.encode();
                assert!(table.remove(tagged.key_bytes().as_slice(), entry.as_slice())?);
            }
            write.commit()?;
        }

        let writer = store.test_writer(&ns)?;
        assert!(matches!(
            store.tag_delete_in_txn(&writer.txn, &ns, "latest", now),
            Err(kappa_store::StoreError::Internal(_))
        ));
        drop(writer);
        assert!(diverged(&store));

        let repair = store.repair_indexes()?;
        assert!(repair.diverged);
        assert!(!diverged(&store));
        assert_eq!(snapshot(&store, &ns)?, incremental);

        let writer = store.test_writer(&ns)?;
        store.tag_delete_in_txn(&writer.txn, &ns, "latest", now)?;
        store.publish_test_writer(writer, &ns, now)?;
        Ok(())
    }

    /// A retirement that finds `ALLOCATIONS` diverged refuses to commit and
    /// records it; the repair rebuilds ownership from `BLOB_INDEX` and the
    /// retried retirement releases the allocation.
    #[test]
    fn an_allocation_divergence_is_recorded_repaired_and_the_retirement_retried()
    -> Result<(), Box<dyn std::error::Error>> {
        use kappa_store::MaintenanceStore;
        let store = crate::test_support::persistent_store()?.into_store();
        let ns = NamespaceRef::deterministic("allocation-repair");
        let now = ClockMs::from_raw(1000);
        let size = usize::try_from(store.representation_limits.inline_limit)? + 1;
        let content = vec![0x6b; size];
        let prepared = store.prepare_representation(
            kappa_store::Axis::Sha256,
            None,
            &mut content.as_slice(),
            None,
            u64::try_from(size)?,
            std::time::Instant::now() + std::time::Duration::from_secs(30),
        )?;
        let identity = prepared.identity().clone();
        let limits = store.representation_limits;
        let writer = store.test_writer(&ns)?;
        crate::content_install::install_in_txn(&store, &writer.txn, &ns, prepared, now, limits)?;
        store.publish_test_writer(writer, &ns, now)?;
        store.settle_all()?;
        let allocation = match store.blob_record(&identity)?.representation() {
            crate::representation::Representation::External { allocation, .. } => *allocation,
            _ => return Err("content above the inline limit is not external".into()),
        };

        {
            let (db, _active) = store.namespace_db(&ns)?;
            let write = db.begin_write()?;
            assert!(
                write
                    .open_table(crate::tables::ALLOCATIONS)?
                    .remove(allocation.0.as_slice())?
                    .is_some()
            );
            write.commit()?;
        }

        let writer = store.test_writer(&ns)?;
        assert!(matches!(
            crate::content_reclaim::retire_in_txn(&store, &writer.txn, &ns, now, &identity),
            Err(kappa_store::StoreError::Internal(_))
        ));
        drop(writer);
        assert!(diverged(&store));

        let repair = store.repair_indexes()?;
        assert!(repair.diverged);
        assert!(!diverged(&store));

        let writer = store.test_writer(&ns)?;
        assert_eq!(
            crate::content_reclaim::retire_in_txn(&store, &writer.txn, &ns, now, &identity)?,
            crate::content_reclaim::Retired::Row(Some(allocation))
        );
        Ok(())
    }
}
