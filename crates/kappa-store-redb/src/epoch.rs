//! Epoch operations for PersistentStore.
//!
//! Epoch roots are Merkle trees of 7 dCBOR-encoded leaves stored as
//! content-addressed blobs on the filesystem. The current epoch pointer
//! for each namespace is persisted in the redb EPOCH_CURRENT table.
//!
//! An in-memory cache (RwLock<HashMap>) avoids repeated deserialization
//! of epoch root blobs. The cache is populated on demand and on advance.

use redb::{ReadableDatabase, ReadableTable};

use kappa_core::epoch::{self, EpochRoot, EpochRootFields};
use kappa_core::types::*;

use crate::tables::*;
use crate::PersistentStore;

impl PersistentStore {
    pub(crate) fn epoch_advance_impl(
        &self,
        ns: &str,
        mutations: Vec<EpochMutation>,
    ) -> Result<String, StoreError> {
        // Read tag state for the state root before the write transaction.
        // tag_list_impl opens a read transaction internally; cannot nest
        // a read transaction inside a write transaction in redb.
        let sorted_tags = self.tag_list_impl(ns)?;
        let state_root = epoch::state_merkle_root(&sorted_tags);
        let mutations_root = epoch::mutations_merkle_root(&mutations);
        let timestamp_ms = self.clock.now_ms();

        // Single write transaction: increment sequence + update epoch_current
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        let kappa;
        {
            let mut ns_table = txn.open_table(NAMESPACES).map_err(Self::redb_err)?;
            ns_table.insert(ns, ()).map_err(Self::redb_err)?;
            drop(ns_table);

            // Sequence increment for epoch number
            let seq_key = format!("{}\x00_epoch", ns);
            let mut seq_table = txn.open_table(SEQUENCES).map_err(Self::redb_err)?;
            let epoch_number = {
                let current = seq_table
                    .get(seq_key.as_str())
                    .map_err(Self::redb_err)?
                    .map(|v| v.value())
                    .unwrap_or(0);
                let next = current + 1;
                seq_table
                    .insert(seq_key.as_str(), next)
                    .map_err(Self::redb_err)?;
                next
            };
            drop(seq_table);

            // Read current epoch pointer
            let epoch_table = txn.open_table(EPOCH_CURRENT).map_err(Self::redb_err)?;
            let prev_root_kappa = epoch_table
                .get(ns)
                .map_err(Self::redb_err)?
                .map(|v| v.value().to_string());
            drop(epoch_table);

            let epoch_root = EpochRoot::build(EpochRootFields {
                namespace: ns.to_string(),
                epoch_number,
                prev_root_kappa,
                state_root,
                mutations_root,
                timestamp_ms,
                signer_anchor: String::new(),
            });

            kappa = epoch_root.kappa();

            // Persist epoch blob on filesystem (must happen before commit
            // so the blob exists when recovery reads the pointer)
            let path = self.blob_path_for(&kappa)?;
            if !path.exists() {
                if let Some(parent) = path.parent() {
                    std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
                }
                let tmp = path.with_extension("tmp");
                let leaf_bytes = epoch_root.to_leaf_bytes();
                {
                    use std::io::Write;
                    let file = std::fs::File::create(&tmp).map_err(StoreError::Io)?;
                    let mut writer = std::io::BufWriter::new(file);
                    writer.write_all(&leaf_bytes).map_err(StoreError::Io)?;
                    let file = writer
                        .into_inner()
                        .map_err(|e| StoreError::Io(e.into_error()))?;
                    if self.fsync {
                        file.sync_all().map_err(StoreError::Io)?;
                    }
                }
                std::fs::rename(&tmp, &path).map_err(StoreError::Io)?;
                if self.fsync {
                    if let Some(parent) = path.parent() {
                        if let Ok(dir) = std::fs::File::open(parent) {
                            let _ = dir.sync_all();
                        }
                    }
                }
            }

            // Update current pointer in redb
            let mut epoch_table = txn.open_table(EPOCH_CURRENT).map_err(Self::redb_err)?;
            epoch_table
                .insert(ns, kappa.as_str())
                .map_err(Self::redb_err)?;

            // Cache in memory
            self.epoch_cache
                .write()
                .unwrap()
                .insert(kappa.clone(), epoch_root);
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(kappa)
    }

    pub(crate) fn epoch_current_impl(&self, ns: &str) -> Result<Option<String>, StoreError> {
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(EPOCH_CURRENT).map_err(Self::redb_err)?;
        Ok(table
            .get(ns)
            .map_err(Self::redb_err)?
            .map(|v| v.value().to_string()))
    }

    pub(crate) fn epoch_get_impl(&self, kappa: &str) -> Result<EpochRoot, StoreError> {
        // Check in-memory cache
        if let Some(root) = self.epoch_cache.read().unwrap().get(kappa) {
            return Ok(root.clone());
        }
        // Fall back to blob
        let blob = self.blob_get_impl(kappa)?;
        let root = EpochRoot::from_leaf_bytes(&blob)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
        self.epoch_cache
            .write()
            .unwrap()
            .insert(kappa.to_string(), root.clone());
        Ok(root)
    }
}
