//! Blob operations for PersistentStore.
//!
//! Blobs live on the filesystem, content-addressed by kappa-label.
//! Path: {blob_root}/{algo}/{shard1}/{shard2}/{hex}
//! Every algorithm (sha256, sha512, blake3, sha1) is structurally equal.
//!
//! Blob metadata lives in the redb BLOB_META table.

use std::path::PathBuf;

use redb::ReadableDatabase;

use kappa_core::types::StoreError;

use crate::tables::{BLOB_META, NAMESPACES};
use crate::PersistentStore;

impl PersistentStore {
    pub(crate) fn blob_path_for(&self, kappa: &str) -> Result<PathBuf, StoreError> {
        kappa_core::kappa::blob_path_for(&self.blob_root, kappa)
    }

    pub(crate) fn blob_put_impl(&self, kappa: &str, content: &[u8]) -> Result<bool, StoreError> {
        tracing::debug!(kappa = kappa, size = content.len(), "blob_put");
        let path = self.blob_path_for(kappa)?;
        if path.exists() {
            return Ok(false);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
        }
        let tmp = path.with_extension("tmp");
        {
            use std::io::Write;
            let file = std::fs::File::create(&tmp).map_err(StoreError::Io)?;
            let mut writer = std::io::BufWriter::new(file);
            writer.write_all(content).map_err(StoreError::Io)?;
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
        Ok(true)
    }

    pub(crate) fn blob_get_impl(&self, kappa: &str) -> Result<Vec<u8>, StoreError> {
        let path = self.blob_path_for(kappa)?;
        std::fs::read(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(kappa.to_string())
            } else {
                StoreError::Io(e)
            }
        })
    }

    pub(crate) fn blob_exists_impl(&self, kappa: &str) -> Result<bool, StoreError> {
        Ok(self.blob_path_for(kappa)?.exists())
    }

    pub(crate) fn blob_delete_impl(&self, kappa: &str) -> Result<(), StoreError> {
        let path = self.blob_path_for(kappa)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StoreError::Io(e)),
        }
    }

    pub(crate) fn blob_size_impl(&self, kappa: &str) -> Result<u64, StoreError> {
        let path = self.blob_path_for(kappa)?;
        std::fs::metadata(&path)
            .map(|m| m.len())
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    StoreError::NotFound(kappa.to_string())
                } else {
                    StoreError::Io(e)
                }
            })
    }

    pub(crate) fn blob_get_range_impl(
        &self,
        kappa: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        use std::io::{Read, Seek, SeekFrom};
        let path = self.blob_path_for(kappa)?;
        let mut file = std::fs::File::open(&path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StoreError::NotFound(kappa.to_string())
            } else {
                StoreError::Io(e)
            }
        })?;
        file.seek(SeekFrom::Start(offset)).map_err(StoreError::Io)?;
        let mut buf = vec![0u8; length as usize];
        let n = file.read(&mut buf).map_err(StoreError::Io)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub(crate) fn blob_list_impl(&self) -> Result<Vec<String>, StoreError> {
        let mut kappas = Vec::new();
        let Ok(algo_entries) = std::fs::read_dir(&self.blob_root) else {
            return Ok(kappas);
        };
        for algo_entry in algo_entries {
            let algo_entry = algo_entry.map_err(StoreError::Io)?;
            if !algo_entry.file_type().map_err(StoreError::Io)?.is_dir() {
                continue;
            }
            let algo = algo_entry.file_name().to_string_lossy().to_string();
            for s1 in std::fs::read_dir(algo_entry.path()).map_err(StoreError::Io)? {
                let s1 = s1.map_err(StoreError::Io)?;
                if !s1.file_type().map_err(StoreError::Io)?.is_dir() {
                    continue;
                }
                for s2 in std::fs::read_dir(s1.path()).map_err(StoreError::Io)? {
                    let s2 = s2.map_err(StoreError::Io)?;
                    if !s2.file_type().map_err(StoreError::Io)?.is_dir() {
                        continue;
                    }
                    for blob in std::fs::read_dir(s2.path()).map_err(StoreError::Io)? {
                        let blob = blob.map_err(StoreError::Io)?;
                        let name = blob.file_name().to_string_lossy().to_string();
                        if name.ends_with(".tmp") {
                            continue;
                        }
                        kappas.push(format!("{}:{}", algo, name));
                    }
                }
            }
        }
        kappas.sort();
        Ok(kappas)
    }

    // -- Blob metadata (redb BLOB_META table) ---------------------------------

    pub(crate) fn blob_put_meta_impl(
        &self,
        kappa: &str,
        key: &str,
        value: &[u8],
    ) -> Result<(), StoreError> {
        let db_key = format!("{}\x00{}", kappa, key);
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let mut table = txn.open_table(BLOB_META).map_err(Self::redb_err)?;
            table
                .insert(db_key.as_str(), value)
                .map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }

    pub(crate) fn blob_get_meta_impl(
        &self,
        kappa: &str,
        key: &str,
    ) -> Result<Vec<u8>, StoreError> {
        let db_key = format!("{}\x00{}", kappa, key);
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(BLOB_META).map_err(Self::redb_err)?;
        table
            .get(db_key.as_str())
            .map_err(Self::redb_err)?
            .map(|v| v.value().to_vec())
            .ok_or_else(|| StoreError::NotFound(format!("meta {}:{}", kappa, key)))
    }

    pub(crate) fn blob_delete_meta_impl(
        &self,
        kappa: &str,
        key: &str,
    ) -> Result<(), StoreError> {
        let db_key = format!("{}\x00{}", kappa, key);
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let mut table = txn.open_table(BLOB_META).map_err(Self::redb_err)?;
            table.remove(db_key.as_str()).map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }

    // -- Namespace-scoped metadata (redb NS_META multimap) --------------------

    pub(crate) fn meta_set_impl(
        &self,
        ns: &str,
        kappa: &str,
        key: &str,
        value: &str,
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let mut ns_table = txn.open_table(NAMESPACES).map_err(Self::redb_err)?;
            ns_table.insert(ns, ()).map_err(Self::redb_err)?;
            let db_key = format!("{}\x00{}\x00{}", ns, key, value);
            let mut table = txn
                .open_multimap_table(crate::tables::NS_META)
                .map_err(Self::redb_err)?;
            table
                .insert(db_key.as_str(), kappa)
                .map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }

    pub(crate) fn meta_query_impl(
        &self,
        ns: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<String>, StoreError> {
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn
            .open_multimap_table(crate::tables::NS_META)
            .map_err(Self::redb_err)?;
        let mut results = Vec::new();

        if value.is_empty() {
            let prefix = format!("{}\x00{}\x00", ns, key);
            match Self::prefix_successor(prefix.as_bytes()) {
                Some(end_bytes) => {
                    let end_str = String::from_utf8(end_bytes)
                        .map_err(|_| StoreError::Io(std::io::Error::other("utf8")))?;
                    for entry in table
                        .range::<&str>(prefix.as_str()..end_str.as_str())
                        .map_err(Self::redb_err)?
                    {
                        let (_, values) = entry.map_err(Self::redb_err)?;
                        for v in values {
                            results.push(v.map_err(Self::redb_err)?.value().to_string());
                        }
                    }
                }
                None => {
                    for entry in table
                        .range::<&str>(prefix.as_str()..)
                        .map_err(Self::redb_err)?
                    {
                        let (k, values) = entry.map_err(Self::redb_err)?;
                        if !k.value().starts_with(&prefix) {
                            break;
                        }
                        for v in values {
                            results.push(v.map_err(Self::redb_err)?.value().to_string());
                        }
                    }
                }
            }
        } else {
            let db_key = format!("{}\x00{}\x00{}", ns, key, value);
            for v in table.get(db_key.as_str()).map_err(Self::redb_err)? {
                results.push(v.map_err(Self::redb_err)?.value().to_string());
            }
        }

        results.sort();
        results.dedup();
        Ok(results)
    }
}
