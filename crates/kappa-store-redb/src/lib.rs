//! redb B+tree query accelerator for kappa-registry.
//!
//! Wraps InMemoryStore and maintains redb B+tree indexes for operations
//! that benefit from sorted iteration. Mutations write through to both
//! the InMemoryStore (source of truth for blobs, epochs, sequences,
//! edges, namespaces) and the redb index (sorted tag access).
//!
//! tag_list and tag_prefix use redb range scans: O(log n + k) where k
//! is the result count. InMemoryStore's tag_list scans all tags across
//! all namespaces (O(N)) -- at 10K namespaces x 10K tags = 100M entries,
//! that scan returns 10K results after touching 100M. redb returns
//! the same 10K in microseconds via B+tree range iteration.

use std::path::PathBuf;
use std::sync::Arc;

use redb::{Database, ReadableDatabase, TableDefinition};

use kappa_core::epoch::EpochRoot;
use kappa_core::store::memory::InMemoryStore;
use kappa_core::store::KappaStore;
use kappa_core::types::*;

/// Tag index table. Key: "ns\x00name" (compound, lexicographic sort).
/// Value: "kappa\x00version" (version as decimal string).
/// The name is recoverable from the key (everything after \x00).
const TAG_TABLE: TableDefinition<&str, &str> = TableDefinition::new("tags");

fn redb_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Io(std::io::Error::other(e.to_string()))
}

pub struct RedbAcceleratedStore {
    inner: Arc<InMemoryStore>,
    db: Database,
}

impl RedbAcceleratedStore {
    pub fn new(inner: Arc<InMemoryStore>, db_path: PathBuf) -> Result<Self, StoreError> {
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Database::create(&db_path).map_err(redb_err)?;

        let write_txn = db.begin_write().map_err(redb_err)?;
        {
            let _ = write_txn.open_table(TAG_TABLE).map_err(redb_err)?;
        }
        write_txn.commit().map_err(redb_err)?;

        Ok(Self { inner, db })
    }

    fn tag_key(ns: &str, name: &str) -> String {
        format!("{}\x00{}", ns, name)
    }

    fn tag_value(kappa: &str, version: u64) -> String {
        format!("{}\x00{}", kappa, version)
    }

    fn parse_tag_value(key: &str, value: &str) -> TagEntry {
        let name = key
            .split_once('\x00')
            .map(|(_, n)| n.to_string())
            .unwrap_or_default();
        let (kappa, version_str) = value.split_once('\x00').unwrap_or((value, "0"));
        let version = version_str.parse::<u64>().unwrap_or(0);
        TagEntry {
            name,
            kappa: kappa.to_string(),
            version,
        }
    }

    fn ns_range_start(ns: &str) -> String {
        format!("{}\x00", ns)
    }

    fn ns_range_end(ns: &str) -> String {
        format!("{}\x01", ns)
    }

    fn prefix_range_start(ns: &str, prefix: &str) -> String {
        format!("{}\x00{}", ns, prefix)
    }

    fn prefix_range_end(ns: &str, prefix: &str) -> String {
        let mut end = prefix.as_bytes().to_vec();
        if let Some(last) = end.last_mut() {
            *last = last.wrapping_add(1);
        }
        let end_str = String::from_utf8_lossy(&end);
        format!("{}\x00{}", ns, end_str)
    }

    fn sync_tag(&self, ns: &str, name: &str, kappa: &str, version: u64) -> Result<(), StoreError> {
        let key = Self::tag_key(ns, name);
        let val = Self::tag_value(kappa, version);
        let write_txn = self.db.begin_write().map_err(redb_err)?;
        {
            let mut table = write_txn.open_table(TAG_TABLE).map_err(redb_err)?;
            table.insert(key.as_str(), val.as_str()).map_err(redb_err)?;
        }
        write_txn.commit().map_err(redb_err)?;

        // Verify the write landed via read-back
        let read_txn = self.db.begin_read().map_err(redb_err)?;
        let table = read_txn.open_table(TAG_TABLE).map_err(redb_err)?;
        let stored = table.get(key.as_str()).map_err(redb_err)?;
        match stored {
            Some(guard) if guard.value() == val.as_str() => Ok(()),
            Some(guard) => Err(StoreError::Conflict(format!(
                "redb write verification failed: expected {}, got {}",
                val,
                guard.value()
            ))),
            None => Err(StoreError::Conflict(format!(
                "redb write verification failed: key {} not found after commit",
                key
            ))),
        }
    }

    fn remove_tag(&self, ns: &str, name: &str) -> Result<(), StoreError> {
        let key = Self::tag_key(ns, name);
        let write_txn = self.db.begin_write().map_err(redb_err)?;
        {
            let mut table = write_txn.open_table(TAG_TABLE).map_err(redb_err)?;
            let _ = table.remove(key.as_str()).map_err(redb_err)?;
        }
        write_txn.commit().map_err(redb_err)?;
        Ok(())
    }
}

impl KappaStore for RedbAcceleratedStore {
    fn blob_put(&self, kappa: &str, content: &[u8]) -> Result<bool, StoreError> {
        self.inner.blob_put(kappa, content)
    }

    fn blob_get(&self, kappa: &str) -> Result<Vec<u8>, StoreError> {
        self.inner.blob_get(kappa)
    }

    fn blob_exists(&self, kappa: &str) -> Result<bool, StoreError> {
        self.inner.blob_exists(kappa)
    }

    fn blob_delete(&self, kappa: &str) -> Result<(), StoreError> {
        self.inner.blob_delete(kappa)
    }

    fn blob_size(&self, kappa: &str) -> Result<u64, StoreError> {
        self.inner.blob_size(kappa)
    }

    fn blob_get_range(&self, kappa: &str, offset: u64, length: u64) -> Result<Vec<u8>, StoreError> {
        self.inner.blob_get_range(kappa, offset, length)
    }

    fn blob_list(&self) -> Result<Vec<String>, StoreError> {
        self.inner.blob_list()
    }

    fn blob_put_meta(&self, kappa: &str, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.inner.blob_put_meta(kappa, key, value)
    }

    fn blob_get_meta(&self, kappa: &str, key: &str) -> Result<Vec<u8>, StoreError> {
        self.inner.blob_get_meta(kappa, key)
    }

    fn blob_delete_meta(&self, kappa: &str, key: &str) -> Result<(), StoreError> {
        self.inner.blob_delete_meta(kappa, key)
    }

    fn meta_set(&self, ns: &str, kappa: &str, key: &str, value: &str) -> Result<(), StoreError> {
        self.inner.meta_set(ns, kappa, key, value)
    }

    fn meta_query(&self, ns: &str, key: &str, value: &str) -> Result<Vec<String>, StoreError> {
        self.inner.meta_query(ns, key, value)
    }

    fn tag_set(&self, ns: &str, name: &str, kappa: &str) -> Result<u64, StoreError> {
        let version = self.inner.tag_set(ns, name, kappa)?;
        self.sync_tag(ns, name, kappa, version)?;
        Ok(version)
    }

    /// O(log n) point lookup via redb B+tree, falls back to InMemoryStore
    /// if the key is not in the redb index.
    fn tag_get(&self, ns: &str, name: &str) -> Result<TagEntry, StoreError> {
        let key = Self::tag_key(ns, name);
        let read_txn = self.db.begin_read().map_err(redb_err)?;
        let table = read_txn.open_table(TAG_TABLE).map_err(redb_err)?;
        if let Some(guard) = table.get(key.as_str()).map_err(redb_err)? {
            let val = guard.value();
            return Ok(Self::parse_tag_value(&key, val));
        }
        self.inner.tag_get(ns, name)
    }

    fn tag_delete(&self, ns: &str, name: &str) -> Result<(), StoreError> {
        self.inner.tag_delete(ns, name)?;
        self.remove_tag(ns, name)?;
        Ok(())
    }

    /// O(log n + k) sorted tag list via redb B+tree range scan.
    fn tag_list(&self, ns: &str) -> Result<Vec<TagEntry>, StoreError> {
        let start = Self::ns_range_start(ns);
        let end = Self::ns_range_end(ns);
        let read_txn = self.db.begin_read().map_err(redb_err)?;
        let table = read_txn.open_table(TAG_TABLE).map_err(redb_err)?;
        let range = table
            .range(start.as_str()..end.as_str())
            .map_err(redb_err)?;
        let mut result = Vec::new();
        for entry in range {
            let (key_guard, val_guard) = entry.map_err(redb_err)?;
            let key = key_guard.value();
            let val = val_guard.value();
            result.push(Self::parse_tag_value(key, val));
        }
        Ok(result)
    }

    /// O(log n + k) sorted prefix scan via redb B+tree range scan.
    fn tag_prefix(&self, ns: &str, prefix: &str) -> Result<Vec<TagEntry>, StoreError> {
        let start = Self::prefix_range_start(ns, prefix);
        let end = Self::prefix_range_end(ns, prefix);
        let read_txn = self.db.begin_read().map_err(redb_err)?;
        let table = read_txn.open_table(TAG_TABLE).map_err(redb_err)?;
        let range = table
            .range(start.as_str()..end.as_str())
            .map_err(redb_err)?;
        let mut result = Vec::new();
        for entry in range {
            let (key_guard, val_guard) = entry.map_err(redb_err)?;
            let key = key_guard.value();
            let val = val_guard.value();
            result.push(Self::parse_tag_value(key, val));
        }
        Ok(result)
    }

    fn tag_set_batch(&self, ns: &str, updates: &[TagUpdate]) -> Result<(), StoreError> {
        self.inner.tag_set_batch(ns, updates)?;
        let write_txn = self.db.begin_write().map_err(redb_err)?;
        {
            let mut table = write_txn.open_table(TAG_TABLE).map_err(redb_err)?;
            for update in updates {
                let entry = self.inner.tag_get(ns, &update.name)?;
                let key = Self::tag_key(ns, &update.name);
                let val = Self::tag_value(&entry.kappa, entry.version);
                table.insert(key.as_str(), val.as_str()).map_err(redb_err)?;
            }
        }
        write_txn.commit().map_err(redb_err)?;
        Ok(())
    }

    fn edge_put(&self, ns: &str, edge: &Edge) -> Result<(), StoreError> {
        self.inner.edge_put(ns, edge)
    }

    fn edge_query(&self, ns: &str, query: &EdgeQuery) -> Result<Vec<Edge>, StoreError> {
        self.inner.edge_query(ns, query)
    }

    fn edge_delete(
        &self,
        ns: &str,
        source: &str,
        target: &str,
        relation: EdgeRelation,
    ) -> Result<(), StoreError> {
        self.inner.edge_delete(ns, source, target, relation)
    }

    fn sequence_next(&self, ns: &str, name: &str) -> Result<u64, StoreError> {
        self.inner.sequence_next(ns, name)
    }

    fn sequence_current(&self, ns: &str, name: &str) -> Result<u64, StoreError> {
        self.inner.sequence_current(ns, name)
    }

    fn epoch_advance(&self, ns: &str, mutations: Vec<EpochMutation>) -> Result<String, StoreError> {
        self.inner.epoch_advance(ns, mutations)
    }

    fn epoch_current(&self, ns: &str) -> Result<Option<String>, StoreError> {
        self.inner.epoch_current(ns)
    }

    fn epoch_get(&self, kappa: &str) -> Result<EpochRoot, StoreError> {
        self.inner.epoch_get(kappa)
    }

    fn namespace_list(&self) -> Result<Vec<String>, StoreError> {
        self.inner.namespace_list()
    }

    fn namespace_exists(&self, ns: &str) -> Result<bool, StoreError> {
        self.inner.namespace_exists(ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_core::clock::ntp_lamport::NtpLamportClock;
    use kappa_core::kappa::kappa_from_bytes;
    use kappa_core::store::memory::MemoryStoreConfig;

    fn test_store() -> (RedbAcceleratedStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(NtpLamportClock::new());
        let inner = Arc::new(
            InMemoryStore::new(
                MemoryStoreConfig {
                    blob_root: dir.path().join("blobs"),
                },
                clock,
            )
            .unwrap(),
        );
        let db_path = dir.path().join("index.redb");
        let store = RedbAcceleratedStore::new(inner, db_path).unwrap();
        (store, dir)
    }

    #[test]
    fn tag_set_get() {
        let (s, _d) = test_store();
        assert_eq!(s.tag_set("ns", "latest", "sha256:aaa").unwrap(), 1);
        let entry = s.tag_get("ns", "latest").unwrap();
        assert_eq!(entry.kappa, "sha256:aaa");
        assert_eq!(entry.version, 1);
    }

    #[test]
    fn tag_list_uses_redb_range_scan() {
        let (s, _d) = test_store();
        s.tag_set("ns", "c", "k3").unwrap();
        s.tag_set("ns", "a", "k1").unwrap();
        s.tag_set("ns", "b", "k2").unwrap();
        let list = s.tag_list("ns").unwrap();
        let names: Vec<&str> = list.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn tag_list_isolates_namespaces() {
        let (s, _d) = test_store();
        s.tag_set("ns1", "a", "k1").unwrap();
        s.tag_set("ns2", "b", "k2").unwrap();
        let list = s.tag_list("ns1").unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].name, "a");
    }

    #[test]
    fn tag_prefix_uses_redb_range_scan() {
        let (s, _d) = test_store();
        s.tag_set("ns", "v1.0", "k1").unwrap();
        s.tag_set("ns", "v1.1", "k2").unwrap();
        s.tag_set("ns", "v2.0", "k3").unwrap();
        let result = s.tag_prefix("ns", "v1.").unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "v1.0");
        assert_eq!(result[1].name, "v1.1");
    }

    #[test]
    fn tag_delete_removes_from_redb() {
        let (s, _d) = test_store();
        s.tag_set("ns", "t", "k").unwrap();
        s.tag_delete("ns", "t").unwrap();
        let list = s.tag_list("ns").unwrap();
        assert!(list.is_empty());
    }

    #[test]
    fn tag_batch_syncs_to_redb() {
        let (s, _d) = test_store();
        let updates = vec![
            TagUpdate {
                name: "x".into(),
                kappa: "kx".into(),
                expected_version: None,
            },
            TagUpdate {
                name: "y".into(),
                kappa: "ky".into(),
                expected_version: None,
            },
        ];
        s.tag_set_batch("ns", &updates).unwrap();
        let list = s.tag_list("ns").unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name, "x");
        assert_eq!(list[1].name, "y");
    }

    #[test]
    fn tag_version_preserved_in_redb() {
        let (s, _d) = test_store();
        s.tag_set("ns", "t", "k1").unwrap();
        s.tag_set("ns", "t", "k2").unwrap();
        s.tag_set("ns", "t", "k3").unwrap();
        let list = s.tag_list("ns").unwrap();
        assert_eq!(list[0].version, 3);
        assert_eq!(list[0].kappa, "k3");
    }

    #[test]
    fn blob_operations_delegate() {
        let (s, _d) = test_store();
        let kappa = kappa_from_bytes(b"hello");
        s.blob_put(&kappa, b"hello").unwrap();
        assert_eq!(s.blob_get(&kappa).unwrap(), b"hello");
        assert!(s.blob_exists(&kappa).unwrap());
        assert_eq!(s.blob_size(&kappa).unwrap(), 5);
    }

    #[test]
    fn blob_meta_delegates() {
        let (s, _d) = test_store();
        let kappa = kappa_from_bytes(b"meta test");
        s.blob_put(&kappa, b"meta test").unwrap();
        s.blob_put_meta(&kappa, "content-type", b"text/plain")
            .unwrap();
        assert_eq!(
            s.blob_get_meta(&kappa, "content-type").unwrap(),
            b"text/plain"
        );
        s.blob_delete_meta(&kappa, "content-type").unwrap();
        assert!(s.blob_get_meta(&kappa, "content-type").is_err());
    }

    #[test]
    fn empty_namespace_returns_empty() {
        let (s, _d) = test_store();
        assert!(s.tag_list("empty").unwrap().is_empty());
    }

    #[test]
    fn empty_prefix_returns_empty() {
        let (s, _d) = test_store();
        s.tag_set("ns", "alpha", "k").unwrap();
        assert!(s.tag_prefix("ns", "zzz").unwrap().is_empty());
    }
}
