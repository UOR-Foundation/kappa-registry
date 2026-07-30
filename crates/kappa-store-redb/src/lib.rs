//! Persistent KappaStore backed by redb B+tree tables and filesystem blobs.
//!
//! All structured state (tags, edges, sequences, metadata, namespaces,
//! epoch pointers) is stored in redb tables and survives process restart.
//! Blobs remain on the filesystem, content-addressed by kappa-label.
//!
//! redb provides ACID transactions with Durability::Immediate by default
//! (fsync on commit). This means committed data survives kill -9.
//!
//! The store is organized as modules:
//!   blob.rs      -- filesystem blob ops + redb blob metadata + ns_meta
//!   tag.rs       -- redb tag CRUD with B+tree range scans
//!   edge.rs      -- redb edge tables with 4 multimap indexes
//!   epoch.rs     -- epoch chain with blob persistence + redb pointer
//!   namespace.rs -- redb namespace + sequence tables
//!   tables.rs    -- redb table constant definitions

mod blob;
mod edge;
mod epoch;
mod namespace;
mod tables;
mod tag;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use redb::Database;

use kappa_core::clock::Clock;
use kappa_core::epoch::EpochRoot;
use kappa_core::store::KappaStore;
use kappa_core::types::*;

pub struct PersistentStore {
    blob_root: PathBuf,
    clock: Arc<dyn Clock>,
    db: Database,
    fsync: bool,
    epoch_cache: RwLock<HashMap<String, EpochRoot>>,
}

impl PersistentStore {
    pub fn new(
        blob_root: PathBuf,
        db_path: PathBuf,
        clock: Arc<dyn Clock>,
        fsync: bool,
    ) -> Result<Self, StoreError> {
        std::fs::create_dir_all(&blob_root).map_err(StoreError::Io)?;
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).map_err(StoreError::Io)?;
        }
        let db = Database::create(&db_path).map_err(Self::redb_err)?;

        // Create all tables on first open
        let txn = db.begin_write().map_err(Self::redb_err)?;
        {
            txn.open_table(tables::TAGS).map_err(Self::redb_err)?;
            txn.open_table(tables::EDGES).map_err(Self::redb_err)?;
            txn.open_multimap_table(tables::EDGE_FWD)
                .map_err(Self::redb_err)?;
            txn.open_multimap_table(tables::EDGE_REV)
                .map_err(Self::redb_err)?;
            txn.open_multimap_table(tables::EDGE_REL)
                .map_err(Self::redb_err)?;
            txn.open_multimap_table(tables::EDGE_ASR)
                .map_err(Self::redb_err)?;
            txn.open_table(tables::SEQUENCES).map_err(Self::redb_err)?;
            txn.open_table(tables::BLOB_META).map_err(Self::redb_err)?;
            txn.open_multimap_table(tables::NS_META)
                .map_err(Self::redb_err)?;
            txn.open_table(tables::NAMESPACES).map_err(Self::redb_err)?;
            txn.open_table(tables::EPOCH_CURRENT)
                .map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;

        Ok(Self {
            blob_root,
            clock,
            db,
            fsync,
            epoch_cache: RwLock::new(HashMap::new()),
        })
    }

    pub(crate) fn redb_err(e: impl std::fmt::Display) -> StoreError {
        StoreError::Io(std::io::Error::other(e.to_string()))
    }

    /// Compute the successor key for prefix range scans.
    /// Handles 0xFF carry: increments the rightmost non-0xFF byte
    /// and truncates everything after it. Returns None if all bytes
    /// are 0xFF (range extends to end of keyspace).
    pub(crate) fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
        let mut successor = prefix.to_vec();
        while let Some(last) = successor.last_mut() {
            if *last < 0xFF {
                *last += 1;
                return Some(successor);
            }
            successor.pop();
        }
        None
    }
}

// -- KappaStore trait implementation -------------------------------------------
// Each method delegates to the _impl method in the corresponding module.

impl KappaStore for PersistentStore {
    fn blob_put(&self, kappa: &str, content: &[u8]) -> Result<bool, StoreError> {
        self.blob_put_impl(kappa, content)
    }
    fn blob_get(&self, kappa: &str) -> Result<Vec<u8>, StoreError> {
        self.blob_get_impl(kappa)
    }
    fn blob_exists(&self, kappa: &str) -> Result<bool, StoreError> {
        self.blob_exists_impl(kappa)
    }
    fn blob_delete(&self, kappa: &str) -> Result<(), StoreError> {
        self.blob_delete_impl(kappa)
    }
    fn blob_size(&self, kappa: &str) -> Result<u64, StoreError> {
        self.blob_size_impl(kappa)
    }
    fn blob_get_range(
        &self,
        kappa: &str,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, StoreError> {
        self.blob_get_range_impl(kappa, offset, length)
    }
    fn blob_list(&self) -> Result<Vec<String>, StoreError> {
        self.blob_list_impl()
    }
    fn blob_put_meta(
        &self,
        kappa: &str,
        key: &str,
        value: &[u8],
    ) -> Result<(), StoreError> {
        self.blob_put_meta_impl(kappa, key, value)
    }
    fn blob_get_meta(&self, kappa: &str, key: &str) -> Result<Vec<u8>, StoreError> {
        self.blob_get_meta_impl(kappa, key)
    }
    fn blob_delete_meta(&self, kappa: &str, key: &str) -> Result<(), StoreError> {
        self.blob_delete_meta_impl(kappa, key)
    }
    fn meta_set(
        &self,
        ns: &str,
        kappa: &str,
        key: &str,
        value: &str,
    ) -> Result<(), StoreError> {
        self.meta_set_impl(ns, kappa, key, value)
    }
    fn meta_query(
        &self,
        ns: &str,
        key: &str,
        value: &str,
    ) -> Result<Vec<String>, StoreError> {
        self.meta_query_impl(ns, key, value)
    }
    fn tag_set(&self, ns: &str, name: &str, kappa: &str) -> Result<u64, StoreError> {
        self.tag_set_impl(ns, name, kappa)
    }
    fn tag_get(&self, ns: &str, name: &str) -> Result<TagEntry, StoreError> {
        self.tag_get_impl(ns, name)
    }
    fn tag_delete(&self, ns: &str, name: &str) -> Result<(), StoreError> {
        self.tag_delete_impl(ns, name)
    }
    fn tag_list(&self, ns: &str) -> Result<Vec<TagEntry>, StoreError> {
        self.tag_list_impl(ns)
    }
    fn tag_prefix(&self, ns: &str, prefix: &str) -> Result<Vec<TagEntry>, StoreError> {
        self.tag_prefix_impl(ns, prefix)
    }
    fn tag_set_batch(&self, ns: &str, updates: &[TagUpdate]) -> Result<(), StoreError> {
        self.tag_set_batch_impl(ns, updates)
    }
    fn edge_put(&self, ns: &str, edge: &Edge) -> Result<(), StoreError> {
        self.edge_put_impl(ns, edge)
    }
    fn edge_query(&self, ns: &str, query: &EdgeQuery) -> Result<Vec<Edge>, StoreError> {
        self.edge_query_impl(ns, query)
    }
    fn edge_delete(
        &self,
        ns: &str,
        source: &str,
        target: &str,
        relation: EdgeRelation,
    ) -> Result<(), StoreError> {
        self.edge_delete_impl(ns, source, target, relation)
    }
    fn sequence_next(&self, ns: &str, name: &str) -> Result<u64, StoreError> {
        self.sequence_next_impl(ns, name)
    }
    fn sequence_current(&self, ns: &str, name: &str) -> Result<u64, StoreError> {
        self.sequence_current_impl(ns, name)
    }
    fn epoch_advance(
        &self,
        ns: &str,
        mutations: Vec<EpochMutation>,
    ) -> Result<String, StoreError> {
        self.epoch_advance_impl(ns, mutations)
    }
    fn epoch_current(&self, ns: &str) -> Result<Option<String>, StoreError> {
        self.epoch_current_impl(ns)
    }
    fn epoch_get(&self, kappa: &str) -> Result<EpochRoot, StoreError> {
        self.epoch_get_impl(kappa)
    }
    fn namespace_list(&self) -> Result<Vec<String>, StoreError> {
        self.namespace_list_impl()
    }
    fn namespace_exists(&self, ns: &str) -> Result<bool, StoreError> {
        self.namespace_exists_impl(ns)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_core::clock::ntp_lamport::NtpLamportClock;
    use kappa_core::kappa::kappa_from_bytes;
    use kappa_core::store::blob_put_computed;

    fn new_store() -> (PersistentStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let blob_root = tmp.path().join("blobs");
        let db_path = tmp.path().join("state.redb");
        let clock = Arc::new(NtpLamportClock::new());
        let store = PersistentStore::new(blob_root, db_path, clock, false).unwrap();
        (store, tmp)
    }

    fn reopen(tmp: &std::path::Path) -> PersistentStore {
        let blob_root = tmp.join("blobs");
        let db_path = tmp.join("state.redb");
        let clock = Arc::new(NtpLamportClock::new());
        PersistentStore::new(blob_root, db_path, clock, false).unwrap()
    }

    // -- Blob -----------------------------------------------------------------

    #[test]
    fn blob_roundtrip() {
        let (s, _d) = new_store();
        let k = kappa_from_bytes(b"hello");
        assert!(s.blob_put(&k, b"hello").unwrap());
        assert_eq!(s.blob_get(&k).unwrap(), b"hello");
        assert!(!s.blob_put(&k, b"hello").unwrap()); // idempotent
    }

    #[test]
    fn blob_meta_roundtrip() {
        let (s, _d) = new_store();
        let k = kappa_from_bytes(b"meta");
        s.blob_put(&k, b"meta").unwrap();
        s.blob_put_meta(&k, "ct", b"text/plain").unwrap();
        assert_eq!(s.blob_get_meta(&k, "ct").unwrap(), b"text/plain");
        s.blob_delete_meta(&k, "ct").unwrap();
        assert!(s.blob_get_meta(&k, "ct").is_err());
    }

    // -- Tag ------------------------------------------------------------------

    #[test]
    fn tag_set_get() {
        let (s, _d) = new_store();
        assert_eq!(s.tag_set("ns", "latest", "sha256:aaa").unwrap(), 1);
        let e = s.tag_get("ns", "latest").unwrap();
        assert_eq!(e.kappa, "sha256:aaa");
        assert_eq!(e.version, 1);
    }

    #[test]
    fn tag_list_sorted() {
        let (s, _d) = new_store();
        s.tag_set("ns", "c", "k3").unwrap();
        s.tag_set("ns", "a", "k1").unwrap();
        s.tag_set("ns", "b", "k2").unwrap();
        let list = s.tag_list("ns").unwrap();
        let names: Vec<&str> = list.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, vec!["a", "b", "c"]);
    }

    #[test]
    fn tag_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let s = reopen(tmp.path());
            let k = blob_put_computed(&s, b"persist").unwrap();
            s.tag_set("ns", "t1", &k).unwrap();
        }
        {
            let s = reopen(tmp.path());
            let e = s.tag_get("ns", "t1").unwrap();
            assert_eq!(e.version, 1);
        }
    }

    // -- Edge -----------------------------------------------------------------

    #[test]
    fn edge_put_query() {
        let (s, _d) = new_store();
        let edge = Edge {
            source: "sha256:src".into(),
            target: "sha256:tgt".into(),
            relation: EdgeRelation::Owns,
            asserter: "a".into(),
            value_kappa: None,
            metadata: None,
        };
        s.edge_put("ns", &edge).unwrap();
        let r = s
            .edge_query(
                "ns",
                &EdgeQuery {
                    anchor: "sha256:src".into(),
                    direction: Direction::Outbound,
                    relation: None,
                    asserter: None,
                },
            )
            .unwrap();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].target, "sha256:tgt");
    }

    #[test]
    fn edge_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let s = reopen(tmp.path());
            s.edge_put(
                "ns",
                &Edge {
                    source: "s".into(),
                    target: "t".into(),
                    relation: EdgeRelation::DerivedFrom,
                    asserter: "a".into(),
                    value_kappa: None,
                    metadata: None,
                },
            )
            .unwrap();
        }
        {
            let s = reopen(tmp.path());
            let r = s
                .edge_query(
                    "ns",
                    &EdgeQuery {
                        anchor: "s".into(),
                        direction: Direction::Outbound,
                        relation: None,
                        asserter: None,
                    },
                )
                .unwrap();
            assert_eq!(r.len(), 1);
        }
    }

    // -- Sequence -------------------------------------------------------------

    #[test]
    fn sequence_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let s = reopen(tmp.path());
            for _ in 0..5 {
                s.sequence_next("ns", "c").unwrap();
            }
        }
        {
            let s = reopen(tmp.path());
            assert_eq!(s.sequence_current("ns", "c").unwrap(), 5);
            assert_eq!(s.sequence_next("ns", "c").unwrap(), 6);
        }
    }

    // -- Namespace ------------------------------------------------------------

    #[test]
    fn namespace_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let s = reopen(tmp.path());
            s.tag_set("test-ns", "t", "k").unwrap();
        }
        {
            let s = reopen(tmp.path());
            assert!(s.namespace_exists("test-ns").unwrap());
            assert!(s.namespace_list().unwrap().contains(&"test-ns".to_string()));
        }
    }

    // -- Epoch ----------------------------------------------------------------

    #[test]
    fn epoch_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        let epoch_k;
        {
            let s = reopen(tmp.path());
            epoch_k = s.epoch_advance("ns", vec![]).unwrap();
        }
        {
            let s = reopen(tmp.path());
            assert_eq!(s.epoch_current("ns").unwrap(), Some(epoch_k.clone()));
            let root = s.epoch_get(&epoch_k).unwrap();
            assert_eq!(root.epoch_number, 1);
        }
    }

    // -- Meta query -----------------------------------------------------------

    #[test]
    fn meta_query_survives_reopen() {
        let tmp = tempfile::tempdir().unwrap();
        {
            let s = reopen(tmp.path());
            let k = blob_put_computed(&s, b"mq").unwrap();
            s.meta_set("ns", &k, "object-type", "manifest").unwrap();
        }
        {
            let s = reopen(tmp.path());
            let r = s.meta_query("ns", "object-type", "manifest").unwrap();
            assert_eq!(r.len(), 1);
        }
    }

    // -- Prefix successor -----------------------------------------------------

    #[test]
    fn prefix_successor_normal() {
        let s = PersistentStore::prefix_successor(b"abc");
        assert_eq!(s, Some(b"abd".to_vec()));
    }

    #[test]
    fn prefix_successor_trailing_ff() {
        let s = PersistentStore::prefix_successor(b"ab\xff");
        assert_eq!(s, Some(b"ac".to_vec()));
    }

    #[test]
    fn prefix_successor_all_ff() {
        let s = PersistentStore::prefix_successor(b"\xff\xff");
        assert_eq!(s, None);
    }
}
