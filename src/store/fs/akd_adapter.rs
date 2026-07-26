//! AKD Database adapter backed by redb.
//!
//! Implements storage for the AKD (Auditable Key Directory) against a
//! per-namespace redb file at `vkd/{safe_name(ns)}.redb`.
//!
//! Three redb tables mirror akd's StorageType enum:
//! - AZKS (tag 1): single Azks record (StorageKey = u8)
//! - TREE_NODE (tag 2): sparse Merkle tree nodes
//! - VALUE_STATE (tag 4): keyed on (username, epoch) for prefix-scan reads
//!
//! Transaction priority constraint from akd types.rs:203:
//! Azks gets priority 2 (written last). TreeNode and ValueState get
//! priority 1. In batch_set, insert TreeNode and ValueState first,
//! Azks last, then commit.

use std::path::Path;
use std::sync::Arc;

use redb::{Database, ReadableDatabase, TableDefinition};

use crate::store::StoreError;

/// Key-value pair from a VALUE_STATE prefix scan.
pub type KeyValuePair = (Vec<u8>, Vec<u8>);

const AZKS_TABLE: TableDefinition<u8, &[u8]> = TableDefinition::new("akd_azks");
const TREE_NODE_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("akd_tree_nodes");
const VALUE_STATE_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("akd_value_states");

/// StorageType tag values matching akd's StorageType enum.
pub const TAG_AZKS: u8 = 1;
pub const TAG_TREE_NODE: u8 = 2;
pub const TAG_VALUE_STATE: u8 = 4;

fn redb_err(e: impl std::fmt::Display) -> StoreError {
    StoreError::Io(std::io::Error::other(e.to_string()))
}

/// A redb-backed storage adapter for akd.
///
/// Each asserter namespace gets its own instance at
/// `vkd/{safe_name(ns)}.redb`.
pub struct RedbAkdStore {
    db: Arc<Database>,
}

impl RedbAkdStore {
    /// Open or create the AKD store for a namespace.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let db = Database::create(path).map_err(redb_err)?;

        // Ensure tables exist on first open.
        let write_txn = db.begin_write().map_err(redb_err)?;
        {
            write_txn.open_table(AZKS_TABLE).map_err(redb_err)?;
            write_txn.open_table(TREE_NODE_TABLE).map_err(redb_err)?;
            write_txn.open_table(VALUE_STATE_TABLE).map_err(redb_err)?;
        }
        write_txn.commit().map_err(redb_err)?;

        Ok(Self { db: Arc::new(db) })
    }

    /// Build a VALUE_STATE key from username bytes and epoch.
    ///
    /// Format: u16(username.len) BE + username + epoch BE u64
    /// Enables prefix scan on username for get_user_data and range
    /// scan with epoch for get_user_state.
    pub fn value_state_key(username: &[u8], epoch: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(2 + username.len() + 8);
        key.extend_from_slice(&(username.len() as u16).to_be_bytes());
        key.extend_from_slice(username);
        key.extend_from_slice(&epoch.to_be_bytes());
        key
    }

    /// Build a prefix for scanning all VALUE_STATE entries for a username.
    pub fn value_state_prefix(username: &[u8]) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(2 + username.len());
        prefix.extend_from_slice(&(username.len() as u16).to_be_bytes());
        prefix.extend_from_slice(username);
        prefix
    }

    fn prefix_upper_bound(prefix: &[u8]) -> Vec<u8> {
        let mut bound = prefix.to_vec();
        while let Some(last) = bound.last_mut() {
            if *last < 0xFF {
                *last += 1;
                return bound;
            }
            bound.pop();
        }
        vec![0xFF; prefix.len() + 1]
    }

    /// Store a single record by table tag and key.
    pub fn set(&self, table_tag: u8, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write().map_err(redb_err)?;
        {
            match table_tag {
                TAG_AZKS => {
                    let mut table = write_txn.open_table(AZKS_TABLE).map_err(redb_err)?;
                    let k = if key.is_empty() { 1u8 } else { key[0] };
                    table.insert(k, value).map_err(redb_err)?;
                }
                TAG_TREE_NODE => {
                    let mut table = write_txn.open_table(TREE_NODE_TABLE).map_err(redb_err)?;
                    table.insert(key, value).map_err(redb_err)?;
                }
                TAG_VALUE_STATE => {
                    let mut table = write_txn.open_table(VALUE_STATE_TABLE).map_err(redb_err)?;
                    table.insert(key, value).map_err(redb_err)?;
                }
                other => {
                    return Err(StoreError::Io(std::io::Error::other(format!(
                        "unknown akd table tag: {other}"
                    ))));
                }
            }
        }
        write_txn.commit().map_err(redb_err)?;
        Ok(())
    }

    /// Batch set with priority ordering: TreeNode and ValueState first,
    /// Azks last. All in one redb WriteTransaction.
    ///
    /// Each entry is (table_tag, key, value).
    pub fn batch_set(&self, records: &[(u8, Vec<u8>, Vec<u8>)]) -> Result<(), StoreError> {
        let write_txn = self.db.begin_write().map_err(redb_err)?;
        {
            let mut azks_table = write_txn.open_table(AZKS_TABLE).map_err(redb_err)?;
            let mut tree_table = write_txn.open_table(TREE_NODE_TABLE).map_err(redb_err)?;
            let mut vs_table = write_txn.open_table(VALUE_STATE_TABLE).map_err(redb_err)?;

            // Priority 1: TreeNode + ValueState
            for (tag, key, value) in records {
                match *tag {
                    TAG_TREE_NODE => {
                        tree_table
                            .insert(key.as_slice(), value.as_slice())
                            .map_err(redb_err)?;
                    }
                    TAG_VALUE_STATE => {
                        vs_table
                            .insert(key.as_slice(), value.as_slice())
                            .map_err(redb_err)?;
                    }
                    _ => {}
                }
            }

            // Priority 2: Azks (last)
            for (tag, key, value) in records {
                if *tag == TAG_AZKS {
                    let k = if key.is_empty() { 1u8 } else { key[0] };
                    azks_table.insert(k, value.as_slice()).map_err(redb_err)?;
                }
            }
        }
        write_txn.commit().map_err(redb_err)?;
        Ok(())
    }

    /// Get a single record by table tag and key.
    pub fn get(&self, table_tag: u8, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        let read_txn = self.db.begin_read().map_err(redb_err)?;

        let result = match table_tag {
            TAG_AZKS => {
                let table = match read_txn.open_table(AZKS_TABLE) {
                    Ok(t) => t,
                    Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                    Err(e) => return Err(redb_err(e)),
                };
                let k = if key.is_empty() { 1u8 } else { key[0] };
                table.get(k).map_err(redb_err)?.map(|g| g.value().to_vec())
            }
            TAG_TREE_NODE => {
                let table = match read_txn.open_table(TREE_NODE_TABLE) {
                    Ok(t) => t,
                    Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                    Err(e) => return Err(redb_err(e)),
                };
                table
                    .get(key)
                    .map_err(redb_err)?
                    .map(|g| g.value().to_vec())
            }
            TAG_VALUE_STATE => {
                let table = match read_txn.open_table(VALUE_STATE_TABLE) {
                    Ok(t) => t,
                    Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
                    Err(e) => return Err(redb_err(e)),
                };
                table
                    .get(key)
                    .map_err(redb_err)?
                    .map(|g| g.value().to_vec())
            }
            _ => None,
        };
        Ok(result)
    }

    /// Prefix scan on VALUE_STATE table for a given username.
    /// Returns all (key, value) pairs where key starts with the username prefix.
    pub fn scan_user_states(&self, username: &[u8]) -> Result<Vec<KeyValuePair>, StoreError> {
        let read_txn = self.db.begin_read().map_err(redb_err)?;
        let table = match read_txn.open_table(VALUE_STATE_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(redb_err(e)),
        };

        let prefix = Self::value_state_prefix(username);
        let upper = Self::prefix_upper_bound(&prefix);
        let range = table
            .range(prefix.as_slice()..upper.as_slice())
            .map_err(redb_err)?;

        let mut results = Vec::new();
        for entry in range {
            let (k, v) = entry.map_err(redb_err)?;
            results.push((k.value().to_vec(), v.value().to_vec()));
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn open_creates_tables() {
        let dir = TempDir::new().unwrap();
        let store = RedbAkdStore::open(&dir.path().join("test.redb")).unwrap();
        assert!(store.get(TAG_AZKS, &[1]).unwrap().is_none());
        assert!(store.get(TAG_TREE_NODE, b"nonexistent").unwrap().is_none());
        assert!(store
            .get(TAG_VALUE_STATE, b"nonexistent")
            .unwrap()
            .is_none());
    }

    #[test]
    fn set_get_roundtrip() {
        let dir = TempDir::new().unwrap();
        let store = RedbAkdStore::open(&dir.path().join("test.redb")).unwrap();

        store.set(TAG_AZKS, &[1], b"azks-data").unwrap();
        store.set(TAG_TREE_NODE, b"node-key", b"node-data").unwrap();
        store.set(TAG_VALUE_STATE, b"vs-key", b"vs-data").unwrap();

        assert_eq!(
            store.get(TAG_AZKS, &[1]).unwrap(),
            Some(b"azks-data".to_vec())
        );
        assert_eq!(
            store.get(TAG_TREE_NODE, b"node-key").unwrap(),
            Some(b"node-data".to_vec())
        );
        assert_eq!(
            store.get(TAG_VALUE_STATE, b"vs-key").unwrap(),
            Some(b"vs-data".to_vec())
        );
    }

    #[test]
    fn batch_set_priority_order() {
        let dir = TempDir::new().unwrap();
        let store = RedbAkdStore::open(&dir.path().join("test.redb")).unwrap();

        let records = vec![
            (TAG_AZKS, vec![1], b"azks".to_vec()),
            (TAG_TREE_NODE, b"node".to_vec(), b"node-val".to_vec()),
            (TAG_VALUE_STATE, b"vs".to_vec(), b"vs-val".to_vec()),
        ];
        store.batch_set(&records).unwrap();

        assert_eq!(store.get(TAG_AZKS, &[1]).unwrap(), Some(b"azks".to_vec()));
        assert_eq!(
            store.get(TAG_TREE_NODE, b"node").unwrap(),
            Some(b"node-val".to_vec())
        );
        assert_eq!(
            store.get(TAG_VALUE_STATE, b"vs").unwrap(),
            Some(b"vs-val".to_vec())
        );
    }

    #[test]
    fn value_state_key_format() {
        let key = RedbAkdStore::value_state_key(b"alice", 42);
        assert_eq!(key.len(), 2 + 5 + 8);
        assert_eq!(&key[..2], &5u16.to_be_bytes());
        assert_eq!(&key[2..7], b"alice");
        assert_eq!(&key[7..], &42u64.to_be_bytes());
    }

    #[test]
    fn scan_user_states_prefix() {
        let dir = TempDir::new().unwrap();
        let store = RedbAkdStore::open(&dir.path().join("test.redb")).unwrap();

        let k1 = RedbAkdStore::value_state_key(b"alice", 1);
        let k2 = RedbAkdStore::value_state_key(b"alice", 2);
        let k3 = RedbAkdStore::value_state_key(b"bob", 1);

        store.set(TAG_VALUE_STATE, &k1, b"alice-epoch-1").unwrap();
        store.set(TAG_VALUE_STATE, &k2, b"alice-epoch-2").unwrap();
        store.set(TAG_VALUE_STATE, &k3, b"bob-epoch-1").unwrap();

        let alice_states = store.scan_user_states(b"alice").unwrap();
        assert_eq!(alice_states.len(), 2);

        let bob_states = store.scan_user_states(b"bob").unwrap();
        assert_eq!(bob_states.len(), 1);

        let nobody_states = store.scan_user_states(b"nobody").unwrap();
        assert!(nobody_states.is_empty());
    }
}
