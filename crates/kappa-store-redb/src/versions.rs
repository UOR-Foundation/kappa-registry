//! Version chain index implementation for PersistentStore.
//!
//! Composite key: {ns}\x00{key}\x00{!timestamp_be}
//! Bit-inverted timestamp makes newest versions sort first in redb's
//! ascending B-tree. Value: JSON-serialized VersionEntry.
//!
//! Three versioning states per namespace, stored as tag _config/versioning:
//! - Unversioned (default): bypass version table, delegate to tag_set/get/delete
//! - Enabled: UUID version_id per write, version table populated
//! - Suspended: version_id = "null", replaces previous null entry

use kappa_core::types::{DeleteResult, StoreError, VersionEntry, VersioningState};
use redb::{ReadableDatabase, ReadableTable};

use crate::tables::VERSIONS;
use crate::PersistentStore;

impl PersistentStore {
    /// Read the versioning state for a namespace from the _config/versioning tag.
    pub(crate) fn versioning_state(&self, ns: &str) -> Result<VersioningState, StoreError> {
        match self.tag_get_impl(ns, "_config/versioning") {
            Ok(entry) => match entry.kappa.as_str() {
                "enabled" => Ok(VersioningState::Enabled),
                "suspended" => Ok(VersioningState::Suspended),
                _ => Ok(VersioningState::Unversioned),
            },
            Err(StoreError::NotFound(_)) => Ok(VersioningState::Unversioned),
            Err(e) => Err(e),
        }
    }

    fn version_composite_key(ns: &str, key: &str, timestamp_ms: u64) -> Vec<u8> {
        let inverted_ts = (!timestamp_ms).to_be_bytes();
        let mut composite = Vec::with_capacity(ns.len() + 1 + key.len() + 1 + 8);
        composite.extend_from_slice(ns.as_bytes());
        composite.push(0);
        composite.extend_from_slice(key.as_bytes());
        composite.push(0);
        composite.extend_from_slice(&inverted_ts);
        composite
    }

    fn version_prefix(ns: &str, key: &str) -> Vec<u8> {
        let mut prefix = Vec::with_capacity(ns.len() + 1 + key.len() + 1);
        prefix.extend_from_slice(ns.as_bytes());
        prefix.push(0);
        prefix.extend_from_slice(key.as_bytes());
        prefix.push(0);
        prefix
    }

    fn serialize_version_entry(entry: &VersionEntry) -> Result<Vec<u8>, StoreError> {
        serde_json::to_vec(entry)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))
    }

    fn deserialize_version_entry(bytes: &[u8]) -> Result<VersionEntry, StoreError> {
        serde_json::from_slice(bytes)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))
    }

    pub(crate) fn version_put_impl(
        &self,
        ns: &str,
        key: &str,
        kappa: &str,
        etag: Option<&str>,
    ) -> Result<String, StoreError> {
        let state = self.versioning_state(ns)?;
        match state {
            VersioningState::Unversioned => {
                self.tag_set_impl(ns, key, kappa)?;
                Ok("null".to_string())
            }
            VersioningState::Enabled => {
                let version_id = uuid::Uuid::new_v4().to_string();
                let now_ms = self.clock.now_ms();
                let size = self.blob_size_impl(kappa).unwrap_or(0);
                let entry = VersionEntry {
                    version_id: version_id.clone(),
                    kappa: Some(kappa.to_string()),
                    is_delete_marker: false,
                    timestamp_ms: now_ms,
                    size,
                    etag: etag.map(|s| s.to_string()),
                };
                let composite_key = Self::version_composite_key(ns, key, now_ms);
                let value = Self::serialize_version_entry(&entry)?;
                let txn = self.db.begin_write().map_err(Self::redb_err)?;
                {
                    let mut table = txn.open_table(VERSIONS).map_err(Self::redb_err)?;
                    table
                        .insert(composite_key.as_slice(), value.as_slice())
                        .map_err(Self::redb_err)?;
                }
                txn.commit().map_err(Self::redb_err)?;
                self.tag_set_impl(ns, key, kappa)?;
                Ok(version_id)
            }
            VersioningState::Suspended => {
                let now_ms = self.clock.now_ms();
                let size = self.blob_size_impl(kappa).unwrap_or(0);
                // Remove previous "null" version entry
                self.version_remove_null(ns, key)?;
                let entry = VersionEntry {
                    version_id: "null".to_string(),
                    kappa: Some(kappa.to_string()),
                    is_delete_marker: false,
                    timestamp_ms: now_ms,
                    size,
                    etag: etag.map(|s| s.to_string()),
                };
                let composite_key = Self::version_composite_key(ns, key, now_ms);
                let value = Self::serialize_version_entry(&entry)?;
                let txn = self.db.begin_write().map_err(Self::redb_err)?;
                {
                    let mut table = txn.open_table(VERSIONS).map_err(Self::redb_err)?;
                    table
                        .insert(composite_key.as_slice(), value.as_slice())
                        .map_err(Self::redb_err)?;
                }
                txn.commit().map_err(Self::redb_err)?;
                self.tag_set_impl(ns, key, kappa)?;
                Ok("null".to_string())
            }
        }
    }

    pub(crate) fn version_get_impl(
        &self,
        ns: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<VersionEntry, StoreError> {
        let state = self.versioning_state(ns)?;
        if matches!(state, VersioningState::Unversioned) {
            // Unversioned: delegate to tag_get
            let tag = self.tag_get_impl(ns, key)?;
            let size = self.blob_size_impl(&tag.kappa).unwrap_or(0);
            return Ok(VersionEntry {
                version_id: "null".to_string(),
                kappa: Some(tag.kappa),
                is_delete_marker: false,
                timestamp_ms: 0,
                size,
                etag: None,
            });
        }

        let prefix = Self::version_prefix(ns, key);
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(VERSIONS).map_err(Self::redb_err)?;

        // Scan entries for this key
        let range = match Self::prefix_successor(&prefix) {
            Some(end) => {
                table
                    .range::<&[u8]>(prefix.as_slice()..end.as_slice())
                    .map_err(Self::redb_err)?
            }
            None => {
                table
                    .range::<&[u8]>(prefix.as_slice()..)
                    .map_err(Self::redb_err)?
            }
        };

        match version_id {
            Some(vid) => {
                // Find specific version_id
                for item in range {
                    let (_, v) = item.map_err(Self::redb_err)?;
                    let entry = Self::deserialize_version_entry(v.value())?;
                    if entry.version_id == vid {
                        return Ok(entry);
                    }
                }
                Err(StoreError::NotFound(format!(
                    "version {} of {}/{}",
                    vid, ns, key
                )))
            }
            None => {
                // Find latest non-delete-marker
                for item in range {
                    let (_, v) = item.map_err(Self::redb_err)?;
                    let entry = Self::deserialize_version_entry(v.value())?;
                    if entry.is_delete_marker {
                        // First entry is a delete marker -- object is "deleted"
                        return Err(StoreError::NotFound(format!(
                            "{}/{} (delete marker: {})",
                            ns, key, entry.version_id
                        )));
                    }
                    return Ok(entry);
                }
                Err(StoreError::NotFound(format!("{}/{}", ns, key)))
            }
        }
    }

    pub(crate) fn version_delete_impl(
        &self,
        ns: &str,
        key: &str,
        version_id: Option<&str>,
    ) -> Result<DeleteResult, StoreError> {
        let state = self.versioning_state(ns)?;
        if matches!(state, VersioningState::Unversioned) {
            self.tag_delete_impl(ns, key)?;
            return Ok(DeleteResult {
                version_id: "null".to_string(),
                is_delete_marker: false,
            });
        }

        match version_id {
            None => {
                // Insert delete marker
                let now_ms = self.clock.now_ms();
                let marker_id = uuid::Uuid::new_v4().to_string();
                let entry = VersionEntry {
                    version_id: marker_id.clone(),
                    kappa: None,
                    is_delete_marker: true,
                    timestamp_ms: now_ms,
                    size: 0,
                    etag: None,
                };
                let composite_key = Self::version_composite_key(ns, key, now_ms);
                let value = Self::serialize_version_entry(&entry)?;
                let txn = self.db.begin_write().map_err(Self::redb_err)?;
                {
                    let mut table = txn.open_table(VERSIONS).map_err(Self::redb_err)?;
                    table
                        .insert(composite_key.as_slice(), value.as_slice())
                        .map_err(Self::redb_err)?;
                }
                txn.commit().map_err(Self::redb_err)?;
                // Remove the current tag binding (object appears deleted)
                let _ = self.tag_delete_impl(ns, key);
                Ok(DeleteResult {
                    version_id: marker_id,
                    is_delete_marker: true,
                })
            }
            Some(vid) => {
                // Permanent removal of a specific version
                let prefix = Self::version_prefix(ns, key);
                let txn = self.db.begin_write().map_err(Self::redb_err)?;
                {
                    let mut table = txn.open_table(VERSIONS).map_err(Self::redb_err)?;
                    // Find and remove the entry with matching version_id
                    let range = match Self::prefix_successor(&prefix) {
                        Some(end) => {
                            table
                                .range::<&[u8]>(prefix.as_slice()..end.as_slice())
                                .map_err(Self::redb_err)?
                        }
                        None => {
                            table
                                .range::<&[u8]>(prefix.as_slice()..)
                                .map_err(Self::redb_err)?
                        }
                    };
                    let mut key_to_remove: Option<Vec<u8>> = None;
                    let mut was_delete_marker = false;
                    for item in range {
                        let (k, v) = item.map_err(Self::redb_err)?;
                        let entry = Self::deserialize_version_entry(v.value())?;
                        if entry.version_id == vid {
                            key_to_remove = Some(k.value().to_vec());
                            was_delete_marker = entry.is_delete_marker;
                            break;
                        }
                    }
                    if let Some(key_bytes) = key_to_remove {
                        table
                            .remove(key_bytes.as_slice())
                            .map_err(Self::redb_err)?;
                    }
                    drop(table);
                    txn.commit().map_err(Self::redb_err)?;
                    Ok(DeleteResult {
                        version_id: vid.to_string(),
                        is_delete_marker: was_delete_marker,
                    })
                }
            }
        }
    }

    pub(crate) fn version_list_impl(
        &self,
        ns: &str,
        key: &str,
        max: usize,
    ) -> Result<Vec<VersionEntry>, StoreError> {
        let state = self.versioning_state(ns)?;
        if matches!(state, VersioningState::Unversioned) {
            return Ok(Vec::new());
        }

        let prefix = Self::version_prefix(ns, key);
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(VERSIONS).map_err(Self::redb_err)?;

        let range = match Self::prefix_successor(&prefix) {
            Some(end) => {
                table
                    .range::<&[u8]>(prefix.as_slice()..end.as_slice())
                    .map_err(Self::redb_err)?
            }
            None => {
                table
                    .range::<&[u8]>(prefix.as_slice()..)
                    .map_err(Self::redb_err)?
            }
        };

        let mut entries = Vec::new();
        for item in range {
            if entries.len() >= max {
                break;
            }
            let (_, v) = item.map_err(Self::redb_err)?;
            let entry = Self::deserialize_version_entry(v.value())?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// Remove all entries with version_id == "null" for a given ns/key.
    fn version_remove_null(&self, ns: &str, key: &str) -> Result<(), StoreError> {
        let prefix = Self::version_prefix(ns, key);
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let mut table = txn.open_table(VERSIONS).map_err(Self::redb_err)?;
            let range = match Self::prefix_successor(&prefix) {
                Some(end) => {
                    table
                        .range::<&[u8]>(prefix.as_slice()..end.as_slice())
                        .map_err(Self::redb_err)?
                }
                None => {
                    table
                        .range::<&[u8]>(prefix.as_slice()..)
                        .map_err(Self::redb_err)?
                }
            };
            let mut keys_to_remove: Vec<Vec<u8>> = Vec::new();
            for item in range {
                let (k, v) = item.map_err(Self::redb_err)?;
                let entry = Self::deserialize_version_entry(v.value())?;
                if entry.version_id == "null" {
                    keys_to_remove.push(k.value().to_vec());
                }
            }
            for key_bytes in keys_to_remove {
                table
                    .remove(key_bytes.as_slice())
                    .map_err(Self::redb_err)?;
            }
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }
}
