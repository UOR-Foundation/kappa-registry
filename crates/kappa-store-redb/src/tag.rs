//! Tag operations for PersistentStore.
//!
//! Tags are stored in the redb TAGS table with compound keys
//! "{ns}\x00{name}" and values "{kappa}\x00{version}".
//!
//! All tag mutations use a single write transaction that includes
//! the NAMESPACES table insert (no separate ensure_namespace call).
//!
//! tag_set_batch validates all CAS preconditions in phase 1,
//! then applies all writes in phase 2, within one atomic transaction.

use redb::{ReadableDatabase, ReadableTable};

use kappa_core::types::*;

use crate::tables::{NAMESPACES, TAGS};
use crate::PersistentStore;

fn parse_version(val: &str) -> u64 {
    val.rsplit_once('\x00')
        .and_then(|(_, ver)| ver.parse::<u64>().ok())
        .unwrap_or(0)
}

fn parse_entry(name: &str, val: &str) -> Result<TagEntry, StoreError> {
    let (kappa, version_str) = val
        .rsplit_once('\x00')
        .ok_or_else(|| StoreError::Io(std::io::Error::other("corrupted tag value")))?;
    let version: u64 = version_str
        .parse()
        .map_err(|_| StoreError::Io(std::io::Error::other("corrupted tag version")))?;
    Ok(TagEntry {
        name: name.to_string(),
        kappa: kappa.to_string(),
        version,
    })
}

impl PersistentStore {
    pub(crate) fn tag_set_impl(
        &self,
        ns: &str,
        name: &str,
        kappa: &str,
    ) -> Result<u64, StoreError> {
        let db_key = format!("{}\x00{}", ns, name);
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        let version;
        {
            let mut ns_table = txn.open_table(NAMESPACES).map_err(Self::redb_err)?;
            ns_table.insert(ns, ()).map_err(Self::redb_err)?;

            let mut table = txn.open_table(TAGS).map_err(Self::redb_err)?;
            let current_version = table
                .get(db_key.as_str())
                .map_err(Self::redb_err)?
                .map(|v| parse_version(v.value()))
                .unwrap_or(0);
            version = current_version + 1;
            let db_value = format!("{}\x00{}", kappa, version);
            table
                .insert(db_key.as_str(), db_value.as_str())
                .map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(version)
    }

    pub(crate) fn tag_get_impl(&self, ns: &str, name: &str) -> Result<TagEntry, StoreError> {
        let db_key = format!("{}\x00{}", ns, name);
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(TAGS).map_err(Self::redb_err)?;
        let val = table
            .get(db_key.as_str())
            .map_err(Self::redb_err)?
            .ok_or_else(|| StoreError::NotFound(format!("{}/{}", ns, name)))?;
        parse_entry(name, val.value())
    }

    pub(crate) fn tag_delete_impl(&self, ns: &str, name: &str) -> Result<(), StoreError> {
        let db_key = format!("{}\x00{}", ns, name);
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let mut table = txn.open_table(TAGS).map_err(Self::redb_err)?;
            table.remove(db_key.as_str()).map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }

    pub(crate) fn tag_list_impl(&self, ns: &str) -> Result<Vec<TagEntry>, StoreError> {
        let prefix = format!("{}\x00", ns);
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(TAGS).map_err(Self::redb_err)?;
        let mut entries = Vec::new();

        match Self::prefix_successor(prefix.as_bytes()) {
            Some(end_bytes) => {
                let end_str = String::from_utf8(end_bytes)
                    .map_err(|_| StoreError::Io(std::io::Error::other("utf8")))?;
                for item in table
                    .range::<&str>(prefix.as_str()..end_str.as_str())
                    .map_err(Self::redb_err)?
                {
                    let (k, v) = item.map_err(Self::redb_err)?;
                    let name = k.value().strip_prefix(&prefix).ok_or_else(|| {
                        StoreError::Io(std::io::Error::other("prefix mismatch"))
                    })?;
                    entries.push(parse_entry(name, v.value())?);
                }
            }
            None => {
                for item in table
                    .range::<&str>(prefix.as_str()..)
                    .map_err(Self::redb_err)?
                {
                    let (k, v) = item.map_err(Self::redb_err)?;
                    let key_str = k.value();
                    if !key_str.starts_with(&prefix) {
                        break;
                    }
                    let name = key_str.strip_prefix(&prefix).unwrap();
                    entries.push(parse_entry(name, v.value())?);
                }
            }
        }
        // Already sorted by redb B+tree key ordering
        Ok(entries)
    }

    pub(crate) fn tag_prefix_impl(
        &self,
        ns: &str,
        prefix: &str,
    ) -> Result<Vec<TagEntry>, StoreError> {
        let db_prefix = format!("{}\x00{}", ns, prefix);
        let ns_prefix = format!("{}\x00", ns);
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(TAGS).map_err(Self::redb_err)?;
        let mut entries = Vec::new();

        match Self::prefix_successor(db_prefix.as_bytes()) {
            Some(end_bytes) => {
                let end_str = String::from_utf8(end_bytes)
                    .map_err(|_| StoreError::Io(std::io::Error::other("utf8")))?;
                for item in table
                    .range::<&str>(db_prefix.as_str()..end_str.as_str())
                    .map_err(Self::redb_err)?
                {
                    let (k, v) = item.map_err(Self::redb_err)?;
                    let name = k.value().strip_prefix(&ns_prefix).ok_or_else(|| {
                        StoreError::Io(std::io::Error::other("prefix mismatch"))
                    })?;
                    entries.push(parse_entry(name, v.value())?);
                }
            }
            None => {
                for item in table
                    .range::<&str>(db_prefix.as_str()..)
                    .map_err(Self::redb_err)?
                {
                    let (k, v) = item.map_err(Self::redb_err)?;
                    let key_str = k.value();
                    if !key_str.starts_with(&db_prefix) {
                        break;
                    }
                    let name = key_str.strip_prefix(&ns_prefix).unwrap();
                    entries.push(parse_entry(name, v.value())?);
                }
            }
        }
        Ok(entries)
    }

    pub(crate) fn tag_set_batch_impl(
        &self,
        ns: &str,
        updates: &[TagUpdate],
    ) -> Result<(), StoreError> {
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let mut ns_table = txn.open_table(NAMESPACES).map_err(Self::redb_err)?;
            ns_table.insert(ns, ()).map_err(Self::redb_err)?;
            drop(ns_table);

            let mut table = txn.open_table(TAGS).map_err(Self::redb_err)?;

            // Phase 1: validate all CAS preconditions
            for update in updates {
                if let Some(expected) = update.expected_version {
                    let db_key = format!("{}\x00{}", ns, update.name);
                    let current = table
                        .get(db_key.as_str())
                        .map_err(Self::redb_err)?
                        .map(|v| parse_version(v.value()))
                        .unwrap_or(0);
                    if current != expected {
                        return Err(StoreError::Conflict(format!(
                            "tag {}: expected version {} but current is {}",
                            update.name, expected, current
                        )));
                    }
                }
            }

            // Phase 2: apply all writes
            for update in updates {
                let db_key = format!("{}\x00{}", ns, update.name);
                let current = table
                    .get(db_key.as_str())
                    .map_err(Self::redb_err)?
                    .map(|v| parse_version(v.value()))
                    .unwrap_or(0);
                let version = current + 1;
                let db_value = format!("{}\x00{}", update.kappa, version);
                table
                    .insert(db_key.as_str(), db_value.as_str())
                    .map_err(Self::redb_err)?;
            }
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }
}
