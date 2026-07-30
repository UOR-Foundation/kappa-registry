//! Namespace and sequence operations for PersistentStore.

use redb::{ReadableDatabase, ReadableTable};

use kappa_core::types::StoreError;

use crate::tables::*;
use crate::PersistentStore;

impl PersistentStore {
    // -- Sequence (redb SEQUENCES table) --------------------------------------

    pub(crate) fn sequence_next_impl(
        &self,
        ns: &str,
        name: &str,
    ) -> Result<u64, StoreError> {
        let db_key = format!("{}\x00{}", ns, name);
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        let value;
        {
            let mut ns_table = txn.open_table(NAMESPACES).map_err(Self::redb_err)?;
            ns_table.insert(ns, ()).map_err(Self::redb_err)?;
            drop(ns_table);

            let mut table = txn.open_table(SEQUENCES).map_err(Self::redb_err)?;
            let current = table
                .get(db_key.as_str())
                .map_err(Self::redb_err)?
                .map(|v| v.value())
                .unwrap_or(0);
            value = current + 1;
            table
                .insert(db_key.as_str(), value)
                .map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(value)
    }

    pub(crate) fn sequence_current_impl(
        &self,
        ns: &str,
        name: &str,
    ) -> Result<u64, StoreError> {
        let db_key = format!("{}\x00{}", ns, name);
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(SEQUENCES).map_err(Self::redb_err)?;
        Ok(table
            .get(db_key.as_str())
            .map_err(Self::redb_err)?
            .map(|v| v.value())
            .unwrap_or(0))
    }

    // -- Namespace (redb NAMESPACES table) ------------------------------------

    pub(crate) fn namespace_list_impl(&self) -> Result<Vec<String>, StoreError> {
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(NAMESPACES).map_err(Self::redb_err)?;
        let mut result: Vec<String> = table
            .iter()
            .map_err(Self::redb_err)?
            .filter_map(|item| item.ok().map(|(k, _)| k.value().to_string()))
            .collect();
        result.sort();
        Ok(result)
    }

    pub(crate) fn namespace_exists_impl(&self, ns: &str) -> Result<bool, StoreError> {
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(NAMESPACES).map_err(Self::redb_err)?;
        Ok(table.get(ns).map_err(Self::redb_err)?.is_some())
    }
}
