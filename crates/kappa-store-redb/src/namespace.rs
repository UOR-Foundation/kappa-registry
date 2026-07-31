//! Namespace and sequence operations for PersistentStore.

use redb::{ReadableDatabase, ReadableTable};

use kappa_core::types::StoreError;

use crate::tables::*;
use crate::PersistentStore;

impl PersistentStore {
    // -- Sequence (redb SEQUENCES table) --------------------------------------

    pub(crate) fn decode_seq_value(&self, db_key: &str, raw: &[u8]) -> Result<u64, StoreError> {
        let bytes = match &self.table_encryptor {
            Some(enc) => enc.decrypt_value(db_key, raw)
                .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?,
            None => raw.to_vec(),
        };
        if bytes.len() != 8 {
            return Err(StoreError::Io(std::io::Error::other("sequence value not 8 bytes")));
        }
        Ok(u64::from_be_bytes(bytes.try_into().unwrap()))
    }

    pub(crate) fn encode_seq_value(&self, db_key: &str, value: u64) -> Result<Vec<u8>, StoreError> {
        let bytes = value.to_be_bytes();
        match &self.table_encryptor {
            Some(enc) => enc.encrypt_value(db_key, &bytes)
                .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string()))),
            None => Ok(bytes.to_vec()),
        }
    }

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
            let current = match table.get(db_key.as_str()).map_err(Self::redb_err)? {
                Some(v) => self.decode_seq_value(&db_key, v.value())?,
                None => 0,
            };
            value = current + 1;
            let encoded = self.encode_seq_value(&db_key, value)?;
            table
                .insert(db_key.as_str(), encoded.as_slice())
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
        match table.get(db_key.as_str()).map_err(Self::redb_err)? {
            Some(v) => self.decode_seq_value(&db_key, v.value()),
            None => Ok(0),
        }
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
