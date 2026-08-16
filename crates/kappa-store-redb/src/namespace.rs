//! Namespace and sequence operations for PersistentStore.

use redb::{ReadableDatabase, ReadableTable};

use kappa_core::store::{AliasEvent, NamespaceRecord};
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

    // -- Namespace (UUID-based) ------------------------------------------------

    fn alias_key(name: &str, protocol: Option<&str>) -> String {
        match protocol {
            Some(p) => format!("{}:{}", p, name),
            None => name.to_string(),
        }
    }

    fn now_ms() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn parse_record(data: &[u8]) -> Result<NamespaceRecord, StoreError> {
        serde_json::from_slice::<NamespaceRecord>(data)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))
    }

    fn encode_record(record: &NamespaceRecord) -> Result<Vec<u8>, StoreError> {
        serde_json::to_vec(record)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))
    }

    // -- namespace_create -----------------------------------------------------

    pub(crate) fn namespace_create_impl(
        &self,
        name: &str,
        owner: &str,
        protocol: Option<&str>,
    ) -> Result<kappa_core::types::NamespaceRef, StoreError> {
        let key = Self::alias_key(name, protocol);
        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            // Collision detection: check alias does not exist
            let alias_table = txn.open_table(NAMESPACE_ALIASES).map_err(Self::redb_err)?;
            if alias_table.get(key.as_str()).map_err(Self::redb_err)?.is_some() {
                return Err(StoreError::Conflict(format!("namespace alias already exists: {}", key)));
            }
            // Cross-protocol collision detection
            if protocol.is_some() {
                let global_key = name.to_string();
                if alias_table.get(global_key.as_str()).map_err(Self::redb_err)?.is_some() {
                    return Err(StoreError::Conflict(format!(
                        "namespace alias collides with global alias: {}", name
                    )));
                }
            } else {
                for proto in &["oci", "s3", "git", "nix"] {
                    let scoped = format!("{}:{}", proto, name);
                    if alias_table.get(scoped.as_str()).map_err(Self::redb_err)?.is_some() {
                        return Err(StoreError::Conflict(format!(
                            "namespace alias collides with {}-scoped alias: {}", proto, name
                        )));
                    }
                }
            }
            drop(alias_table);

            let ns = kappa_core::types::NamespaceRef::generate(name);
            let uuid = *ns.uuid();
            let now = Self::now_ms();
            let record = NamespaceRecord {
                uuid_hex: ns.uuid_hex(),
                owner: owner.to_string(),
                created_at_ms: now,
                protocol: protocol.map(|s| s.to_string()),
                aliases: vec![name.to_string()],
                tombstoned: false,
            };
            let record_json = Self::encode_record(&record)?;

            let mut alias_table = txn.open_table(NAMESPACE_ALIASES).map_err(Self::redb_err)?;
            alias_table.insert(key.as_str(), uuid.as_slice()).map_err(Self::redb_err)?;
            drop(alias_table);

            let mut record_table = txn.open_table(NAMESPACE_RECORDS).map_err(Self::redb_err)?;
            record_table.insert(uuid.as_slice(), record_json.as_slice()).map_err(Self::redb_err)?;
            drop(record_table);

            // Alias history
            let event = AliasEvent {
                action: "create".into(),
                alias: name.to_string(),
                actor: owner.to_string(),
                timestamp_ms: now,
                detail: protocol.map(|s| s.to_string()),
            };
            let event_json = serde_json::to_vec(&event)
                .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
            let mut hist_key = Vec::with_capacity(24);
            hist_key.extend_from_slice(&uuid);
            hist_key.extend_from_slice(&now.to_be_bytes());
            let mut hist_table = txn.open_table(ALIAS_HISTORY).map_err(Self::redb_err)?;
            hist_table.insert(hist_key.as_slice(), event_json.as_slice()).map_err(Self::redb_err)?;
            drop(hist_table);

            txn.commit().map_err(Self::redb_err)?;
            return Ok(ns);
        }
    }

    // -- namespace_resolve ----------------------------------------------------

    pub(crate) fn namespace_resolve_impl(
        &self,
        name: &str,
        protocol: Option<&str>,
    ) -> Result<kappa_core::types::NamespaceRef, StoreError> {
        let key = Self::alias_key(name, protocol);
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(NAMESPACE_ALIASES).map_err(Self::redb_err)?;
        match table.get(key.as_str()).map_err(Self::redb_err)? {
            Some(val) => {
                let bytes = val.value();
                if bytes.len() != 16 {
                    return Err(StoreError::Io(std::io::Error::other("alias UUID not 16 bytes")));
                }
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(bytes);
                Ok(kappa_core::types::NamespaceRef::with_name(uuid, name.to_string()))
            }
            None => Err(StoreError::NotFound(format!("namespace alias: {}", key))),
        }
    }

    // -- namespace_rename -----------------------------------------------------

    pub(crate) fn namespace_rename_impl(
        &self,
        old_name: &str,
        new_name: &str,
        actor: &str,
        protocol: Option<&str>,
    ) -> Result<(), StoreError> {
        let old_key = Self::alias_key(old_name, protocol);
        let new_key = Self::alias_key(new_name, protocol);

        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            // Resolve old alias
            let alias_table = txn.open_table(NAMESPACE_ALIASES).map_err(Self::redb_err)?;
            let val = alias_table.get(old_key.as_str()).map_err(Self::redb_err)?
                .ok_or_else(|| StoreError::NotFound(format!("namespace alias: {}", old_key)))?;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(val.value());
            drop(val);
            // Check new doesn't exist
            if alias_table.get(new_key.as_str()).map_err(Self::redb_err)?.is_some() {
                return Err(StoreError::Conflict(format!("target alias already exists: {}", new_key)));
            }
            drop(alias_table);

            // Verify owner
            let record_table = txn.open_table(NAMESPACE_RECORDS).map_err(Self::redb_err)?;
            let rec_val = record_table.get(uuid.as_slice()).map_err(Self::redb_err)?
                .ok_or_else(|| StoreError::NotFound(format!("namespace record: {}", hex::encode(uuid))))?;
            let mut record = Self::parse_record(rec_val.value())?;
            drop(rec_val);
            drop(record_table);

            if record.owner != actor {
                return Err(StoreError::Rejected(format!(
                    "only owner {} can rename, actor is {}", record.owner, actor
                )));
            }

            // Perform rename
            let mut alias_table = txn.open_table(NAMESPACE_ALIASES).map_err(Self::redb_err)?;
            alias_table.remove(old_key.as_str()).map_err(Self::redb_err)?;
            alias_table.insert(new_key.as_str(), uuid.as_slice()).map_err(Self::redb_err)?;
            drop(alias_table);

            record.aliases.retain(|a| a != old_name);
            record.aliases.push(new_name.to_string());
            let record_json = Self::encode_record(&record)?;
            let mut record_table = txn.open_table(NAMESPACE_RECORDS).map_err(Self::redb_err)?;
            record_table.insert(uuid.as_slice(), record_json.as_slice()).map_err(Self::redb_err)?;
            drop(record_table);

            let now = Self::now_ms();
            let event = AliasEvent {
                action: "rename".into(),
                alias: new_name.to_string(),
                actor: actor.to_string(),
                timestamp_ms: now,
                detail: Some(old_name.to_string()),
            };
            let event_json = serde_json::to_vec(&event)
                .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
            let mut hist_key = Vec::with_capacity(24);
            hist_key.extend_from_slice(&uuid);
            hist_key.extend_from_slice(&now.to_be_bytes());
            let mut hist_table = txn.open_table(ALIAS_HISTORY).map_err(Self::redb_err)?;
            hist_table.insert(hist_key.as_slice(), event_json.as_slice()).map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }

    // -- namespace_add_alias --------------------------------------------------

    pub(crate) fn namespace_add_alias_impl(
        &self,
        uuid: &[u8; 16],
        alias: &str,
        actor: &str,
        protocol: Option<&str>,
    ) -> Result<(), StoreError> {
        let key = Self::alias_key(alias, protocol);

        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            // Verify owner
            let record_table = txn.open_table(NAMESPACE_RECORDS).map_err(Self::redb_err)?;
            let rec_val = record_table.get(uuid.as_slice()).map_err(Self::redb_err)?
                .ok_or_else(|| StoreError::NotFound(format!("namespace record: {}", hex::encode(uuid))))?;
            let mut record = Self::parse_record(rec_val.value())?;
            drop(rec_val);
            drop(record_table);

            if record.owner != actor {
                return Err(StoreError::Rejected(format!(
                    "only owner {} can add alias, actor is {}", record.owner, actor
                )));
            }

            // Check alias doesn't exist
            let alias_table = txn.open_table(NAMESPACE_ALIASES).map_err(Self::redb_err)?;
            if alias_table.get(key.as_str()).map_err(Self::redb_err)?.is_some() {
                return Err(StoreError::Conflict(format!("alias already exists: {}", key)));
            }
            drop(alias_table);

            // Insert alias
            let mut alias_table = txn.open_table(NAMESPACE_ALIASES).map_err(Self::redb_err)?;
            alias_table.insert(key.as_str(), uuid.as_slice()).map_err(Self::redb_err)?;
            drop(alias_table);

            if !record.aliases.contains(&alias.to_string()) {
                record.aliases.push(alias.to_string());
            }
            let record_json = Self::encode_record(&record)?;
            let mut record_table = txn.open_table(NAMESPACE_RECORDS).map_err(Self::redb_err)?;
            record_table.insert(uuid.as_slice(), record_json.as_slice()).map_err(Self::redb_err)?;
            drop(record_table);

            let now = Self::now_ms();
            let event = AliasEvent {
                action: "add_alias".into(),
                alias: alias.to_string(),
                actor: actor.to_string(),
                timestamp_ms: now,
                detail: protocol.map(|s| s.to_string()),
            };
            let event_json = serde_json::to_vec(&event)
                .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
            let mut hist_key = Vec::with_capacity(24);
            hist_key.extend_from_slice(uuid);
            hist_key.extend_from_slice(&now.to_be_bytes());
            let mut hist_table = txn.open_table(ALIAS_HISTORY).map_err(Self::redb_err)?;
            hist_table.insert(hist_key.as_slice(), event_json.as_slice()).map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }

    // -- namespace_transfer ---------------------------------------------------

    pub(crate) fn namespace_transfer_impl(
        &self,
        uuid: &[u8; 16],
        new_owner: &str,
        actor: &str,
    ) -> Result<(), StoreError> {
        // Verify actor is current owner or has succession chain to owner
        let old_owner = {
            let txn = self.db.begin_read().map_err(Self::redb_err)?;
            let record_table = txn.open_table(NAMESPACE_RECORDS).map_err(Self::redb_err)?;
            let rec_val = record_table.get(uuid.as_slice()).map_err(Self::redb_err)?
                .ok_or_else(|| StoreError::NotFound(format!("namespace record: {}", hex::encode(uuid))))?;
            let record = Self::parse_record(rec_val.value())?;
            if record.owner != actor {
                // Check succession chain
                use kappa_core::store::KappaStore;
                let resolved = self.identity_succession_resolve(&record.owner)?;
                if resolved != actor {
                    return Err(StoreError::Rejected(format!(
                        "only owner {} (or successor) can transfer, actor is {}", record.owner, actor
                    )));
                }
            }
            record.owner.clone()
        };

        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let record_table = txn.open_table(NAMESPACE_RECORDS).map_err(Self::redb_err)?;
            let rec_val = record_table.get(uuid.as_slice()).map_err(Self::redb_err)?
                .ok_or_else(|| StoreError::NotFound(format!("namespace record: {}", hex::encode(uuid))))?;
            let mut record = Self::parse_record(rec_val.value())?;
            drop(rec_val);
            drop(record_table);

            record.owner = new_owner.to_string();
            let record_json = Self::encode_record(&record)?;
            let mut record_table = txn.open_table(NAMESPACE_RECORDS).map_err(Self::redb_err)?;
            record_table.insert(uuid.as_slice(), record_json.as_slice()).map_err(Self::redb_err)?;
            drop(record_table);

            let now = Self::now_ms();
            let event = AliasEvent {
                action: "transfer".into(),
                alias: record.aliases.first().cloned().unwrap_or_default(),
                actor: actor.to_string(),
                timestamp_ms: now,
                detail: Some(format!("{} -> {}", old_owner, new_owner)),
            };
            let event_json = serde_json::to_vec(&event)
                .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
            let mut hist_key = Vec::with_capacity(24);
            hist_key.extend_from_slice(uuid);
            hist_key.extend_from_slice(&now.to_be_bytes());
            let mut hist_table = txn.open_table(ALIAS_HISTORY).map_err(Self::redb_err)?;
            hist_table.insert(hist_key.as_slice(), event_json.as_slice()).map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }

    // -- namespace_info -------------------------------------------------------

    pub(crate) fn namespace_info_impl(
        &self,
        name: &str,
        protocol: Option<&str>,
    ) -> Result<NamespaceRecord, StoreError> {
        let key = Self::alias_key(name, protocol);
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let alias_table = txn.open_table(NAMESPACE_ALIASES).map_err(Self::redb_err)?;
        let val = alias_table.get(key.as_str()).map_err(Self::redb_err)?
            .ok_or_else(|| StoreError::NotFound(format!("namespace alias: {}", key)))?;
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(val.value());
        drop(val);
        drop(alias_table);
        let record_table = txn.open_table(NAMESPACE_RECORDS).map_err(Self::redb_err)?;
        let rec_val = record_table.get(uuid.as_slice()).map_err(Self::redb_err)?
            .ok_or_else(|| StoreError::NotFound(format!("namespace record: {}", hex::encode(uuid))))?;
        Self::parse_record(rec_val.value())
    }

    // -- namespace_list -------------------------------------------------------

    pub(crate) fn namespace_list_impl_v2(
        &self,
        protocol: Option<&str>,
    ) -> Result<Vec<NamespaceRecord>, StoreError> {
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let mut records = Vec::new();
        let record_table = txn.open_table(NAMESPACE_RECORDS).map_err(Self::redb_err)?;
        for item in record_table.iter().map_err(Self::redb_err)? {
            let (_, v) = item.map_err(Self::redb_err)?;
            if let Ok(rec) = Self::parse_record(v.value()) {
                if rec.tombstoned { continue; }
                if let Some(p) = protocol {
                    if rec.protocol.as_deref() != Some(p) { continue; }
                }
                records.push(rec);
            }
        }
        records.sort_by(|a, b| a.aliases.first().cmp(&b.aliases.first()));
        Ok(records)
    }

    // -- namespace_exists -----------------------------------------------------

    pub(crate) fn namespace_exists_impl_v2(
        &self,
        name: &str,
        protocol: Option<&str>,
    ) -> Result<bool, StoreError> {
        let key = Self::alias_key(name, protocol);
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(NAMESPACE_ALIASES).map_err(Self::redb_err)?;
        Ok(table.get(key.as_str()).map_err(Self::redb_err)?.is_some())
    }

    // -- namespace_delete -----------------------------------------------------

    pub(crate) fn namespace_delete_impl(
        &self,
        name: &str,
        actor: &str,
        protocol: Option<&str>,
    ) -> Result<(), StoreError> {
        let key = Self::alias_key(name, protocol);

        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            // Resolve UUID
            let alias_table = txn.open_table(NAMESPACE_ALIASES).map_err(Self::redb_err)?;
            let val = alias_table.get(key.as_str()).map_err(Self::redb_err)?
                .ok_or_else(|| StoreError::NotFound(format!("namespace alias: {}", key)))?;
            let mut uuid = [0u8; 16];
            uuid.copy_from_slice(val.value());
            drop(val);
            drop(alias_table);

            // Verify owner
            let record_table = txn.open_table(NAMESPACE_RECORDS).map_err(Self::redb_err)?;
            let rec_val = record_table.get(uuid.as_slice()).map_err(Self::redb_err)?
                .ok_or_else(|| StoreError::NotFound(format!("namespace record: {}", hex::encode(uuid))))?;
            let mut record = Self::parse_record(rec_val.value())?;
            drop(rec_val);
            drop(record_table);

            if record.owner != actor {
                return Err(StoreError::Rejected(format!(
                    "only owner {} can delete, actor is {}", record.owner, actor
                )));
            }

            // Remove all aliases
            let mut alias_table = txn.open_table(NAMESPACE_ALIASES).map_err(Self::redb_err)?;
            for alias_name in &record.aliases {
                let global_key = alias_name.to_string();
                alias_table.remove(global_key.as_str()).map_err(Self::redb_err)?;
                if let Some(ref proto) = record.protocol {
                    let scoped_key = format!("{}:{}", proto, alias_name);
                    alias_table.remove(scoped_key.as_str()).map_err(Self::redb_err)?;
                }
            }
            drop(alias_table);

            // Tombstone the record
            record.tombstoned = true;
            let record_json = Self::encode_record(&record)?;
            let mut record_table = txn.open_table(NAMESPACE_RECORDS).map_err(Self::redb_err)?;
            record_table.insert(uuid.as_slice(), record_json.as_slice()).map_err(Self::redb_err)?;
            drop(record_table);

            let now = Self::now_ms();
            let event = AliasEvent {
                action: "delete".into(),
                alias: name.to_string(),
                actor: actor.to_string(),
                timestamp_ms: now,
                detail: None,
            };
            let event_json = serde_json::to_vec(&event)
                .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
            let mut hist_key = Vec::with_capacity(24);
            hist_key.extend_from_slice(&uuid);
            hist_key.extend_from_slice(&now.to_be_bytes());
            let mut hist_table = txn.open_table(ALIAS_HISTORY).map_err(Self::redb_err)?;
            hist_table.insert(hist_key.as_slice(), event_json.as_slice()).map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }
}
