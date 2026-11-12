use redb::ReadableTable;

use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::error::StoreError;
use kappa_store::namespace::{NamespaceRef, ProtocolId};
use kappa_store::page::{NamespaceFilter, Page, PageRequest};
use kappa_store::traits::namespace::{NamespaceInfo, NamespaceStore};
use kappa_store::work::Meter;

use crate::PersistentStore;
use crate::projection::{Family, ProjectionRead};
use crate::tables::{
    ALIAS_HISTORY, NAMESPACE_ALIASES, NAMESPACE_CONFIG, NAMESPACE_NAMES, NAMESPACE_RECORDS,
};

pub(super) fn alias_key(name: &str, protocol: Option<&ProtocolId>) -> String {
    kappa_store::namespace::namespace_alias_key(name, protocol)
}

pub(super) fn names_key(name: &str, protocol: Option<&ProtocolId>) -> String {
    protocol.map_or_else(
        || format!("{name}\0_"),
        |protocol| format!("{name}\0{}", protocol.as_str()),
    )
}

/// The [`names_key`] of the entry an [`alias_key`] names: an alias key is
/// `{protocol}\0{name}`, the empty protocol being the global scope that a
/// names key writes as `_`.
pub(super) fn names_key_of(alias_key: &str) -> Result<String, StoreError> {
    let (protocol, name) = alias_key
        .split_once('\0')
        .ok_or_else(|| StoreError::Internal(format!("alias key {alias_key:?} names no scope")))?;
    let scope = if protocol.is_empty() { "_" } else { protocol };
    Ok(format!("{name}\0{scope}"))
}

/// Binary config key: `[ns_uuid:16][key_bytes]`.
pub(super) fn config_key(ns: &NamespaceRef, key: &str) -> Vec<u8> {
    let key_bytes = key.as_bytes();
    let mut k = Vec::with_capacity(16 + key_bytes.len());
    k.extend_from_slice(ns.id());
    k.extend_from_slice(key_bytes);
    k
}

/// The AEAD context of the `NAMESPACE_CONFIG` row at `key`.
pub(crate) fn config_context(key: &[u8]) -> String {
    crate::encrypted::bound("ns_config", key)
}

fn config_prefix(ns: &NamespaceRef, prefix: &str) -> Vec<u8> {
    let prefix_bytes = prefix.as_bytes();
    let mut k = Vec::with_capacity(16 + prefix_bytes.len());
    k.extend_from_slice(ns.id());
    k.extend_from_slice(prefix_bytes);
    k
}

pub(super) fn parse_record(data: &[u8]) -> Result<NamespaceInfo, StoreError> {
    from_canonical(data).map_err(|e| StoreError::Internal(format!("namespace record decode: {e}")))
}

/// The completed directory record of namespace `uuid`, read on `work`: of
/// its instances, the one completed last holds the namespace's current
/// record.
fn completed_record(
    read: &ProjectionRead,
    uuid: &[u8; 16],
    work: &mut dyn Meter,
) -> Result<Option<NamespaceInfo>, StoreError> {
    read.get(Family::NamespaceRecord, uuid, work)?
        .into_iter()
        .max_by_key(|visible| visible.completion)
        .map(|visible| parse_record(&visible.value))
        .transpose()
}

impl PersistentStore {
    /// The record of `ns` as settlement last projected it, read on `work`:
    /// the evidence of a namespace whose storage is gone (a lost instance's
    /// release). Lags every commit; a namespace with storage is read by
    /// `namespace_info`. A refusal is never absence.
    pub(crate) fn settled_namespace_info(
        &self,
        ns: &NamespaceRef,
        work: &mut dyn Meter,
    ) -> Result<NamespaceInfo, StoreError> {
        completed_record(&self.projection()?, ns.id(), work)?
            .ok_or_else(|| StoreError::NotFound(format!("namespace: {ns}")))
    }

    /// The committed record of namespace `uuid` in its own database;
    /// `None` when no storage of it exists or no creation of it committed
    /// (a directory claim whose creation was abandoned).
    fn committed_record(&self, uuid: &[u8; 16]) -> Result<Option<NamespaceInfo>, StoreError> {
        let ns = crate::storage::NamespaceStorage::namespace_ref(*uuid);
        match NamespaceStore::namespace_info(self, &ns) {
            Ok(record) => Ok(Some(record)),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[derive(Clone, dcbor::prelude::CBORCodable)]
pub(super) enum HistoryDetail {
    #[cbor(n = 0)]
    None,
    #[cbor(n = 1)]
    Create {
        #[cbor(n = 0)]
        protocol: Option<String>,
    },
    #[cbor(n = 2)]
    Rename {
        #[cbor(n = 0)]
        old_name: String,
    },
    #[cbor(n = 3)]
    Transfer {
        #[cbor(n = 0)]
        old_owner: String,
        #[cbor(n = 1)]
        new_owner: String,
    },
    #[cbor(n = 4)]
    AddAlias {
        #[cbor(n = 0)]
        protocol: Option<String>,
    },
}

#[derive(Clone, dcbor::prelude::CBORCodable)]
struct HistoryEvent {
    #[cbor(n = 0)]
    alias: String,
    #[cbor(n = 1)]
    actor: String,
    #[cbor(n = 2)]
    timestamp_ms: i64,
    #[cbor(n = 3)]
    detail: HistoryDetail,
}

pub(super) fn append_history(
    txn: &redb::WriteTransaction,
    uuid: &[u8; 16],
    alias: &str,
    actor: &str,
    timestamp_ms: i64,
    detail: HistoryDetail,
) -> Result<(), StoreError> {
    let event = HistoryEvent {
        alias: alias.to_string(),
        actor: actor.to_string(),
        timestamp_ms,
        detail,
    };
    let event_bytes = canonical_bytes(&event);
    let mut hist_key = Vec::with_capacity(24);
    hist_key.extend_from_slice(uuid);
    hist_key.extend_from_slice(&timestamp_ms.to_be_bytes());
    let mut hist_table = txn.open_table(ALIAS_HISTORY).map_err(crate::error::redb)?;
    hist_table
        .insert(hist_key.as_slice(), event_bytes.as_slice())
        .map_err(crate::error::redb)?;
    Ok(())
}

/// Check if creating a global alias (protocol=None) collides with any
/// protocol-scoped namespace for the same name.
/// Uses `NAMESPACE_NAMES` prefix scan: all entries for `name` start with
/// `{name}\0`. If any exist, global creation is a collision.
fn global_collides_with_scoped(
    names_table: &impl ReadableTable<&'static str, &'static [u8]>,
    name: &str,
) -> Result<bool, StoreError> {
    let prefix = format!("{name}\0");
    let end = PersistentStore::prefix_successor(prefix.as_bytes())
        .map(String::from_utf8)
        .transpose()
        .map_err(|error| StoreError::Internal(format!("namespace prefix: {error}")))?;
    let iter = match &end {
        Some(e) => names_table
            .range::<&str>(prefix.as_str()..e.as_str())
            .map_err(crate::error::redb)?,
        None => names_table
            .range::<&str>(prefix.as_str()..)
            .map_err(crate::error::redb)?,
    };
    iter.into_iter()
        .next()
        .transpose()
        .map(|entry| entry.is_some())
        .map_err(crate::error::redb)
}

pub(super) fn ensure_alias_available(
    aliases: &impl ReadableTable<&'static str, &'static [u8]>,
    names: &impl ReadableTable<&'static str, &'static [u8]>,
    name: &str,
    protocol: Option<&ProtocolId>,
) -> Result<(), StoreError> {
    let key = alias_key(name, protocol);
    let exact_exists = aliases
        .get(key.as_str())
        .map_err(crate::error::redb)?
        .is_some();
    let global_exists = aliases
        .get(alias_key(name, None).as_str())
        .map_err(crate::error::redb)?
        .is_some();
    let scoped_exists = protocol.is_none() && global_collides_with_scoped(names, name)?;
    kappa_store::traits::namespace::validate_alias_admission(
        name,
        protocol,
        exact_exists,
        global_exists,
        scoped_exists,
    )
}

// Namespace lifecycle (create, rename, transfer, alias, delete) and metadata
// writes are `EpochExecution` methods over the `*_in_txn` transitions in
// `namespace_write.rs`; each records its ledger evidence in the execution's
// writer and publishes with its epoch.
impl PersistentStore {
    /// The namespace a committed alias `path` within `protocol` names. An
    /// alias reserved by an execution not yet resolved names none: a
    /// directory change is visible exactly when its epoch is
    /// (`namespace_directory_journal`).
    fn committed_alias(
        &self,
        path: &str,
        protocol: Option<&ProtocolId>,
    ) -> Result<Option<[u8; 16]>, StoreError> {
        let key = alias_key(path, protocol);
        let txn = self.registry.begin_read()?;
        let table = txn
            .open_table(NAMESPACE_ALIASES)
            .map_err(crate::error::redb)?;
        let Some(value) = table.get(key.as_str()).map_err(crate::error::redb)? else {
            return Ok(None);
        };
        let (uuid, committed) = crate::namespace_write::entry_owner(value.value())?;
        Ok(committed.then_some(uuid))
    }
}

impl NamespaceStore for PersistentStore {
    fn namespace_resolve(
        &self,
        path: &str,
        protocol: Option<&ProtocolId>,
    ) -> Result<NamespaceRef, StoreError> {
        let uuid = self
            .committed_alias(path, protocol)?
            .ok_or_else(|| StoreError::NotFound(format!("namespace: {path}")))?;
        Ok(NamespaceRef::resolved(
            uuid,
            path.to_string(),
            protocol.cloned(),
        ))
    }

    fn namespace_exists(
        &self,
        path: &str,
        protocol: Option<&ProtocolId>,
    ) -> Result<bool, StoreError> {
        Ok(self.committed_alias(path, protocol)?.is_some())
    }

    /// The namespace's own committed record, read from its database: a
    /// publication is visible here as soon as it returns. The settled copy
    /// in the registry lags and is read only where no storage remains
    /// (`settled_namespace_info`).
    fn namespace_info(&self, ns: &NamespaceRef) -> Result<NamespaceInfo, StoreError> {
        let snapshot = self.namespace_snapshot(ns)?;
        let table = snapshot.table(NAMESPACE_RECORDS)?;
        crate::namespace_write::namespace_record_in(&table, ns)
    }

    fn namespace_list(
        &self,
        filter: &NamespaceFilter,
        page: &PageRequest,
    ) -> Result<Page<NamespaceInfo>, StoreError> {
        // Names come from the registry's directory; each record from its
        // namespace's own committed state, so a creation is listed as soon
        // as it is published.
        let read = self.registry.begin_read()?;
        let names_table = read
            .open_table(NAMESPACE_NAMES)
            .map_err(crate::error::redb)?;

        // Build range start from cursor.
        let start_key = page
            .after
            .as_ref()
            .map_or_else(String::new, |cursor| format!("{cursor}\x01"));

        let iter = names_table
            .range::<&str>(start_key.as_str()..)
            .map_err(crate::error::redb)?;

        let mut items = Vec::with_capacity(page.limit.min(1000));
        let mut seen = std::collections::HashSet::new();

        for item in iter {
            if items.len() > page.limit {
                break;
            }
            let (k, v) = item.map_err(crate::error::redb)?;
            let key_str = k.value();

            // Protocol filter via NAMESPACE_NAMES key suffix.
            if let Some(ref p) = filter.protocol {
                let expected_suffix = format!("\0{}", p.as_str());
                if !key_str.ends_with(&expected_suffix) {
                    continue;
                }
            }

            // A name reserved by an execution not yet resolved is not
            // listed: it is visible when its epoch is.
            let (uuid, committed) = crate::namespace_write::entry_owner(v.value())?;
            if !committed {
                continue;
            }

            if !seen.insert(uuid) {
                continue;
            }

            let Some(rec) = self.committed_record(&uuid)? else {
                continue;
            };

            // Apply all NamespaceFilter fields.
            if let Some(ref t) = filter.tombstoned {
                if rec.tombstoned != *t {
                    continue;
                }
            } else if rec.tombstoned {
                continue;
            }
            if let Some(ref owner) = filter.owner_anchor
                && rec.owner_anchor.as_ref() != Some(owner)
            {
                continue;
            }
            if let Some(after_ms) = filter.created_after_ms
                && rec.created_at_ms <= after_ms
            {
                continue;
            }
            if let Some(after_epoch) = filter.last_epoch_after
                && rec.last_epoch <= after_epoch
            {
                continue;
            }

            items.push(rec);
        }

        let next_after = if items.len() > page.limit {
            items.pop();
            items.last().map(|r| r.name.clone())
        } else {
            None
        };

        Ok(Page { items, next_after })
    }

    fn namespace_get_meta(&self, ns: &NamespaceRef, key: &str) -> Result<Vec<u8>, StoreError> {
        let ck = config_key(ns, key);
        let snapshot = self.namespace_snapshot(ns)?;
        let table = snapshot.table(NAMESPACE_CONFIG)?;
        let raw = table
            .get(ck.as_slice())
            .map_err(crate::error::redb)?
            .ok_or_else(|| StoreError::NotFound(format!("namespace config {ns}:{key}")))?;
        self.decrypt_bytes(&config_context(&ck), raw.value())
    }

    fn namespace_list_meta_keys(
        &self,
        ns: &NamespaceRef,
        prefix: &str,
        page: &PageRequest,
    ) -> Result<Page<String>, StoreError> {
        let scan_start = config_prefix(ns, prefix);
        let ns_prefix = ns.id().to_vec();
        let snapshot = self.namespace_snapshot(ns)?;
        let table = snapshot.table(NAMESPACE_CONFIG)?;

        let scan_end = if prefix.is_empty() {
            Self::prefix_successor(&ns_prefix)
        } else {
            Self::prefix_successor(&scan_start)
        };

        let iter = match &scan_end {
            Some(end) => table
                .range(scan_start.as_slice()..end.as_slice())
                .map_err(crate::error::redb)?,
            None => table
                .range(scan_start.as_slice()..)
                .map_err(crate::error::redb)?,
        };

        let mut items = Vec::with_capacity(page.limit.min(1000));

        for item in iter {
            if items.len() > page.limit {
                break;
            }
            let (k, _) = item.map_err(crate::error::redb)?;
            let raw = k.value();
            if raw.len() < 16 || &raw[..16] != ns.id() {
                break;
            }
            let key_str = std::str::from_utf8(&raw[16..])
                .map_err(|e| StoreError::Internal(format!("meta key not utf8: {e}")))?;

            if let Some(ref cursor) = page.after
                && key_str <= cursor.as_str()
            {
                continue;
            }

            items.push(key_str.to_string());
        }

        let next_after = if items.len() > page.limit {
            items.pop();
            items.last().cloned()
        } else {
            None
        };

        Ok(Page { items, next_after })
    }
}
