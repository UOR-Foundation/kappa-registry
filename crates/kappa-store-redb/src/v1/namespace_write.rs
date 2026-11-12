//! Namespace records and ownership changes inside an epoch-owned writer,
//! and the directory claims they make in the registry.
//!
//! The namespace's own record (`NAMESPACE_RECORDS` in its database) and its
//! metadata (`NAMESPACE_CONFIG`) are epoch state: each change is applied
//! through the transition boundary (`transition_apply`) as `NamespaceUpdate`
//! or typed `MetadataTransition` evidence, from which settlement projects
//! the registry's copy. The directory itself (alias and name to identity,
//! `NAMESPACES`) is registry state that must be unique across every
//! namespace, so an execution reserves what it adds in one short registry
//! transaction before it writes the namespace side
//! (`namespace_directory`): concurrent creators of one alias serialize on
//! that reservation, and no publication waits on the registry beyond it.
//! What an execution reserved or releases is resolved against what it
//! committed once its outcome is known (`namespace_directory_journal`); a
//! creation that never commits is also found by settlement through the
//! pending entry its claim made, and its claim released.

use kappa_store::transition::RecordTransition;
use kappa_store::work::Meter;
use kappa_store::{
    ClockMs, Kappa, NamespaceInfo, NamespaceRef, StoreError, canonical::canonical_bytes,
    namespace::ProtocolId,
};
use redb::ReadableTable;

use super::namespace::{HistoryDetail, append_history, config_key};
use crate::transition_apply::{RedbPayload, TxnWriter};
use crate::{
    PersistentStore,
    tables::{NAMESPACE_CONFIG, NAMESPACE_RECORDS},
};

#[path = "namespace_directory.rs"]
mod directory;

#[path = "namespace_directory_journal.rs"]
mod journal;
pub use journal::{DirectoryGuard, entry_owner};
pub(crate) use journal::{RESOLUTION_UNIT, Reconciled, record_unit};

impl PersistentStore {
    /// Apply `record` as the namespace's record through the transition
    /// boundary, which writes its row ([`TxnWriter::apply_namespace_record`])
    /// and records its `NamespaceUpdate` evidence, on `meter`, the allowance
    /// of the operation writing it.
    pub(crate) fn record_namespace_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        record: &NamespaceInfo,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        TxnWriter::new(self, txn, ns, now, meter)?
            .apply(
                RecordTransition::NamespaceUpdate(record.clone()),
                RedbPayload::NoResources,
            )
            .map(drop)
    }

    /// Create `ns` under its display name within `protocol`: claim the
    /// alias in the registry, then write the namespace's record and
    /// evidence in its own transaction.
    pub(crate) fn namespace_create_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        owner: Option<&Kappa>,
        protocol: Option<&ProtocolId>,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let uuid = *ns.id();
        if txn
            .open_table(NAMESPACE_RECORDS)
            .map_err(crate::error::redb)?
            .get(uuid.as_slice())
            .map_err(crate::error::redb)?
            .is_some()
        {
            return Err(StoreError::AlreadyExists(format!("namespace: {ns}")));
        }
        let record = NamespaceInfo::created(ns, owner, protocol, now.as_i64());
        // The first claim also takes the identity's existence row.
        for (index, alias) in record.aliases.iter().enumerate() {
            self.claim_alias(&uuid, &alias.name, alias.protocol.as_ref(), index == 0)?;
        }
        self.record_namespace_in_txn(txn, ns, &record, now, meter)
    }

    /// Delete `ns`: its record is tombstoned in its own transaction, and
    /// the release of its aliases is journaled, to be applied once the
    /// tombstone is committed. A deletion that never commits keeps every
    /// alias; the existence row stays either way, so the identity is never
    /// recreated.
    pub(crate) fn namespace_delete_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let mut record = Self::namespace_info_in_txn(txn, ns)?;
        // Every released alias is resolved by the deletion's outcome: each
        // is journaled by its key (`journal_released`).
        let released = record.tombstone()?;
        self.journal_released(ns, &released)?;
        self.record_namespace_in_txn(txn, ns, &record, now, meter)
    }

    pub(crate) fn namespace_info_in_txn(
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
    ) -> Result<NamespaceInfo, StoreError> {
        let table = txn
            .open_table(NAMESPACE_RECORDS)
            .map_err(crate::error::redb)?;
        namespace_record_in(&table, ns)
    }

    pub(crate) fn namespace_transfer_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        new_owner: &Kappa,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let mut record = Self::namespace_info_in_txn(txn, ns)?;
        record.transfer(new_owner)?;
        self.record_namespace_in_txn(txn, ns, &record, now, meter)
    }

    pub(crate) fn namespace_get_meta_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        key: &str,
    ) -> Result<Vec<u8>, StoreError> {
        let table = txn
            .open_table(NAMESPACE_CONFIG)
            .map_err(crate::error::redb)?;
        let ck = config_key(ns, key);
        let raw = table
            .get(ck.as_slice())
            .map_err(crate::error::redb)?
            .ok_or_else(|| StoreError::NotFound(format!("namespace config {ns}:{key}")))?;
        self.decrypt_bytes(&super::namespace::config_context(&ck), raw.value())
    }

    /// Apply the namespace metadata `key` set to `value`, or deleted, as its
    /// typed transition.
    fn apply_meta_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        key: &str,
        value: Option<&[u8]>,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let writer = TxnWriter::new(self, txn, ns, now, meter)?;
        let meta = kappa_types::content::MetadataTransition::namespace_meta(
            *ns.id(),
            *writer.incarnation(),
            key.to_owned(),
            value.map(<[u8]>::to_vec),
        );
        writer
            .apply(RecordTransition::Metadata(meta), RedbPayload::NoResources)
            .map(drop)
    }

    pub(crate) fn namespace_put_meta_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        key: &str,
        value: &[u8],
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        if key.is_empty() {
            return Err(StoreError::Rejected(
                "namespace metadata key must be nonempty".into(),
            ));
        }
        pinned_content(key)?;
        self.apply_meta_in_txn(txn, ns, key, Some(value), now, meter)
    }

    /// Deleting an absent key is a no-op and records no mutation.
    pub(crate) fn namespace_delete_meta_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        key: &str,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let held = txn
            .open_table(NAMESPACE_CONFIG)
            .map_err(crate::error::redb)?
            .get(config_key(ns, key).as_slice())
            .map_err(crate::error::redb)?
            .is_some();
        if !held {
            return Ok(());
        }
        self.apply_meta_in_txn(txn, ns, key, None, now, meter)
    }
}

/// The alias history events a record change makes, derived from the record
/// held before it (`None`: the creation) and the one after: a creation, a
/// deletion, an ownership transfer, a rename (the alias that left, under
/// the record's new name), and each alias added otherwise. Each is
/// `(alias, actor, detail)`.
fn history_events(
    held: Option<&NamespaceInfo>,
    info: &NamespaceInfo,
) -> Vec<(String, String, HistoryDetail)> {
    let protocol_of = |alias: &kappa_store::traits::namespace::NamespaceAlias| {
        alias.protocol.as_ref().map(|p| p.as_str().to_string())
    };
    let Some(held) = held else {
        return vec![(
            info.name.clone(),
            info.owner_anchor
                .as_ref()
                .map(ToString::to_string)
                .unwrap_or_default(),
            HistoryDetail::Create {
                protocol: info.protocol.as_ref().map(|p| p.as_str().to_string()),
            },
        )];
    };
    if info.tombstoned && !held.tombstoned {
        return vec![(held.name.clone(), String::new(), HistoryDetail::None)];
    }
    let mut events = Vec::new();
    if info.owner_anchor != held.owner_anchor {
        events.push((
            info.name.clone(),
            String::new(),
            HistoryDetail::Transfer {
                old_owner: held
                    .owner_anchor
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
                new_owner: info
                    .owner_anchor
                    .as_ref()
                    .map(ToString::to_string)
                    .unwrap_or_default(),
            },
        ));
    }
    let renamed = info.name != held.name;
    if renamed {
        let old_name = held
            .aliases
            .iter()
            .find(|alias| !info.aliases.contains(alias))
            .map_or_else(|| held.name.clone(), |old| old.name.clone());
        events.push((
            info.name.clone(),
            String::new(),
            HistoryDetail::Rename { old_name },
        ));
    }
    for added in info
        .aliases
        .iter()
        .filter(|alias| !held.aliases.contains(alias) && !(renamed && alias.name == info.name))
    {
        events.push((
            added.name.clone(),
            String::new(),
            HistoryDetail::AddAlias {
                protocol: protocol_of(added),
            },
        ));
    }
    events
}

impl TxnWriter<'_> {
    /// Hold `info` as the namespace's record and append the alias history
    /// events the change makes (`history_events`), at this writer's time.
    pub(crate) fn apply_namespace_record(&self, info: &NamespaceInfo) -> Result<(), StoreError> {
        if info.ns.id() != self.ns.id() {
            return Err(StoreError::Internal(
                "namespace record names another namespace".into(),
            ));
        }
        let held = kappa_store::absent(PersistentStore::namespace_info_in_txn(self.txn, self.ns))?;
        self.txn
            .open_table(NAMESPACE_RECORDS)
            .map_err(crate::error::redb)?
            .insert(self.ns.id().as_slice(), canonical_bytes(info).as_slice())
            .map_err(crate::error::redb)?;
        for (alias, actor, detail) in history_events(held.as_ref(), info) {
            append_history(
                self.txn,
                self.ns.id(),
                &alias,
                &actor,
                self.now.as_i64(),
                detail,
            )?;
        }
        Ok(())
    }

    /// Hold `value` under the namespace metadata `key`, or remove the key.
    /// A pin key establishes its content reference when first set and
    /// releases it when removed; a renewal replaces the value and keeps
    /// the reference.
    pub(crate) fn apply_namespace_meta(
        &self,
        key: &str,
        value: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        let (store, txn, ns) = (self.store, self.txn, self.ns);
        let ck = config_key(ns, key);
        let mut table = txn
            .open_table(NAMESPACE_CONFIG)
            .map_err(crate::error::redb)?;
        let pinned = pinned_content(key)?;
        match value {
            Some(value) => {
                let stored = store.encrypt_bytes(&super::namespace::config_context(&ck), value)?;
                let replaced = table
                    .insert(ck.as_slice(), stored.as_slice())
                    .map_err(crate::error::redb)?
                    .is_some();
                drop(table);
                if let Some(pinned) = pinned
                    && !replaced
                {
                    crate::referrers::establish(
                        store,
                        txn,
                        ns,
                        &pinned,
                        &crate::referrers::Referrer::pin(ns),
                    )?;
                }
            }
            None => {
                let removed = table
                    .remove(ck.as_slice())
                    .map_err(crate::error::redb)?
                    .is_some();
                drop(table);
                if !removed {
                    return Err(StoreError::Internal(format!(
                        "metadata deletion names {key}, which the namespace does not hold"
                    )));
                }
                if let Some(pinned) = pinned {
                    crate::referrers::release(
                        store,
                        txn,
                        ns,
                        &pinned,
                        &crate::referrers::Referrer::pin(ns),
                    )?;
                }
            }
        }
        Ok(())
    }
}

/// The committed record of `ns` in its own `NAMESPACE_RECORDS` table, the
/// one decode of it: a write transaction's view or a snapshot's.
pub fn namespace_record_in(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    ns: &NamespaceRef,
) -> Result<NamespaceInfo, StoreError> {
    let record = table
        .get(ns.id().as_slice())
        .map_err(crate::error::redb)?
        .ok_or_else(|| StoreError::NotFound(format!("namespace: {ns}")))?;
    namespace_record_of(record.value(), ns.id())
}

/// The record `bytes` holds, which must be the record of namespace `id`:
/// the one decode of a stored namespace record, for a row already read.
pub fn namespace_record_of(bytes: &[u8], id: &[u8; 16]) -> Result<NamespaceInfo, StoreError> {
    let info = super::namespace::parse_record(bytes)?;
    if info.ns.id() != id {
        return Err(StoreError::Rejected(
            "namespace record identity mismatch".into(),
        ));
    }
    Ok(info)
}

/// The content a `_pin/{kappa}` metadata key pins. A key under the pin
/// prefix that does not name content is rejected rather than stored as an
/// unindexed pin. Shared with the referrer rebuild, which derives pins
/// from replayed metadata evidence.
pub fn pinned_content(key: &str) -> Result<Option<Kappa>, StoreError> {
    let Some(label) = key.strip_prefix("_pin/") else {
        return Ok(None);
    };
    Kappa::parse(label)
        .map(Some)
        .map_err(|error| StoreError::Rejected(format!("pin key names no content: {error}")))
}
