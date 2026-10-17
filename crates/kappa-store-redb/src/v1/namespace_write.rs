//! Namespace records and ownership changes inside an epoch-owned writer,
//! and the directory claims they make in the registry.
//!
//! The namespace's own record (`NAMESPACE_RECORDS` in its database) is
//! epoch state: written in the execution's transaction and recorded as
//! `NamespaceUpdate` evidence, from which settlement projects the
//! registry's copy. The directory itself (alias and name to identity,
//! `NAMESPACES`) is registry state that must be unique across every
//! namespace, so an execution reserves what it adds in one short registry
//! transaction before it writes the namespace side
//! (`namespace_directory`): concurrent creators of one alias serialize on
//! that reservation, and no publication waits on the registry beyond it.
//! What an execution reserved or releases is resolved against what it
//! committed once its outcome is known (`namespace_directory_journal`); a
//! creation that never commits is also found by settlement through the
//! pending entry its claim made, and its claim released.

use kappa_store::{
    ClockMs, Kappa, MutationOp, NamespaceInfo, NamespaceRef, StoreError,
    canonical::canonical_bytes, namespace::ProtocolId,
};
use redb::ReadableTable;

use super::namespace::{HistoryDetail, append_history, config_key};
use crate::{
    PersistentStore,
    tables::{NAMESPACE_CONFIG, NAMESPACE_RECORDS},
};

#[path = "namespace_directory.rs"]
mod directory;

#[path = "namespace_directory_journal.rs"]
mod journal;
pub use journal::{DirectoryGuard, entry_owner};

impl PersistentStore {
    pub(crate) fn record_namespace_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let record = Self::namespace_info_in_txn(txn, ns)?;
        let content = kappa_store::VerifiedContent::compute(
            kappa_store::Axis::Sha256,
            &canonical_bytes(&record),
        )?;
        crate::epoch_blob::blob_put_in_txn(self, txn, ns, &content)?;
        self.record_mutation_in_txn(
            txn,
            ns,
            MutationOp::NamespaceUpdate,
            content.kappa().clone(),
            now,
            None,
        )
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
    ) -> Result<(), StoreError> {
        let uuid = *ns.id();
        let name = ns.display_name();
        if txn
            .open_table(NAMESPACE_RECORDS)
            .map_err(crate::error::redb)?
            .get(uuid.as_slice())
            .map_err(crate::error::redb)?
            .is_some()
        {
            return Err(StoreError::AlreadyExists(format!("namespace: {ns}")));
        }
        self.claim_alias(&uuid, name, protocol, true)?;
        Self::write_namespace_record(
            txn,
            &uuid,
            &NamespaceInfo {
                ns: ns.clone(),
                name: name.to_string(),
                owner_anchor: owner.cloned(),
                created_at_ms: now.as_i64(),
                aliases: vec![name.to_string()],
                protocol: protocol.cloned(),
                tombstoned: false,
                last_epoch: 0,
            },
        )?;
        append_history(
            txn,
            &uuid,
            name,
            &owner.map(ToString::to_string).unwrap_or_default(),
            now.as_i64(),
            HistoryDetail::Create {
                protocol: protocol.map(|p| p.as_str().to_string()),
            },
        )?;
        self.record_namespace_in_txn(txn, ns, now)
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
    ) -> Result<(), StoreError> {
        let mut record = Self::namespace_info_in_txn(txn, ns)?;
        if record.tombstoned {
            return Err(StoreError::Rejected("namespace is already deleted".into()));
        }
        self.journal_deletion(ns)?;
        record.tombstoned = true;
        Self::write_namespace_record(txn, ns.id(), &record)?;
        append_history(
            txn,
            ns.id(),
            ns.as_str(),
            "",
            now.as_i64(),
            HistoryDetail::None,
        )?;
        self.record_namespace_in_txn(txn, ns, now)
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
    ) -> Result<(), StoreError> {
        let mut record = Self::namespace_info_in_txn(txn, ns)?;
        if record.tombstoned {
            return Err(StoreError::Rejected(
                "cannot transfer a deleted namespace".into(),
            ));
        }
        let old_owner = record
            .owner_anchor
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_default();
        record.owner_anchor = Some(new_owner.clone());
        Self::write_namespace_record(txn, ns.id(), &record)?;
        append_history(
            txn,
            ns.id(),
            ns.as_str(),
            "",
            now.as_i64(),
            HistoryDetail::Transfer {
                old_owner,
                new_owner: new_owner.to_string(),
            },
        )?;
        self.record_namespace_in_txn(txn, ns, now)
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

    /// Publish the canonical metadata record and commit it to the ledger.
    fn record_metadata_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        key: &str,
        value: Option<&[u8]>,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let record = kappa_store::epoch::MetadataRecord {
            namespace_id: ns.id().to_vec(),
            key: key.to_string(),
            value: value.map(<[u8]>::to_vec),
        };
        let content = kappa_store::VerifiedContent::compute(
            kappa_store::Axis::Sha256,
            &canonical_bytes(&record),
        )?;
        crate::epoch_blob::blob_put_in_txn(self, txn, ns, &content)?;
        self.record_mutation_in_txn(
            txn,
            ns,
            MutationOp::MetadataUpdate,
            content.kappa().clone(),
            now,
            Some(key.to_string()),
        )
    }

    pub(crate) fn namespace_put_meta_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        key: &str,
        value: &[u8],
        now: ClockMs,
    ) -> Result<(), StoreError> {
        if key.is_empty() {
            return Err(StoreError::Rejected(
                "namespace metadata key must be nonempty".into(),
            ));
        }
        let ck = config_key(ns, key);
        let stored = self.encrypt_bytes(&super::namespace::config_context(&ck), value)?;
        // A pin renewal replaces the value of an existing key; the pin
        // reference it established is unchanged.
        let replaced = txn
            .open_table(NAMESPACE_CONFIG)
            .map_err(crate::error::redb)?
            .insert(ck.as_slice(), stored.as_slice())
            .map_err(crate::error::redb)?
            .is_some();
        if let Some(pinned) = pinned_content(key)?
            && !replaced
        {
            crate::referrers::establish(self, txn, &pinned, &crate::referrers::Referrer::pin(ns))?;
        }
        self.record_metadata_in_txn(txn, ns, key, Some(value), now)
    }

    /// Deleting an absent key is a no-op and records no mutation.
    pub(crate) fn namespace_delete_meta_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        key: &str,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let removed = txn
            .open_table(NAMESPACE_CONFIG)
            .map_err(crate::error::redb)?
            .remove(config_key(ns, key).as_slice())
            .map_err(crate::error::redb)?
            .is_some();
        if !removed {
            return Ok(());
        }
        if let Some(pinned) = pinned_content(key)? {
            crate::referrers::release(self, txn, &pinned, &crate::referrers::Referrer::pin(ns))?;
        }
        self.record_metadata_in_txn(txn, ns, key, None, now)
    }

    pub(super) fn write_namespace_record(
        txn: &redb::WriteTransaction,
        uuid: &[u8; 16],
        record: &NamespaceInfo,
    ) -> Result<(), StoreError> {
        let bytes = canonical_bytes(record);
        txn.open_table(NAMESPACE_RECORDS)
            .map_err(crate::error::redb)?
            .insert(uuid.as_slice(), bytes.as_slice())
            .map_err(crate::error::redb)?;
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
    let info = super::namespace::parse_record(record.value())?;
    if info.ns.id() != ns.id() {
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
