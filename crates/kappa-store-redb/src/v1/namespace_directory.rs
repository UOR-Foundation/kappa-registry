//! Directory claims in the registry: alias and name reservations, the
//! namespace existence row, and their release. An execution reserves in
//! one short registry transaction before it writes the namespace side;
//! what it reserved is committed or removed against its committed record
//! once its outcome is known (`namespace_directory_journal`).

use kappa_store::{
    ClockMs, NamespaceRef, StoreError, namespace::ProtocolId, page::MAX_ALIASES_PER_NAMESPACE,
};
use redb::ReadableTable;

use super::journal::{clear_journal, entry_owner, journal, reserved};
use crate::namespace::{
    HistoryDetail, alias_key, append_history, ensure_alias_available, names_key,
};
use crate::{
    PersistentStore,
    tables::{NAMESPACE_ALIASES, NAMESPACE_NAMES, NAMESPACES},
};

impl PersistentStore {
    /// Whether the directory holds `ns`: a settled record or a live claim.
    pub(crate) fn directory_knows(&self, ns: &NamespaceRef) -> Result<bool, StoreError> {
        use redb::ReadableDatabase;
        let txn = self.registry.begin_read().map_err(crate::error::redb)?;
        Ok(txn
            .open_table(NAMESPACES)
            .map_err(crate::error::redb)?
            .get(ns.id().as_slice())
            .map_err(crate::error::redb)?
            .is_some())
    }

    /// Reserve `name` within `protocol` for `uuid` in the registry, and
    /// mark the open storage instance pending so a reservation a crash
    /// leaves is resolved by settlement. Called inside an execution, which
    /// holds the controller open and its writer gate. One registry
    /// transaction; refused when the alias is taken or reserved. A
    /// creation also claims the identity's existence row.
    pub(super) fn claim_alias(
        &self,
        uuid: &[u8; 16],
        name: &str,
        protocol: Option<&ProtocolId>,
        create: bool,
    ) -> Result<(), StoreError> {
        let instance = self
            .controller(&crate::storage::NamespaceStorage::namespace_ref(*uuid))?
            .instance;
        self.mark_unsettled(&instance)?;
        let key = alias_key(name, protocol);
        let txn = self.registry.begin_write().map_err(crate::error::redb)?;
        {
            let mut aliases = txn
                .open_table(NAMESPACE_ALIASES)
                .map_err(crate::error::redb)?;
            let mut names = txn
                .open_table(NAMESPACE_NAMES)
                .map_err(crate::error::redb)?;
            ensure_alias_available(&aliases, &names, name, protocol)?;
            let value = reserved(uuid);
            aliases
                .insert(key.as_str(), value.as_slice())
                .map_err(crate::error::redb)?;
            names
                .insert(names_key(name, protocol).as_str(), value.as_slice())
                .map_err(crate::error::redb)?;
            if create {
                let mut namespaces = txn.open_table(NAMESPACES).map_err(crate::error::redb)?;
                if namespaces
                    .insert(uuid.as_slice(), ())
                    .map_err(crate::error::redb)?
                    .is_some()
                {
                    return Err(StoreError::AlreadyExists(format!(
                        "namespace {}",
                        hex::encode(uuid)
                    )));
                }
            }
        }
        journal(&txn, uuid, Some(&key))?;
        txn.commit().map_err(crate::error::redb)
    }

    /// Release every directory claim `uuid` holds, committed or reserved,
    /// with its journal: the claim of a creation proven never to have
    /// committed. The namespace's settled record is projection state,
    /// changed only by settlement (`projection`): a creation that never
    /// committed has none.
    pub(crate) fn release_directory_claim(&self, uuid: &[u8; 16]) -> Result<(), StoreError> {
        let txn = self.registry.begin_write().map_err(crate::error::redb)?;
        {
            let mut aliases = txn
                .open_table(NAMESPACE_ALIASES)
                .map_err(crate::error::redb)?;
            let mut names = txn
                .open_table(NAMESPACE_NAMES)
                .map_err(crate::error::redb)?;
            let ns = crate::storage::NamespaceStorage::namespace_ref(*uuid);
            for key in owned_index_keys(&aliases, &ns)? {
                aliases.remove(key.as_str()).map_err(crate::error::redb)?;
            }
            for key in owned_index_keys(&names, &ns)? {
                names.remove(key.as_str()).map_err(crate::error::redb)?;
            }
            txn.open_table(NAMESPACES)
                .map_err(crate::error::redb)?
                .remove(uuid.as_slice())
                .map_err(crate::error::redb)?;
        }
        clear_journal(&txn, uuid)?;
        txn.commit().map_err(crate::error::redb)
    }

    /// Reserve the rename of the committed alias `old_name` within
    /// `protocol` to `new_name`, returning the identity it names: the new
    /// alias is reserved and both are journaled; the old one stays
    /// committed until the rename's outcome resolves them
    /// (`reconcile_directory`). The alias must belong to `expected` when
    /// given.
    fn reserve_rename(
        &self,
        old_name: &str,
        new_name: &str,
        protocol: Option<&ProtocolId>,
        expected: Option<&[u8; 16]>,
    ) -> Result<[u8; 16], StoreError> {
        let old_key = alias_key(old_name, protocol);
        let new_key = alias_key(new_name, protocol);
        let uuid = {
            use redb::ReadableDatabase;
            let read = self.registry.begin_read().map_err(crate::error::redb)?;
            let aliases = read
                .open_table(NAMESPACE_ALIASES)
                .map_err(crate::error::redb)?;
            let value = aliases
                .get(old_key.as_str())
                .map_err(crate::error::redb)?
                .ok_or_else(|| StoreError::NotFound(format!("namespace: {old_name}")))?;
            match entry_owner(value.value())? {
                (uuid, true) => uuid,
                (_, false) => {
                    return Err(StoreError::NotFound(format!("namespace: {old_name}")));
                }
            }
        };
        if expected.is_some_and(|expected| *expected != uuid) {
            return Err(StoreError::Rejected(format!(
                "alias {old_name} does not belong to the execution namespace"
            )));
        }
        let instance = self
            .controller(&crate::storage::NamespaceStorage::namespace_ref(uuid))?
            .instance;
        self.mark_unsettled(&instance)?;
        let registry = self.registry.begin_write().map_err(crate::error::redb)?;
        {
            let mut aliases = registry
                .open_table(NAMESPACE_ALIASES)
                .map_err(crate::error::redb)?;
            let mut names = registry
                .open_table(NAMESPACE_NAMES)
                .map_err(crate::error::redb)?;
            // The writer gate the execution holds keeps every other
            // execution of this namespace out, and the old alias is
            // committed: only a reconciliation of this namespace, which
            // also takes the gate, could change it.
            let current = aliases
                .get(old_key.as_str())
                .map_err(crate::error::redb)?
                .map(|value| entry_owner(value.value()))
                .transpose()?;
            if current != Some((uuid, true)) {
                return Err(StoreError::Conflict(format!(
                    "alias {old_name} changed before its rename was reserved"
                )));
            }
            ensure_alias_available(&aliases, &names, new_name, protocol)?;
            let value = reserved(&uuid);
            aliases
                .insert(new_key.as_str(), value.as_slice())
                .map_err(crate::error::redb)?;
            names
                .insert(names_key(new_name, protocol).as_str(), value.as_slice())
                .map_err(crate::error::redb)?;
        }
        journal(&registry, &uuid, Some(&new_key))?;
        journal(&registry, &uuid, Some(&old_key))?;
        registry.commit().map_err(crate::error::redb)?;
        Ok(uuid)
    }

    /// Rename the alias `old_name` within `protocol`: the registry reserves
    /// the new alias in one registry transaction, the namespace's record
    /// changes in its own, and the directory follows the record once the
    /// execution's outcome is known. The alias must belong to the
    /// execution's namespace.
    pub(crate) fn namespace_rename_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        old_name: &str,
        new_name: &str,
        protocol: Option<&ProtocolId>,
        expected: Option<&[u8; 16]>,
        now: ClockMs,
    ) -> Result<NamespaceRef, StoreError> {
        let uuid = self.reserve_rename(old_name, new_name, protocol, expected)?;
        let ns = NamespaceRef::resolved(uuid, new_name.to_string(), protocol.cloned());
        let mut record = Self::namespace_info_in_txn(txn, &ns)?;
        if record.tombstoned {
            return Err(StoreError::Rejected(
                "cannot rename a deleted namespace".into(),
            ));
        }
        record.aliases.retain(|alias| alias != old_name);
        if !record.aliases.iter().any(|alias| alias == new_name) {
            record.aliases.push(new_name.to_string());
        }
        record.name = new_name.to_string();
        Self::write_namespace_record(txn, &uuid, &record)?;
        append_history(
            txn,
            &uuid,
            new_name,
            "",
            now.as_i64(),
            HistoryDetail::Rename {
                old_name: old_name.to_string(),
            },
        )?;
        self.record_namespace_in_txn(txn, &ns, now)?;
        Ok(ns)
    }

    /// Add an alias to `ns`, enforcing `MAX_ALIASES_PER_NAMESPACE` against
    /// the record observed inside this transaction.
    pub(crate) fn namespace_add_alias_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        alias: &str,
        protocol: Option<&ProtocolId>,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let uuid = *ns.id();
        let mut record = Self::namespace_info_in_txn(txn, ns)?;
        if record.tombstoned {
            return Err(StoreError::Rejected(
                "cannot alias a deleted namespace".into(),
            ));
        }
        if record.aliases.len() >= MAX_ALIASES_PER_NAMESPACE {
            return Err(StoreError::Rejected(format!(
                "namespace has {} aliases, max {MAX_ALIASES_PER_NAMESPACE}",
                record.aliases.len()
            )));
        }
        self.claim_alias(&uuid, alias, protocol, false)?;
        if !record.aliases.iter().any(|existing| existing == alias) {
            record.aliases.push(alias.to_string());
        }
        Self::write_namespace_record(txn, &uuid, &record)?;
        append_history(
            txn,
            &uuid,
            alias,
            "",
            now.as_i64(),
            HistoryDetail::AddAlias {
                protocol: protocol.map(|p| p.as_str().to_string()),
            },
        )?;
        self.record_namespace_in_txn(txn, ns, now)
    }
}

/// The keys of `table` whose entry `ns` holds, committed or reserved.
pub(super) fn owned_index_keys(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    ns: &NamespaceRef,
) -> Result<Vec<String>, StoreError> {
    let mut keys = Vec::new();
    for entry in table.iter().map_err(crate::error::redb)? {
        let (key, owner) = entry.map_err(crate::error::redb)?;
        let (uuid, _) = entry_owner(owner.value())?;
        if uuid == *ns.id() {
            keys.push(key.value().to_owned());
        }
    }
    Ok(keys)
}
