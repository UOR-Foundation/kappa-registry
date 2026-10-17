//! The directory changes an execution makes before its commit, and their
//! resolution against what its namespace committed.
//!
//! The directory (`NAMESPACE_ALIASES`, `NAMESPACE_NAMES`) is registry state
//! unique across every namespace, while an execution commits in its own
//! namespace's database: no transaction spans both. An execution therefore
//! changes the directory in two steps.
//!
//! Before its commit it only reserves. An alias it creates, adds or
//! renames to is inserted reserved ([`reserved`]): the reservation refuses
//! every other claimant of the alias and resolves to nothing. An alias it
//! renames away from, or a deletion's aliases, stay as they are. Every
//! alias it touches is journaled (`DIRECTORY_JOURNAL`) in the registry
//! transaction that touches it, after the instance is marked pending, so a
//! crash leaves the journal to a settlement that visits the instance.
//!
//! Under the namespace's writer gate, once the outcome is known,
//! [`PersistentStore::reconcile_directory`] resolves every journaled alias
//! against the namespace's committed record: an alias the record names, of
//! a namespace not deleted, is committed; any other entry the namespace
//! holds among them is removed; the journal entries go in the same
//! registry transaction. A publication reconciles after its commit and an
//! abandoned execution as it ends ([`DirectoryGuard`]); settlement
//! reconciles at the head under maintenance, completing what a crash
//! interrupted. A directory change is visible exactly when its epoch is,
//! and an aborted one changes nothing anyone can resolve.
//!
//! The existence row (`NAMESPACES`) a creation claims is its claim on the
//! identity, released only by the proof that the creation never committed
//! (`settlement_driver`).

use std::sync::Arc;

use redb::{ReadableDatabase, ReadableTable, WriteTransaction};

use kappa_store::{NamespaceInfo, NamespaceRef, StoreError};

use super::directory::owned_index_keys;
use crate::PersistentStore;
use crate::namespace::{names_key_name, split_alias_key};
use crate::storage::{NamespaceController, NamespaceStorage};
use crate::tables::{DIRECTORY_JOURNAL, NAMESPACE_ALIASES, NAMESPACE_NAMES, NAMESPACE_RECORDS};

/// The byte after the identity of a reserved directory entry.
const RESERVED: u8 = 1;

/// The value of a directory entry `uuid` reserves.
pub fn reserved(uuid: &[u8; 16]) -> [u8; 17] {
    let mut value = [RESERVED; 17];
    value[..16].copy_from_slice(uuid);
    value
}

/// The namespace a directory entry names, and whether the entry is
/// committed (resolvable) rather than reserved.
pub fn entry_owner(value: &[u8]) -> Result<([u8; 16], bool), StoreError> {
    let uuid = value.get(..16).and_then(|id| <[u8; 16]>::try_from(id).ok());
    match (uuid, value.get(16..)) {
        (Some(uuid), Some([])) => Ok((uuid, true)),
        (Some(uuid), Some([RESERVED])) => Ok((uuid, false)),
        _ => Err(StoreError::Internal(format!(
            "directory entry of {} bytes names no namespace",
            value.len()
        ))),
    }
}

/// Journal `alias_key`, or with `None` every alias, as touched by an
/// execution of `uuid`, in `txn`.
pub fn journal(
    txn: &WriteTransaction,
    uuid: &[u8; 16],
    alias_key: Option<&str>,
) -> Result<(), StoreError> {
    let mut key = uuid.to_vec();
    if let Some(alias) = alias_key {
        key.extend_from_slice(alias.as_bytes());
    }
    txn.open_table(DIRECTORY_JOURNAL)
        .map_err(crate::error::redb)?
        .insert(key.as_slice(), ())
        .map_err(crate::error::redb)?;
    Ok(())
}

/// Remove every journal entry of `uuid`, in `txn`.
pub fn clear_journal(txn: &WriteTransaction, uuid: &[u8; 16]) -> Result<(), StoreError> {
    let mut table = txn
        .open_table(DIRECTORY_JOURNAL)
        .map_err(crate::error::redb)?;
    for key in journaled(&table, uuid)?.keys {
        table.remove(key.as_slice()).map_err(crate::error::redb)?;
    }
    Ok(())
}

/// What the journal holds for one namespace.
#[derive(Default)]
struct Journaled {
    /// The alias keys touched.
    aliases: Vec<String>,
    /// A deletion touched every alias.
    every: bool,
    /// The journal keys, for their removal.
    keys: Vec<Vec<u8>>,
}

/// The journal entries of `uuid`: every key in the range its identity
/// prefixes.
fn journaled(
    table: &impl ReadableTable<&'static [u8], ()>,
    uuid: &[u8; 16],
) -> Result<Journaled, StoreError> {
    let end = PersistentStore::prefix_successor(uuid);
    let range = end
        .as_ref()
        .map_or_else(
            || table.range(uuid.as_slice()..),
            |end| table.range(uuid.as_slice()..end.as_slice()),
        )
        .map_err(crate::error::redb)?;
    let mut found = Journaled::default();
    for entry in range {
        let (key, _) = entry.map_err(crate::error::redb)?;
        let key = key.value();
        let alias = key.get(16..).ok_or_else(|| {
            StoreError::Internal("directory journal key shorter than its identity".into())
        })?;
        if alias.is_empty() {
            found.every = true;
        } else {
            found.aliases.push(
                std::str::from_utf8(alias)
                    .map_err(|error| {
                        StoreError::Internal(format!("directory journal alias: {error}"))
                    })?
                    .to_owned(),
            );
        }
        found.keys.push(key.to_vec());
    }
    Ok(found)
}

/// What reconciliation does to one directory entry.
enum Resolution {
    /// Another namespace's entry, an absent one, or a committed one the
    /// record names: unchanged.
    Keep,
    /// A reservation the record names: committed.
    Commit,
    /// An entry of the namespace the record does not name: removed.
    Remove,
}

/// The resolution of an entry whose current value is `value`, for `uuid`
/// whose committed record does (`named`) or does not name it.
fn resolution(value: &[u8], uuid: &[u8; 16], named: bool) -> Result<Resolution, StoreError> {
    let (owner, committed) = entry_owner(value)?;
    Ok(match (owner == *uuid, named, committed) {
        (false, _, _) | (true, true, true) => Resolution::Keep,
        (true, true, false) => Resolution::Commit,
        (true, false, _) => Resolution::Remove,
    })
}

impl PersistentStore {
    /// Journal a deletion of every alias of `ns`, resolved by the
    /// deletion's outcome: the aliases are removed once a tombstoned record
    /// is committed, and kept otherwise.
    pub(super) fn journal_deletion(&self, ns: &NamespaceRef) -> Result<(), StoreError> {
        let instance = self.controller(ns)?.instance;
        self.mark_unsettled(&instance)?;
        let txn = self.registry.begin_write().map_err(crate::error::redb)?;
        journal(&txn, ns.id(), None)?;
        txn.commit().map_err(crate::error::redb)
    }

    /// Resolve every journaled directory change of `controller`'s
    /// namespace against its committed record (see the module
    /// documentation). The caller holds the namespace's writer gate, so no
    /// execution of it reserves or commits meanwhile. Reads only, when
    /// nothing is journaled.
    pub(crate) fn reconcile_directory(
        &self,
        controller: &NamespaceController,
    ) -> Result<(), StoreError> {
        let uuid = controller.id;
        let journaled = {
            let read = self.registry.begin_read().map_err(crate::error::redb)?;
            let table = read
                .open_table(DIRECTORY_JOURNAL)
                .map_err(crate::error::redb)?;
            journaled(&table, &uuid)?
        };
        if journaled.keys.is_empty() {
            return Ok(());
        }
        let record = committed_record(controller)?;
        let justified = |name: &str| {
            record.as_ref().is_some_and(|record| {
                !record.tombstoned && record.aliases.iter().any(|alias| alias == name)
            })
        };
        let ns = NamespaceStorage::namespace_ref(uuid);
        let txn = self.registry.begin_write().map_err(crate::error::redb)?;
        {
            let mut aliases = txn
                .open_table(NAMESPACE_ALIASES)
                .map_err(crate::error::redb)?;
            let mut names = txn
                .open_table(NAMESPACE_NAMES)
                .map_err(crate::error::redb)?;
            let mut alias_keys = journaled.aliases;
            let mut name_keys = Vec::with_capacity(alias_keys.len());
            for key in &alias_keys {
                name_keys.push(split_alias_key(key)?.1);
            }
            if journaled.every {
                alias_keys.extend(owned_index_keys(&aliases, &ns)?);
                name_keys.extend(owned_index_keys(&names, &ns)?);
            }
            for key in &alias_keys {
                let name = split_alias_key(key)?.0;
                let current = aliases
                    .get(key.as_str())
                    .map_err(crate::error::redb)?
                    .map(|value| resolution(value.value(), &uuid, justified(name)))
                    .transpose()?
                    .unwrap_or(Resolution::Keep);
                match current {
                    Resolution::Keep => {}
                    Resolution::Commit => {
                        aliases
                            .insert(key.as_str(), uuid.as_slice())
                            .map_err(crate::error::redb)?;
                    }
                    Resolution::Remove => {
                        aliases.remove(key.as_str()).map_err(crate::error::redb)?;
                    }
                }
            }
            for key in &name_keys {
                let name = names_key_name(key)?;
                let current = names
                    .get(key.as_str())
                    .map_err(crate::error::redb)?
                    .map(|value| resolution(value.value(), &uuid, justified(name)))
                    .transpose()?
                    .unwrap_or(Resolution::Keep);
                match current {
                    Resolution::Keep => {}
                    Resolution::Commit => {
                        names
                            .insert(key.as_str(), uuid.as_slice())
                            .map_err(crate::error::redb)?;
                    }
                    Resolution::Remove => {
                        names.remove(key.as_str()).map_err(crate::error::redb)?;
                    }
                }
            }
        }
        let mut entries = txn
            .open_table(DIRECTORY_JOURNAL)
            .map_err(crate::error::redb)?;
        for key in &journaled.keys {
            entries.remove(key.as_slice()).map_err(crate::error::redb)?;
        }
        drop(entries);
        txn.commit().map_err(crate::error::redb)
    }
}

/// The record `controller`'s database committed, or `None` when no
/// creation of the namespace committed.
fn committed_record(controller: &NamespaceController) -> Result<Option<NamespaceInfo>, StoreError> {
    let read = controller.db.begin_read().map_err(crate::error::redb)?;
    let table = read
        .open_table(NAMESPACE_RECORDS)
        .map_err(crate::error::redb)?;
    match super::namespace_record_in(&table, &NamespaceStorage::namespace_ref(controller.id)) {
        Ok(record) => Ok(Some(record)),
        Err(StoreError::NotFound(_)) => Ok(None),
        Err(error) => Err(error),
    }
}

/// The directory changes one execution made, resolved when it ends: a
/// publication resolves them against the record it committed
/// ([`Self::resolve`]); an execution dropped unpublished, or a publication
/// whose commit was known not to happen, resolves them as it drops; one
/// whose commit outcome is unknown is disarmed ([`Self::disarm`]) and
/// settlement resolves them once recovery learned the outcome. Every owner
/// declares it before its writer gate, so it resolves under the gate.
pub struct DirectoryGuard<'a> {
    store: &'a PersistentStore,
    controller: Arc<NamespaceController>,
    touched: bool,
}

impl<'a> DirectoryGuard<'a> {
    pub(crate) const fn new(
        store: &'a PersistentStore,
        controller: Arc<NamespaceController>,
    ) -> Self {
        Self {
            store,
            controller,
            touched: false,
        }
    }

    /// The execution is about to change the directory.
    pub(crate) const fn touch(&mut self) {
        self.touched = true;
    }

    /// Resolve the changes against the record now committed.
    pub(crate) fn resolve(mut self) -> Result<(), StoreError> {
        if std::mem::take(&mut self.touched) {
            self.store.reconcile_directory(&self.controller)?;
        }
        Ok(())
    }

    /// Leave the changes to settlement: the commit outcome is unknown.
    pub(crate) fn disarm(mut self) {
        self.touched = false;
    }
}

impl Drop for DirectoryGuard<'_> {
    fn drop(&mut self) {
        if !std::mem::take(&mut self.touched) {
            return;
        }
        // A destructor cannot return the failure. The journal is durable
        // and the instance is marked pending, so settlement resolves the
        // changes at the head; until then a reservation resolves to
        // nothing and a committed alias stays, so no reader observes a
        // change the namespace did not commit.
        if let Err(error) = self.store.reconcile_directory(&self.controller) {
            tracing::warn!(
                namespace = %hex::encode(self.controller.id),
                %error,
                "directory changes of an abandoned execution left to settlement"
            );
        }
    }
}
