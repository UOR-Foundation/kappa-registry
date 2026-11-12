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
//! alias it touches is journaled by its key (`DIRECTORY_JOURNAL`) in the
//! registry transaction that touches it, after the instance is marked
//! pending, so a crash leaves the journal to a settlement that visits the
//! instance. A deletion journals each alias its tombstone releases: the
//! journal names every entry a resolution may change, and no resolution
//! scans the directory for a namespace's entries.
//!
//! Under the namespace's writer gate, once the outcome is known, a
//! resolution consumes the journal in bounded steps
//! ([`PersistentStore::reconcile_directory`]): each journaled alias is
//! resolved against the namespace's committed record (an alias the live
//! record names is committed; any other entry the namespace holds among the
//! alias and its name is removed) and its journal entry removed in the same
//! registry transaction. The journal is the resolution's durable
//! continuation: a step the meter stops leaves exactly the unresolved
//! entries, and the next resumes from them. A publication resolves after its
//! commit and an aborted execution as it ends, each on its own allowance
//! ([`DirectoryGuard`]); settlement resolves at the head under maintenance,
//! completing what a crash, an unknown outcome, a spent allowance or an
//! owner dropped without ending left. A creation proven
//! never committed resolves against no record, which releases every claim
//! it made, and with its last journal entry releases its existence row
//! ([`PersistentStore::release_directory_claim`]).

use std::sync::Arc;

use redb::{ReadableDatabase, ReadableTable, WriteTransaction};

use kappa_cursor::interval::Interval;
use kappa_store::traits::namespace::NamespaceAlias;
use kappa_store::work::{Dimension, Meter};
use kappa_store::{NamespaceInfo, NamespaceRef, StoreError};
use kappa_types::namespace::{MAX_ALIAS_KEY_BYTES, namespace_alias_key_len};
use kappa_types::page::MAX_ALIASES_PER_NAMESPACE;

use crate::PersistentStore;
use crate::error::CommitFailure;
use crate::namespace::{alias_key, names_key, names_key_of};
use crate::redb_cursor::rows;
use crate::registry::Standing;
use crate::storage::NamespaceController;
use crate::tables::{
    DIRECTORY_JOURNAL, NAMESPACE_ALIASES, NAMESPACE_NAMES, NAMESPACE_RECORDS, NAMESPACES,
};

/// The byte after the identity of a reserved directory entry.
const RESERVED: u8 = 1;

/// Bytes a names key derived from an alias key (`names_key_of`) holds
/// beyond the alias key: the global scope is written `_` rather than empty.
const NAMES_KEY_GROWTH: u64 = 1;

/// Longest framed alias key (`kappa_types::namespace::MAX_ALIAS_KEY_BYTES`).
const ALIAS_KEY: u64 = MAX_ALIAS_KEY_BYTES as u64;

/// Longest journal key: the namespace identity and the longest alias key.
const JOURNAL_KEY: u64 = 16 + ALIAS_KEY;

/// Bytes of a directory entry's value: the identity and the reserved
/// marker.
const ENTRY_VALUE: u64 = 17;

/// Bytes the journal range of one namespace allocates: its prefix interval
/// (the identity and its upper bound, at most as long) and redb's copy of
/// those bounds.
const JOURNAL_RANGE: u64 = 4 * 16;

/// The bound of resolving one journal entry, the indivisible unit of
/// directory reconciliation: the entry and the two directory entries it
/// names examined and read; the journal range built; the entry's key
/// copied, its alias copied and its name key derived, and its key built
/// again for its removal. Every amount derives from the alias format
/// limit, so an admitted resolution never depends on the entry it reads.
/// The terminal observation (no entry remains) costs within the same
/// bound. `validate_settlement` refuses a configuration whose step does
/// not admit it.
pub(crate) const RESOLUTION_UNIT: [(Dimension, u64); 3] = [
    (Dimension::Entries, 3),
    (Dimension::BytesRead, JOURNAL_KEY + 2 * ENTRY_VALUE),
    (
        Dimension::BytesAllocated,
        JOURNAL_RANGE + JOURNAL_KEY + ALIAS_KEY + ALIAS_KEY + NAMES_KEY_GROWTH + JOURNAL_KEY,
    ),
];

/// The bound of reading and deciding `controller`'s committed record for
/// one resolution: the row examined, read and decoded within the
/// settlement record limit `record_bytes` (every namespace record is
/// settlement evidence, read within it), and the alias and name keys the
/// record justifies, each within the alias format limit, for at most
/// `MAX_ALIASES_PER_NAMESPACE` aliases, with the two collections holding
/// them.
pub(crate) fn record_unit(record_bytes: u64) -> [(Dimension, u64); 4] {
    let aliases = MAX_ALIASES_PER_NAMESPACE as u64;
    let slot = std::mem::size_of::<String>() as u64;
    let keys = aliases.saturating_mul(2 * ALIAS_KEY + NAMES_KEY_GROWTH + 2 * slot);
    [
        (Dimension::Entries, 1),
        (Dimension::BytesRead, record_bytes),
        (Dimension::BytesDecoded, record_bytes),
        (Dimension::BytesAllocated, keys),
    ]
}

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

/// Journal the alias `alias_key` as touched by an execution of `uuid`, in
/// `txn`.
pub fn journal(txn: &WriteTransaction, uuid: &[u8; 16], alias_key: &str) -> Result<(), StoreError> {
    let mut key = uuid.to_vec();
    key.extend_from_slice(alias_key.as_bytes());
    txn.open_table(DIRECTORY_JOURNAL)
        .map_err(crate::error::redb)?
        .insert(key.as_slice(), ())
        .map_err(crate::error::redb)?;
    Ok(())
}

/// How far one resolution of a namespace's journal got.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reconciled {
    /// Every journaled change is resolved and its journal entry removed.
    Complete,
    /// The meter stopped the resolution: the entries it did not resolve
    /// stay journaled for the next.
    Partial,
}

/// The first journal entry of `uuid` in `txn`, inside `unit`, a resolution
/// admitted at [`RESOLUTION_UNIT`]: the examination, the range and the
/// copies are accounted as they are made. `None` when no entry remains.
/// Resolved entries are removed as they go, so the first remaining entry is
/// always the next. An entry outside the alias format is refused
/// explicitly: it is never skipped and never left to wait for a larger
/// step.
fn next_journaled(
    txn: &WriteTransaction,
    uuid: &[u8; 16],
    unit: &mut dyn Meter,
) -> Result<Option<String>, StoreError> {
    unit.account(Dimension::Entries, 1)?;
    let table = txn
        .open_table(DIRECTORY_JOURNAL)
        .map_err(crate::error::redb)?;
    let interval_bytes = Interval::prefix_cost(uuid)
        .ok_or_else(|| StoreError::Internal("journal range bound exceeds u64".into()))?;
    unit.account(Dimension::BytesAllocated, interval_bytes)?;
    let interval = Interval::prefix(uuid);
    let mut entries = rows(&table, &interval, unit)?;
    let Some(entry) = entries.next() else {
        return Ok(None);
    };
    let (key, _) = entry?;
    let key = key.value();
    if key.len() as u64 > JOURNAL_KEY {
        return Err(StoreError::Internal(format!(
            "a directory journal entry of {} bytes exceeds the alias format limit",
            key.len()
        )));
    }
    unit.account(Dimension::BytesRead, key.len() as u64)?;
    unit.account(Dimension::BytesAllocated, key.len() as u64)?;
    let alias = key
        .get(16..)
        .filter(|alias| !alias.is_empty())
        .ok_or_else(|| StoreError::Internal("directory journal entry names no alias".into()))?;
    let alias = std::str::from_utf8(alias)
        .map_err(|error| StoreError::Internal(format!("directory journal alias: {error}")))?;
    unit.account(Dimension::BytesAllocated, alias.len() as u64)?;
    Ok(Some(alias.to_owned()))
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

/// Resolve the directory entry at `key` of `table` for `uuid`, its
/// examination and read accounted inside `unit`.
fn resolve_entry(
    table: &mut redb::Table<'_, &'static str, &'static [u8]>,
    key: &str,
    uuid: &[u8; 16],
    named: bool,
    unit: &mut dyn Meter,
) -> Result<(), StoreError> {
    unit.account(Dimension::Entries, 1)?;
    let current = match table.get(key).map_err(crate::error::redb)? {
        Some(value) => {
            unit.account(Dimension::BytesRead, value.value().len() as u64)?;
            resolution(value.value(), uuid, named)?
        }
        None => Resolution::Keep,
    };
    match current {
        Resolution::Keep => {}
        Resolution::Commit => {
            table
                .insert(key, uuid.as_slice())
                .map_err(crate::error::redb)?;
        }
        Resolution::Remove => {
            table.remove(key).map_err(crate::error::redb)?;
        }
    }
    Ok(())
}

/// The alias and name keys a committed, live record justifies: those of the
/// aliases it holds, by name and scope together. A deleted record, or none,
/// justifies nothing.
struct Justified {
    aliases: Vec<String>,
    names: Vec<String>,
}

impl Justified {
    /// The keys `record` justifies, inside `unit`, the record's unit
    /// ([`record_unit`]): a record holding more aliases than the format
    /// allows is refused before anything is allocated.
    fn of(record: Option<&NamespaceInfo>, unit: &mut dyn Meter) -> Result<Self, StoreError> {
        let held: &[NamespaceAlias] = match record {
            Some(record) if !record.tombstoned => &record.aliases,
            _ => &[],
        };
        if held.len() > MAX_ALIASES_PER_NAMESPACE {
            return Err(StoreError::Internal(format!(
                "a namespace record holds {} aliases, beyond the format limit {MAX_ALIASES_PER_NAMESPACE}",
                held.len()
            )));
        }
        let mut aliases = Vec::with_capacity(held.len());
        let mut names = Vec::with_capacity(held.len());
        let slot = std::mem::size_of::<String>() as u64;
        unit.account(
            Dimension::BytesAllocated,
            (held.len() as u64).saturating_mul(2 * slot),
        )?;
        for alias in held {
            let framed = namespace_alias_key_len(&alias.name, alias.protocol.as_ref()) as u64;
            if framed > ALIAS_KEY {
                return Err(StoreError::Internal(
                    "a namespace record holds an alias beyond the alias format limit".into(),
                ));
            }
            unit.account(
                Dimension::BytesAllocated,
                framed.saturating_mul(2).saturating_add(NAMES_KEY_GROWTH),
            )?;
            aliases.push(alias_key(&alias.name, alias.protocol.as_ref()));
            names.push(names_key(&alias.name, alias.protocol.as_ref()));
        }
        Ok(Self { aliases, names })
    }
}

impl PersistentStore {
    /// Journal the release of every alias a deletion of `ns` tombstoned,
    /// resolved by the deletion's outcome: the aliases are removed once the
    /// tombstoned record is committed, and kept otherwise.
    pub(super) fn journal_released(
        &self,
        ns: &NamespaceRef,
        released: &[NamespaceAlias],
    ) -> Result<(), StoreError> {
        if released.is_empty() {
            return Ok(());
        }
        let instance = self.controller(ns)?.instance;
        self.mark_unsettled(&instance)?;
        let txn = self.registry.begin_write()?;
        for alias in released {
            journal(
                &txn,
                ns.id(),
                &alias_key(&alias.name, alias.protocol.as_ref()),
            )?;
        }
        match txn.commit() {
            Ok(()) => Ok(()),
            // The instance was marked pending first; journal entries that
            // persisted are resolved against the committed record.
            Err(CommitFailure::Known(error) | CommitFailure::Unknown(error)) => Err(error),
        }
    }

    /// Resolve the journaled directory changes of `controller`'s namespace
    /// against its committed record within `work` (see the module
    /// documentation). The caller holds the namespace's writer gate, so no
    /// execution of it reserves or commits meanwhile. `RecoveryRequired`
    /// when the registry's commit outcome is unknown on this handle, before
    /// or by this resolution: the journal stays for a reopen, and the
    /// caller keeps what depends on it.
    pub(crate) fn reconcile_directory(
        &self,
        controller: &NamespaceController,
        work: &mut dyn Meter,
    ) -> Result<Standing<Reconciled>, StoreError> {
        let record_bytes = self.settlement_limits.record_bytes();
        let justified = {
            let Ok(mut unit) = work.admit(&record_unit(record_bytes)) else {
                return Ok(Standing::Ready(Reconciled::Partial));
            };
            let record = committed_record(controller, record_bytes, &mut unit)?;
            Justified::of(record.as_ref(), &mut unit)?
        };
        self.resolve_journal(&controller.id, &justified, false, work)
    }

    /// Release every directory claim `uuid` holds, reserved or committed,
    /// within `work`: the claims of a creation proven never committed, all
    /// of which its execution journaled. The namespace's settled record is
    /// projection state, changed only by settlement (`projection`): a
    /// creation that never committed has none. The existence row goes with
    /// the last journal entry, so a partial release keeps the identity
    /// claimed. `RecoveryRequired` when the registry's commit outcome is
    /// unknown on this handle, before or by this release: the claim's fate
    /// is then a reopen's to decide, never this instance's failure.
    pub(crate) fn release_directory_claim(
        &self,
        uuid: &[u8; 16],
        work: &mut dyn Meter,
    ) -> Result<Standing<Reconciled>, StoreError> {
        // No creation committed: the record justifies nothing.
        let justified = Justified {
            aliases: Vec::new(),
            names: Vec::new(),
        };
        self.resolve_journal(uuid, &justified, true, work)
    }

    /// The one resolution of `uuid`'s journal against what `justified`
    /// holds, releasing the existence row when `release` and the journal is
    /// consumed, in one registry transaction: each entry is one unit
    /// admitted at [`RESOLUTION_UNIT`] before it is examined, and a refusal
    /// leaves that entry, and every one after it, journaled. Any error
    /// abandons the transaction, every effect of this call with it.
    fn resolve_journal(
        &self,
        uuid: &[u8; 16],
        justified: &Justified,
        release: bool,
        work: &mut dyn Meter,
    ) -> Result<Standing<Reconciled>, StoreError> {
        let Standing::Ready(txn) = self.registry.write_standing()? else {
            return Ok(Standing::RecoveryRequired);
        };
        let mut changed = false;
        let reconciled = loop {
            let Ok(mut unit) = work.admit(&RESOLUTION_UNIT) else {
                break Reconciled::Partial;
            };
            let Some(alias) = next_journaled(&txn, uuid, &mut unit)? else {
                break Reconciled::Complete;
            };
            unit.account(
                Dimension::BytesAllocated,
                (alias.len() as u64).saturating_add(NAMES_KEY_GROWTH),
            )?;
            let names = names_key_of(&alias)?;
            resolve_entry(
                &mut txn
                    .open_table(NAMESPACE_ALIASES)
                    .map_err(crate::error::redb)?,
                &alias,
                uuid,
                justified.aliases.contains(&alias),
                &mut unit,
            )?;
            resolve_entry(
                &mut txn
                    .open_table(NAMESPACE_NAMES)
                    .map_err(crate::error::redb)?,
                &names,
                uuid,
                justified.names.contains(&names),
                &mut unit,
            )?;
            let length = 16 + alias.len();
            unit.account(Dimension::BytesAllocated, length as u64)?;
            let mut key = Vec::with_capacity(length);
            key.extend_from_slice(uuid);
            key.extend_from_slice(alias.as_bytes());
            txn.open_table(DIRECTORY_JOURNAL)
                .map_err(crate::error::redb)?
                .remove(key.as_slice())
                .map_err(crate::error::redb)?;
            changed = true;
        };
        if release && reconciled == Reconciled::Complete {
            txn.open_table(NAMESPACES)
                .map_err(crate::error::redb)?
                .remove(uuid.as_slice())
                .map_err(crate::error::redb)?;
            changed = true;
        }
        if !changed {
            txn.abort()?;
            return Ok(Standing::Ready(reconciled));
        }
        match txn.commit() {
            Ok(()) => Ok(Standing::Ready(reconciled)),
            // Nothing persisted: resolution follows the committed record and
            // is idempotent, so the journal entries resolve the same way the
            // next time it runs.
            Err(CommitFailure::Known(error)) => Err(error),
            // The registry is recovery-required from this commit on.
            Err(CommitFailure::Unknown(_)) => Ok(Standing::RecoveryRequired),
        }
    }
}

/// The record `controller`'s database committed, `None` when no creation of
/// the namespace committed, read once and decoded from the row read, inside
/// `unit`, the record's unit ([`record_unit`]). A row beyond the settlement
/// record limit `record_bytes` is refused explicitly: it could never be
/// settled either.
fn committed_record(
    controller: &NamespaceController,
    record_bytes: u64,
    unit: &mut dyn Meter,
) -> Result<Option<NamespaceInfo>, StoreError> {
    unit.account(Dimension::Entries, 1)?;
    let read = controller.db.begin_read().map_err(crate::error::redb)?;
    let table = read
        .open_table(NAMESPACE_RECORDS)
        .map_err(crate::error::redb)?;
    let Some(row) = table
        .get(controller.id.as_slice())
        .map_err(crate::error::redb)?
    else {
        return Ok(None);
    };
    let bytes = row.value().len() as u64;
    if bytes > record_bytes {
        return Err(StoreError::CapacityExceeded(format!(
            "the record of namespace {} is {bytes} bytes, beyond the settlement record limit {record_bytes}",
            hex::encode(controller.id)
        )));
    }
    unit.account(Dimension::BytesRead, bytes)?;
    unit.account(Dimension::BytesDecoded, bytes)?;
    super::namespace_record_of(row.value(), &controller.id).map(Some)
}

/// The directory changes one execution made, resolved when it ends, on the
/// allowance of the operation that made them ([`Self::resolve`]): a
/// publication resolves them against the record it committed, and an
/// execution aborted or a publication whose commit was known not to happen
/// against the record still committed; one whose commit outcome is unknown
/// is disarmed ([`Self::disarm`]) and settlement resolves them once
/// recovery learned the outcome. Every owner declares it before its writer
/// gate, so it resolves under the gate. What a resolution leaves, because
/// the allowance stopped it or because its owner was dropped without
/// ending it, stays journaled under the pending marker for settlement.
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

    /// Resolve the changes against the record now committed, on `work`, the
    /// allowance of the operation that made them. A registry whose commit
    /// outcome is unknown refuses (`Unavailable`); a resolution the
    /// allowance stops is left to settlement, journaled.
    pub(crate) fn resolve(mut self, work: &mut dyn Meter) -> Result<(), StoreError> {
        if std::mem::take(&mut self.touched) {
            let reconciled = self
                .store
                .reconcile_directory(&self.controller, work)?
                .or_unavailable()?;
            if reconciled == Reconciled::Partial {
                tracing::warn!(
                    namespace = %hex::encode(self.controller.id),
                    "directory changes exceed what the operation's allowance left; settlement completes them"
                );
            }
        }
        Ok(())
    }

    /// Leave the changes to settlement: the commit outcome is unknown.
    pub(crate) fn disarm(mut self) {
        self.touched = false;
    }
}

impl Drop for DirectoryGuard<'_> {
    /// Reached with changes still owed only when the owner was dropped
    /// without ending them: no operation, and so no allowance, governs
    /// them any more. Nothing is resolved here. The journal is durable and
    /// the instance is marked pending, so settlement resolves the changes at
    /// the head; until then a reservation resolves to nothing and a
    /// committed alias stays, so no reader observes a change the namespace
    /// did not commit.
    fn drop(&mut self) {
        if std::mem::take(&mut self.touched) {
            tracing::debug!(
                namespace = %hex::encode(self.controller.id),
                "directory changes of an execution dropped without ending left to settlement"
            );
        }
    }
}
