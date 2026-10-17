//! One admitted read of one namespace, and the one classification of the
//! storage a record of a storage instance points at.
//!
//! A [`NamespaceSnapshot`] is a read transaction of a namespace's database
//! that holds the namespace open for its own life: the read grant is
//! retained by its [`ReadView`], so every table it opens and every reader
//! built from it sees one coherent revision whose storage cannot be
//! evicted or retired under it. Every read of committed namespace state
//! goes through one; table opening maps redb's errors in one place.
//!
//! [`PersistentStore::admit_instance`] answers, for a record that names a
//! storage instance, what storage present for it says: held (with how it is
//! identified, `storage_instance::Identification`), released by a recorded
//! retirement, gone without one, or unreadable. Discovery, epoch lookup,
//! settlement and reclamation decide from this one answer.

use std::sync::Arc;

use redb::{
    Key, MultimapTableDefinition, ReadOnlyMultimapTable, ReadOnlyTable, ReadTransaction,
    ReadableDatabase, TableDefinition, Value,
};

use kappa_store::{NamespaceRef, StoreError};

use crate::PersistentStore;
use crate::content_read::ReadView;
use crate::retirement_record::RetirementRecord;
use crate::storage::{Active, NamespaceController};
use crate::storage_instance::{Identification, StorageInstance};

/// A read transaction of one namespace that holds the namespace open.
/// Fields drop in declaration order: the transaction and the controller
/// reference before the view that retains the grant, so the eviction the
/// grant's end triggers finds no reference but the slot's.
pub struct NamespaceSnapshot {
    txn: ReadTransaction,
    controller: Arc<NamespaceController>,
    view: ReadView,
}

impl NamespaceSnapshot {
    /// A snapshot of the namespace `grant` holds open.
    pub(crate) fn of(store: &PersistentStore, grant: Active) -> Result<Self, StoreError> {
        let controller = Arc::clone(grant.controller());
        let txn = controller.db.begin_read().map_err(crate::error::redb)?;
        Ok(Self {
            txn,
            view: store.read_view_retaining(grant),
            controller,
        })
    }

    pub(crate) fn table<K: Key + 'static, V: Value + 'static>(
        &self,
        definition: TableDefinition<'_, K, V>,
    ) -> Result<ReadOnlyTable<K, V>, StoreError> {
        self.txn.open_table(definition).map_err(crate::error::redb)
    }

    pub(crate) fn multimap<K: Key + 'static, V: Key + 'static>(
        &self,
        definition: MultimapTableDefinition<'_, K, V>,
    ) -> Result<ReadOnlyMultimapTable<K, V>, StoreError> {
        self.txn
            .open_multimap_table(definition)
            .map_err(crate::error::redb)
    }

    pub(crate) const fn transaction(&self) -> &ReadTransaction {
        &self.txn
    }

    /// The view readers built from this snapshot share; it retains the
    /// namespace for as long as any of them lives.
    pub(crate) const fn view(&self) -> &ReadView {
        &self.view
    }

    pub(crate) const fn controller(&self) -> &Arc<NamespaceController> {
        &self.controller
    }
}

/// What storage present for a recorded storage instance says.
pub enum InstanceAdmission {
    /// Storage that may answer a read the record locates, and how it is
    /// identified with the record's instance: what it permits beyond
    /// reading is the identification's to decide.
    Held {
        snapshot: NamespaceSnapshot,
        identification: Identification,
    },
    /// No storage of the instance remains, and its retirement `record`
    /// explains why: a read treats what it held as released. A destructive
    /// decision verifies the record first
    /// (`PersistentStore::release_verified`).
    Released(RetirementRecord),
    /// No storage of the instance remains and nothing recorded explains
    /// it: never absence.
    Unexplained(StoreError),
    /// The evidence could not be read.
    Unreadable(StoreError),
}

impl PersistentStore {
    /// A snapshot of `ns`.
    pub(crate) fn namespace_snapshot(
        &self,
        ns: &NamespaceRef,
    ) -> Result<NamespaceSnapshot, StoreError> {
        NamespaceSnapshot::of(self, self.namespaces.admit_read(ns.id())?)
    }

    /// What storage present for `instance` says (see the module docs).
    pub(crate) fn admit_instance(&self, instance: &StorageInstance) -> InstanceAdmission {
        let grant = match self.namespaces.admit_read(instance.namespace()) {
            Ok(grant) => grant,
            Err(StoreError::NotFound(_)) => return self.gone(instance, "missing"),
            Err(error) => return InstanceAdmission::Unreadable(error),
        };
        let identification = grant.controller().instance.identify(instance);
        if !identification.permits_read() {
            drop(grant);
            return self.gone(instance, "replaced by another instance");
        }
        match NamespaceSnapshot::of(self, grant) {
            Ok(snapshot) => InstanceAdmission::Held {
                snapshot,
                identification,
            },
            Err(error) => InstanceAdmission::Unreadable(error),
        }
    }

    /// No storage of `instance` is present (`detail` says how): released
    /// when its retirement record explains it, unexplained otherwise.
    fn gone(&self, instance: &StorageInstance, detail: &str) -> InstanceAdmission {
        match self.retirement_record(instance) {
            Ok(Some(record)) if record.explains_absence() => InstanceAdmission::Released(record),
            Ok(_) => InstanceAdmission::Unexplained(StoreError::Unavailable(format!(
                "storage of {instance} is {detail} without a recorded retirement"
            ))),
            Err(error) => InstanceAdmission::Unreadable(error),
        }
    }
}
