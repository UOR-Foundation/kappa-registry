//! The namespace storage's catalog operations: construction, existence,
//! the on-disk listing, open-controller lookup, assignment resolution, and
//! the storage evidence a removal decides from. Admission and eviction are
//! in `storage_handles`, retirement transitions in `storage_retiring`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize};

use dashmap::DashMap;
use redb::Database;

use kappa_store::error::StoreError;
use kappa_store::namespace::NamespaceRef;

use super::{
    AssignmentSource, ControlPlanes, NamespaceBackend, NamespaceController, NamespaceStorage,
    NamespaceStorageInner, RetirementSource, Slot,
};
use crate::control_plane::AssignmentRecord;
use crate::storage_instance::StorageInstance;

impl NamespaceStorage {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        root: PathBuf,
        max_idle: usize,
        max_active: usize,
        planes: Arc<ControlPlanes>,
        assignments: Arc<dyn AssignmentSource>,
        fences: Arc<dyn RetirementSource>,
        backend: Option<NamespaceBackend>,
        fsync: bool,
    ) -> Self {
        Self {
            inner: Arc::new(NamespaceStorageInner {
                root,
                open: DashMap::new(),
                max_idle,
                max_active,
                active_total: AtomicUsize::new(0),
                planes,
                assignments,
                fences,
                backend,
                fsync,
                uses: AtomicU64::new(0),
            }),
        }
    }

    pub(crate) fn root(&self) -> &Path {
        &self.inner.root
    }

    /// Another handle on the same storage.
    pub(super) fn share(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// The slot of `id`, created closed when the cache holds none.
    pub(super) fn slot(&self, id: &[u8; 16]) -> Arc<Slot> {
        Arc::clone(self.inner.open.entry(*id).or_default().value())
    }

    /// The planes this storage resolves assignments against.
    pub fn planes(&self) -> &Arc<ControlPlanes> {
        &self.inner.planes
    }

    /// Every namespace with storage on disk, by identity. Bounded by the
    /// directory listing; used by the index repair, which rebuilds every
    /// namespace's derived indexes.
    pub(crate) fn on_disk(&self) -> Result<Vec<[u8; 16]>, StoreError> {
        let dir = self.inner.root.join("namespaces");
        let mut ids = Vec::new();
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(ids),
            Err(error) => return Err(StoreError::Io(error)),
        };
        for entry in entries {
            let entry = entry?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            let Ok(bytes) = hex::decode(&name) else {
                continue;
            };
            let Ok(id) = <[u8; 16]>::try_from(bytes.as_slice()) else {
                continue;
            };
            if NamespaceController::database_path(&entry.path()).exists() {
                ids.push(id);
            }
        }
        ids.sort_unstable();
        Ok(ids)
    }

    /// The controller of `id` if it is open. Opening is admission's
    /// (`storage_handles`); write helpers inside an execution find it here.
    pub(crate) fn open_controller(&self, id: &[u8; 16]) -> Option<Arc<NamespaceController>> {
        let slot = self.inner.open.get(id).map(|slot| Arc::clone(&slot))?;
        let held = slot.lock().ok()?;
        held.controller().cloned()
    }

    /// The assignment `controller`'s database admits, if any.
    pub(crate) fn admitted_assignment(
        &self,
        controller: &NamespaceController,
    ) -> Result<Option<AssignmentRecord>, StoreError> {
        self.inner
            .assignments
            .assignment(&controller.id, &controller.db)
    }

    /// Apply an admitted assignment epoch to an open controller, from the
    /// record its database now holds; a controller not open resolves it
    /// at its next open. A controller whose record cannot be installed is
    /// marked stale, whichever path found out (commit, settlement or
    /// admission), so no path admits under the previous authority; a
    /// successful installation clears the mark. The installation runs on a
    /// retained controller outside the slot lock: the retained reference
    /// refuses removal meanwhile (`remove_recorded` requires the slot's to
    /// be the only one), and a controller evicted meanwhile resolves the
    /// admitted record again at its next open.
    pub(crate) fn reassigned(&self, id: &[u8; 16]) -> Result<(), StoreError> {
        let slot = self.inner.open.get(id).map(|slot| Arc::clone(&slot));
        let Some(slot) = slot else {
            return Ok(());
        };
        let Some(controller) = slot.lock()?.controller().cloned() else {
            return Ok(());
        };
        let installed = self.install_admitted(&controller);
        controller.set_assignment_stale(installed.is_err());
        installed
    }

    fn install_admitted(&self, controller: &NamespaceController) -> Result<(), StoreError> {
        let record = self
            .inner
            .assignments
            .assignment(&controller.id, &controller.db)?
            .ok_or_else(|| StoreError::Rejected("namespace admitted no assignment".into()))?;
        let plane = self.inner.planes.plane_for(Some(&record))?;
        controller.reassign(plane, record.generation);
        Ok(())
    }

    /// Open the storage of `id` while no controller holds it (the caller
    /// holds its slot, so none can be opened meanwhile), to read the
    /// instance it records. Opening may repair a database whose last close
    /// was not clean (`redb::Database::new`); that writes nothing a
    /// committed transaction did not. A database a closing handle still
    /// holds is refused by redb (`DatabaseAlreadyOpen`), never shared.
    pub(super) fn open_closed(&self, id: &[u8; 16]) -> ClosedStorage {
        let path = NamespaceController::database_path(&NamespaceController::directory(
            &self.inner.root,
            id,
        ));
        if !path.exists() {
            return ClosedStorage::Absent;
        }
        let unopenable = |error: StoreError| ClosedStorage::Unopenable {
            length: std::fs::metadata(&path).map_or(u64::MAX, |metadata| metadata.len()),
            error,
        };
        let opened = self
            .inner
            .backend
            .as_ref()
            .and_then(|factory| factory(id))
            .map_or_else(
                || Database::open(&path).map_err(crate::error::redb),
                |backend| {
                    Database::builder()
                        .create_with_backend(crate::backend::OwnedBackend(backend))
                        .map_err(crate::error::redb)
                },
            );
        let db = match opened {
            Ok(db) => db,
            Err(error) => return unopenable(error),
        };
        match NamespaceController::recorded_instance(&db, *id, &path) {
            Ok(instance) => ClosedStorage::Database { db, instance },
            Err(error) => unopenable(error),
        }
    }

    pub(crate) fn namespace_ref(id: [u8; 16]) -> NamespaceRef {
        NamespaceRef::resolved(id, hex::encode(id), None)
    }
}

/// What a removal finds of the storage it would remove, read under the
/// slot it holds.
pub enum StorageEvidence<'a> {
    /// The open controller, idle and held by nothing else.
    Open(&'a NamespaceController),
    /// A database no controller held, opened to read its instance.
    Closed {
        instance: StorageInstance,
        db: &'a Database,
    },
    /// A database file that could not be opened or names no readable
    /// instance: partially created, damaged, or still held by a closing
    /// handle. `length` is the file's size.
    Unopenable { length: u64, error: &'a StoreError },
    /// No database file.
    Absent,
}

impl<'a> StorageEvidence<'a> {
    /// The evidence of an open, idle `controller`, or else of the storage
    /// `closed` opened without one.
    pub(super) const fn of(
        controller: Option<&'a NamespaceController>,
        closed: Option<&'a ClosedStorage>,
    ) -> Self {
        match (controller, closed) {
            (Some(controller), _) => Self::Open(controller),
            (None, Some(ClosedStorage::Database { db, instance })) => Self::Closed {
                instance: *instance,
                db,
            },
            (None, Some(ClosedStorage::Unopenable { length, error })) => Self::Unopenable {
                length: *length,
                error,
            },
            (None, Some(ClosedStorage::Absent) | None) => Self::Absent,
        }
    }

    /// The instance the storage records, when it could be read.
    pub(crate) const fn instance(&self) -> Option<StorageInstance> {
        match self {
            Self::Open(controller) => Some(controller.instance),
            Self::Closed { instance, .. } => Some(*instance),
            Self::Unopenable { .. } | Self::Absent => None,
        }
    }

    /// The storage's database, when it could be opened.
    pub(crate) fn database(&self) -> Option<&Database> {
        match self {
            Self::Open(controller) => Some(&controller.db),
            Self::Closed { db, .. } => Some(db),
            Self::Unopenable { .. } | Self::Absent => None,
        }
    }
}

/// Storage of a namespace opened outside any controller.
pub(super) enum ClosedStorage {
    Database {
        db: Database,
        instance: StorageInstance,
    },
    Unopenable {
        length: u64,
        error: StoreError,
    },
    Absent,
}
