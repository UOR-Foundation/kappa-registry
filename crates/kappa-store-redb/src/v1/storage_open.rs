//! Opening a namespace controller: selecting the backend, telling existing
//! storage from absent storage, creating storage for a creation under a
//! durable intent, reading the storage instance it records, and making the
//! directory entries that locate it durable before a creating controller
//! is returned.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
use std::sync::{Arc, Mutex};

use redb::{Database, ReadableDatabase};

use kappa_store::error::StoreError;

use super::{NamespaceController, NamespaceStorageInner, Opening};
use crate::storage_instance::{Incarnation, StorageInstance};
use crate::{creation_intent, tables};

impl NamespaceController {
    /// Open the controller of `id` at `root`, creating the database when
    /// opening for creation and refusing an absent one otherwise. A
    /// database copied under another namespace is refused by its
    /// `NAMESPACE_SELF` row.
    pub(super) fn open(
        storage: &NamespaceStorageInner,
        id: [u8; 16],
        opening: &Opening,
        clock_ms: u64,
    ) -> Result<Self, StoreError> {
        let root = storage.root.as_path();
        let directory = Self::directory(root, &id);
        let path = Self::database_path(&directory);
        let create = matches!(opening, Opening::Create { .. });
        let absent =
            || StoreError::NotFound(format!("namespace {} has no storage", hex::encode(id)));
        // The backend is selected before any existence rule: a custom
        // backend's storage exists when its content records an owner, the
        // file backend's when its database file exists. Existing storage is
        // opened without creating anything; only a creation of absent
        // storage creates, and it records its intent durably first, so
        // storage a failed creation leaves behind always has an owner that
        // recovery visits (`creation_intent`). The intent is handed off to
        // the instance's pending marker (`mark_unsettled`), not completed
        // here: until a marker owns the instance, the intent does.
        let selected = storage.backend.as_ref().and_then(|factory| factory(&id));
        let file_backed = selected.is_none();
        let (db, created) = match selected {
            Some(backend) => {
                let db = Database::builder()
                    .create_with_backend(crate::backend::OwnedBackend(backend))
                    .map_err(crate::error::redb)?;
                if Self::records_owner(&db)? {
                    (db, None)
                } else if create {
                    let instance = StorageInstance::generate(id)?;
                    creation_intent::record(root, &instance)?;
                    (db, Some(instance))
                } else {
                    return Err(absent());
                }
            }
            None if path.exists() => (Database::open(&path).map_err(crate::error::redb)?, None),
            None if create => {
                let instance = StorageInstance::generate(id)?;
                creation_intent::record(root, &instance)?;
                std::fs::create_dir_all(&directory)?;
                (
                    Database::create(&path).map_err(crate::error::redb)?,
                    Some(instance),
                )
            }
            None => return Err(absent()),
        };
        let db = Arc::new(db);
        let instance = match created {
            Some(instance) => {
                Self::initialize(&db, id, &instance)?;
                instance
            }
            None => Self::recorded_instance(&db, id, &path)?,
        };
        // A controller opened for creation is the one that marks the
        // namespace pending and claims it; before it is returned, on a
        // retry as on the first attempt, the directory entries that locate
        // the database are durable, and a failure returns no controller.
        // On the file backend, a marker therefore never precedes locatable
        // storage. A custom backend owns its own durability.
        if create && file_backed {
            sync_directories(&directory, root)?;
        }
        let fenced = Self::fence_path(&directory).exists();
        // The publication fence above is this controller's own commit
        // outcome; a retirement's fence is the slot's lifecycle, entered
        // from the instance's retirement record by admission
        // (`storage_handles::opened`).
        // The admitted assignment decides the plane. A namespace being
        // created has none yet; its creation epoch, decided by the
        // creating plane, admits the first one.
        let admitted = storage.assignments.assignment(&id, &db)?;
        let plane = match (&admitted, opening) {
            (Some(record), _) => Some((storage.planes.plane_for(Some(record))?, record.generation)),
            (None, Opening::Create { plane }) => Some((Arc::clone(plane), 0)),
            (None, Opening::Existing) => None,
        };
        Ok(Self {
            id,
            instance,
            db,
            path,
            publication_fenced: AtomicBool::new(fenced),
            // A fence found on disk is resolvable by this fresh open only
            // when every allocation a commit could name was synced first.
            fence_resolvable: AtomicBool::new(fenced && storage.fsync),
            writer_pins: Mutex::new(Vec::new()),
            installed_rows: Mutex::new(Vec::new()),
            unresolved_content: Mutex::new(crate::unsettled::Parked::default()),
            mutation_seq: AtomicU64::new(0),
            epoch_number: AtomicU64::new(0),
            plane: Mutex::new(plane),
            active: AtomicUsize::new(0),
            last_used: AtomicU64::new(clock_ms),
            pending_pins: Mutex::new(std::collections::BTreeMap::new()),
            assignment_stale: AtomicBool::new(false),
            writer_gate: super::WriterGate::default(),
            head_recovered: AtomicBool::new(false),
        })
    }

    /// One durable transaction per database lifetime: every table, the
    /// owner row and the incarnation exist before the handle is returned.
    fn initialize(
        db: &Database,
        id: [u8; 16],
        instance: &StorageInstance,
    ) -> Result<(), StoreError> {
        let txn = db.begin_write().map_err(crate::error::redb)?;
        tables::create_namespace_tables(&txn).map_err(crate::error::redb)?;
        {
            let mut own = txn
                .open_table(tables::NAMESPACE_SELF)
                .map_err(crate::error::redb)?;
            own.insert(&b"self"[..], id.as_slice())
                .map_err(crate::error::redb)?;
            if let Incarnation::Known(incarnation) = instance.incarnation() {
                own.insert(&b"incarnation"[..], incarnation.as_slice())
                    .map_err(crate::error::redb)?;
            }
        }
        txn.commit().map_err(crate::error::redb)
    }

    /// Whether `db` records an owner: its tables were created. A custom
    /// backend's storage exists exactly when this holds.
    fn records_owner(db: &Database) -> Result<bool, StoreError> {
        let txn = db.begin_read().map_err(crate::error::redb)?;
        match txn.open_table(tables::NAMESPACE_SELF) {
            Ok(own) => Ok(own.get(&b"self"[..]).map_err(crate::error::redb)?.is_some()),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(false),
            Err(error) => Err(crate::error::redb(error)),
        }
    }

    /// The instance an existing database records: it must name `id` as
    /// its owner, and its incarnation is unknown when it predates
    /// incarnations.
    pub(super) fn recorded_instance(
        db: &Database,
        id: [u8; 16],
        path: &Path,
    ) -> Result<StorageInstance, StoreError> {
        let txn = db.begin_read().map_err(crate::error::redb)?;
        let own = txn
            .open_table(tables::NAMESPACE_SELF)
            .map_err(crate::error::redb)?;
        match own.get(&b"self"[..]).map_err(crate::error::redb)? {
            Some(recorded) if recorded.value() != id.as_slice() => {
                return Err(StoreError::Rejected(format!(
                    "namespace storage at {} belongs to {}",
                    path.display(),
                    hex::encode(recorded.value())
                )));
            }
            Some(_) => {}
            None => {
                return Err(StoreError::Rejected(format!(
                    "namespace storage at {} records no owner",
                    path.display()
                )));
            }
        }
        let incarnation = own
            .get(&b"incarnation"[..])
            .map_err(crate::error::redb)?
            .map(|value| value.value().to_vec());
        Ok(StorageInstance::new(
            id,
            StorageInstance::incarnation_from_row(incarnation.as_deref())?,
        ))
    }
}

/// Sync `directory` and every directory above it up to and including
/// `root`, so the entries a creation made survive a crash.
fn sync_directories(directory: &Path, root: &Path) -> Result<(), StoreError> {
    let mut current = Some(directory);
    while let Some(path) = current {
        std::fs::File::open(path)?.sync_all()?;
        if path == root {
            break;
        }
        current = path.parent().filter(|parent| parent.starts_with(root));
    }
    Ok(())
}
