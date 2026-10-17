//! Physical allocations: one file per allocation instance in the content
//! cache, deduplicated by storage identity, owned by the handles that may
//! still read it.
//!
//! An allocation instance is distinct from the logical identity it stores.
//! Its file lives at `{content path}.{table}-{instance}`, where `table` is
//! a random nonce drawn when the table is created, so two instances of one
//! identity never share a path, in this process or across processes over
//! the same root: the cleanup of an instance that lost its last handle
//! removes exactly its own file, never the file of a later instance that
//! reused the identity. Preparation files are `.tmp{table}` followed by
//! the temporary file's random suffix. The store owns its blob root
//! exclusively, so a file of another table is residue of an earlier
//! process.
//!
//! Every instance has one lifecycle record from before it is exposed until
//! its file is gone:
//!
//! ```text
//! Live -> Pending -> Deleting -> (discharged)
//!                 <- (removal failed)
//! ```
//!
//! The record holds the instance's charge, its path and identity. It is
//! created, and queue capacity for its removal ticket reserved, when the
//! instance is created; the queue's capacity always covers every
//! outstanding record, whatever its state. Dropping the last handle only
//! changes its record's state and enqueues the ticket into that reserved
//! capacity: no map insertion, no clone, no allocation, and no index lock,
//! so a handle may be dropped anywhere, including while an index shard is
//! held. A removal that fails returns its record to `Pending`; the charge is
//! released only when the file is removed or found gone.
//!
//! The lifecycle registry and the filesystem scope's owner are shared by
//! the table and every instance, so a handle that outlives the store keeps
//! the directory it reads from and the records owing its file. When the
//! last of them drops, the registry removes every file it still owes; a
//! removal that fails then passes to the process's abandoned-file owner
//! ([`abandoned`]), which every later discharge retries.
//!
//! Deduplication is the `instances` index: identity to the live instance.
//! Acquisition takes the identity's shard for the lookup-and-upgrade only;
//! file creation happens before it and removal after it, outside any shard.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::hash::{BuildHasher, Hasher, RandomState};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use dashmap::DashMap;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;

use super::cache_layout;
use super::segments::Segments;

/// What every instance shares with the table: the lifecycle registry and
/// the owner of the directory the files are in. Declared in that order so
/// the registry removes what it owes while the directory still exists.
struct Shared {
    registry: Registry,
    _owner: Option<Arc<dyn Send + Sync>>,
}

/// A live allocation instance. Cloning shares ownership; the file stays
/// until every clone has dropped.
#[derive(Clone)]
pub struct Allocation(Arc<Instance>);

struct Instance {
    /// The instance number: its lifecycle record and its file name.
    id: u64,
    storage: Kappa,
    path: PathBuf,
    bytes: u64,
    /// Segment digests of the file's bytes (`segments`).
    segments: Segments,
    shared: Arc<Shared>,
}

impl Drop for Instance {
    fn drop(&mut self) {
        self.shared.registry.release(self.id);
    }
}

impl Allocation {
    pub fn storage(&self) -> &Kappa {
        &self.0.storage
    }

    pub fn path(&self) -> &Path {
        &self.0.path
    }

    pub fn bytes(&self) -> u64 {
        self.0.bytes
    }

    /// Segment digests of the file's bytes.
    pub fn segments(&self) -> &Segments {
        &self.0.segments
    }

    #[cfg(test)]
    pub fn instance(&self) -> u64 {
        self.0.id
    }

    /// Whether two handles name the same instance.
    pub fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl std::fmt::Debug for Allocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Allocation")
            .field("instance", &self.0.id)
            .field("storage", &self.0.storage.to_string())
            .field("bytes", &self.0.bytes)
            .finish()
    }
}

impl PartialEq for Allocation {
    fn eq(&self, other: &Self) -> bool {
        self.same(other)
    }
}

impl Eq for Allocation {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Live,
    Pending,
    Deleting,
}

struct Record {
    storage: Kappa,
    path: PathBuf,
    bytes: u64,
    state: State,
}

#[derive(Default)]
struct Lifecycle {
    records: BTreeMap<u64, Record>,
    /// Instances waiting for a removal attempt. Capacity always covers
    /// every record.
    pending: VecDeque<u64>,
    /// Bytes of every record: live allocations and owed files.
    charged: u64,
    /// Bytes of records whose file is owed.
    owed: u64,
}

#[derive(Default)]
struct Registry {
    state: Mutex<Lifecycle>,
}

impl Registry {
    // The registry's state is consistent after every statement, so a lock
    // a panicking thread poisoned is still usable.
    fn lock(&self) -> MutexGuard<'_, Lifecycle> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Create the record of a new instance, reserving its ticket's queue
    /// capacity and charging its bytes.
    fn create(
        &self,
        instance: u64,
        storage: &Kappa,
        path: &Path,
        bytes: u64,
    ) -> Result<(), StoreError> {
        let mut state = self.lock();
        let lifecycle = &mut *state;
        let needed =
            lifecycle.records.len().checked_add(1).ok_or_else(|| {
                StoreError::CapacityExceeded("allocation records exhausted".into())
            })?;
        let additional = needed.saturating_sub(lifecycle.pending.len());
        lifecycle
            .pending
            .try_reserve(additional)
            .map_err(|error| StoreError::CapacityExceeded(format!("cleanup queue: {error}")))?;
        lifecycle.charged = lifecycle
            .charged
            .checked_add(bytes)
            .ok_or_else(|| StoreError::CapacityExceeded("allocation charge overflows".into()))?;
        lifecycle.records.insert(
            instance,
            Record {
                storage: storage.clone(),
                path: path.to_path_buf(),
                bytes,
                state: State::Live,
            },
        );
        drop(state);
        Ok(())
    }

    /// The last handle of `instance` dropped: its file is now owed.
    fn release(&self, instance: u64) {
        let mut state = self.lock();
        let lifecycle = &mut *state;
        if let Some(record) = lifecycle.records.get_mut(&instance)
            && record.state == State::Live
        {
            record.state = State::Pending;
            lifecycle.owed = lifecycle.owed.saturating_add(record.bytes);
            lifecycle.pending.push_back(instance);
        }
        drop(state);
    }
}

impl Drop for Registry {
    fn drop(&mut self) {
        // Every handle and the table are gone: nothing can read these files.
        // Remove them now, while the directory's owner (dropped after the
        // registry) still keeps the directory; a removal that fails passes
        // to the abandoned-file owner.
        let state = self.state.get_mut().unwrap_or_else(PoisonError::into_inner);
        for record in std::mem::take(&mut state.records).into_values() {
            match fs::remove_file(&record.path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::warn!(path = %record.path.display(), %error, "allocation file passed to the abandoned-file owner");
                    abandoned_lock().push(record.path);
                }
            }
        }
    }
}

/// Files whose registry ended with their removal failed.
static ABANDONED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

fn abandoned_lock() -> MutexGuard<'static, Vec<PathBuf>> {
    ABANDONED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What one cleanup step did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Discharged {
    pub files: u64,
    pub bytes: u64,
    /// Obligations whose file was already gone.
    pub absent: u64,
    /// Obligations whose removal failed and stay owed.
    pub retained: u64,
}

/// The deduplication index and the lifecycle registry of one store.
pub struct AllocationTable {
    root: PathBuf,
    nonce: u64,
    instances: DashMap<Kappa, (u64, Weak<Instance>)>,
    next: AtomicU64,
    shared: Arc<Shared>,
}

impl AllocationTable {
    /// The table of the cache at `root`, retaining `owner` (the filesystem
    /// scope containing `root`) for as long as any allocation or owed file
    /// remains.
    pub fn new(root: PathBuf, owner: Option<Arc<dyn Send + Sync>>) -> Self {
        // Randomly keyed by the standard library for every new state.
        let nonce = RandomState::new().build_hasher().finish();
        Self {
            root,
            nonce,
            instances: DashMap::new(),
            next: AtomicU64::new(1),
            shared: Arc::new(Shared {
                registry: Registry::default(),
                _owner: owner,
            }),
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// This table's nonce, which names every file it creates.
    pub const fn nonce(&self) -> u64 {
        self.nonce
    }

    fn instance_path(&self, storage: &Kappa, instance: u64) -> Result<PathBuf, StoreError> {
        cache_layout::instance_path(&self.root, storage, self.nonce, instance)
    }

    /// The live instance of `storage`, if any.
    pub fn existing(&self, storage: &Kappa) -> Option<Allocation> {
        self.instances
            .get(storage)
            .and_then(|entry| entry.1.upgrade())
            .map(Allocation)
    }

    /// The allocation holding `staged`'s bytes under `storage`: the live
    /// instance when one exists (the staged file is then discarded), or a
    /// new instance the staged file becomes. Content addressing makes the
    /// bytes of every instance of one identity equal; callers verified
    /// `staged` against `storage` before calling and computed `segments`
    /// from the bytes they verified.
    pub fn install(
        &self,
        storage: &Kappa,
        staged: tempfile::NamedTempFile,
        segments: Segments,
    ) -> Result<Allocation, StoreError> {
        if let Some(existing) = self.existing(storage) {
            return Ok(existing);
        }
        let instance = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| StoreError::CapacityExceeded("allocation instances exhausted".into()))?;
        let path = self.instance_path(storage, instance)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let bytes = staged.as_file().metadata()?.len();
        if bytes != segments.length() {
            return Err(StoreError::Internal(format!(
                "staged {storage} holds {bytes} bytes where its segments cover {}",
                segments.length()
            )));
        }
        // The record exists, its ticket capacity reserved, before the file
        // reaches its path; a failed persist leaves a record whose file is
        // owed (and absent), which the next discharge settles.
        self.shared
            .registry
            .create(instance, storage, &path, bytes)?;
        let created = Allocation(Arc::new(Instance {
            id: instance,
            storage: storage.clone(),
            path: path.clone(),
            bytes,
            segments,
            shared: Arc::clone(&self.shared),
        }));
        staged
            .persist_noclobber(&path)
            .map_err(|error| StoreError::Io(error.error))?;
        // The shard is held only to decide which instance survives. The
        // losing handle drops after the shard is released and owes its own
        // file.
        let mut entry = self
            .instances
            .entry(storage.clone())
            .or_insert_with(|| (instance, Arc::downgrade(&created.0)));
        let chosen = if let Some(live) = entry.1.upgrade() {
            Allocation(live)
        } else {
            *entry = (instance, Arc::downgrade(&created.0));
            created.clone()
        };
        drop(entry);
        drop(created);
        Ok(chosen)
    }

    /// Stage `bytes`, which the caller verified as `storage`, and install
    /// them under `storage`.
    pub fn install_bytes(&self, storage: &Kappa, bytes: &[u8]) -> Result<Allocation, StoreError> {
        if let Some(existing) = self.existing(storage) {
            return Ok(existing);
        }
        let mut staged = self.staging_file()?;
        std::io::Write::write_all(&mut staged, bytes)?;
        self.install(storage, staged, Segments::of(bytes))
    }

    /// A private temporary file in the cache for a preparation, named by
    /// this table so an inventory tells it from an earlier process's.
    pub fn staging_file(&self) -> Result<tempfile::NamedTempFile, StoreError> {
        let prefix = cache_layout::staging_prefix(self.nonce);
        Ok(tempfile::Builder::new()
            .prefix(&prefix)
            .tempfile_in(&self.root)?)
    }

    /// Owed files and their bytes, those being removed included.
    #[cfg(test)]
    pub fn owed(&self) -> (usize, u64) {
        let state = self.shared.registry.lock();
        let owed = state
            .records
            .values()
            .filter(|record| record.state != State::Live)
            .count();
        (owed, state.owed)
    }

    /// Attempt at most `limit` removals, abandoned files of ended
    /// registries first, each owed file at most once per call. A record
    /// stays charged while its removal runs; success or established absence
    /// discharges it, failure returns it to `Pending` and requeues its
    /// ticket after this call's attempts, for a later call.
    pub fn discharge(&self, limit: usize) -> Discharged {
        let mut done = Discharged::default();
        let mut budget = limit;
        {
            let mut abandoned = abandoned_lock();
            while budget > 0 {
                let Some(path) = abandoned.pop() else {
                    break;
                };
                budget -= 1;
                match fs::remove_file(&path) {
                    Ok(()) => done.files += 1,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => done.absent += 1,
                    Err(_) => {
                        done.retained += 1;
                        abandoned.insert(0, path);
                        break;
                    }
                }
            }
            drop(abandoned);
        }
        let mut failed = Vec::new();
        for _ in 0..budget {
            let ticket = {
                let mut state = self.shared.registry.lock();
                let Some(instance) = state.pending.pop_front() else {
                    break;
                };
                state.records.get_mut(&instance).map(|record| {
                    record.state = State::Deleting;
                    (instance, record.path.clone())
                })
            };
            let Some((instance, path)) = ticket else {
                continue;
            };
            let outcome = match fs::remove_file(&path) {
                Ok(()) => Some(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(false),
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error, "allocation removal failed; kept owed");
                    None
                }
            };
            let mut state = self.shared.registry.lock();
            let lifecycle = &mut *state;
            let storage = if let Some(removed) = outcome {
                lifecycle.records.remove(&instance).map(|record| {
                    lifecycle.charged = lifecycle.charged.saturating_sub(record.bytes);
                    lifecycle.owed = lifecycle.owed.saturating_sub(record.bytes);
                    if removed {
                        done.files += 1;
                        done.bytes = done.bytes.saturating_add(record.bytes);
                    } else {
                        done.absent += 1;
                    }
                    record.storage
                })
            } else {
                if let Some(record) = lifecycle.records.get_mut(&instance) {
                    record.state = State::Pending;
                }
                failed.push(instance);
                done.retained += 1;
                None
            };
            drop(state);
            if let Some(storage) = storage {
                self.instances.remove_if(&storage, |_, (live, weak)| {
                    *live == instance && weak.strong_count() == 0
                });
            }
        }
        if !failed.is_empty() {
            // Within capacity: the queue's capacity covers every record,
            // and these are still outstanding.
            self.shared.registry.lock().pending.extend(failed);
        }
        done
    }

    /// Whether the file of `instance` of `storage` belongs to a record:
    /// a live allocation or a file still owed.
    pub fn accounts_for(&self, storage: &Kappa, instance: u64) -> bool {
        self.shared
            .registry
            .lock()
            .records
            .get(&instance)
            .is_some_and(|record| record.storage == *storage)
    }
}

#[cfg(test)]
#[path = "allocation_tests.rs"]
mod tests;
