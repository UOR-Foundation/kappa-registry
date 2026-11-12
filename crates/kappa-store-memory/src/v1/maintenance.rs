//! Physical maintenance of the content cache.
//!
//! An allocation's file is owned by its lifecycle record from before the
//! file reaches its path until it is removed (`allocation`): views,
//! readers and preparations hold the allocation, and the last handle's drop
//! makes the file owed. A step first discharges owed files from the
//! lifecycle queue, which needs no listing; the rest of its budget walks
//! the cache to find files no record of this table explains: residue of an
//! earlier process over the same root, or files left by a failure between
//! a record's discharge and its removal. The store owns its blob root
//! exclusively, so another table's file is never live.
//!
//! Every cleanup attempt and every walk move is admitted before it is
//! made: the step's deadline is checked and the entry, and any directory
//! handle it opens, charged first. Running out of budget ends the step
//! with what it did and its continuation; only a storage failure is an
//! error.
//!
//! The walk is depth-first over the layout's directories
//! (`cache_layout::DIRECTORY_DEPTH` levels under the root), holding one
//! open listing per level and nothing else: no queue of sibling paths. Its
//! retained state is therefore bounded by the layout, at most
//! `DIRECTORY_DEPTH + 1` open listings and one deferred directory path, and
//! a directory deeper than the layout is reported, never entered. A
//! directory found but not yet admitted is held as the deferred path and
//! opened first when the walk resumes, so a refused admission skips
//! nothing.
//!
//! Coverage is what the retained traversal returns: a pass processes the
//! entries its open directory listings yield, under the platform's
//! directory-iteration semantics while other writers create and remove
//! files. Nothing is decided from the traversal alone: each file is decided
//! on its own, when it is examined, from its path (`cache_layout`) and this
//! table's records, and residue the traversal did not return is found by a
//! later pass. A file of this table is decided against its record without
//! a race: the record is created before the file reaches its path and
//! removed only after the file is gone, so a file of this table without a
//! record is never one a live allocation may still open.

use std::fs::{DirEntry, ReadDir};
use std::path::PathBuf;
use std::sync::Arc;

use kappa_store::traits::maintenance::{
    Continuation, ContinuationScope, IndexRepair, MaintenanceOperation, MaintenanceStore, Progress,
    Reclamation, Settlement,
};
use kappa_types::capacity::{CapacityError, Reservation};
use kappa_types::error::StoreError;
use kappa_types::work::{Dimension, Work, WorkExhausted, WorkLimit, WorkMeter};

use super::InMemoryStore;
use super::cache_layout::{CacheEntry, DIRECTORY_DEPTH, classify};

/// Bytes the one deferred directory path of a walk may occupy: Linux's
/// `PATH_MAX` (`include/uapi/linux/limits.h`), the longest path a
/// directory can be opened by, including its terminator. A conservative
/// allowance with that basis, reserved once per walk, not a measurement.
pub const DEFERRED_PATH_ALLOWANCE: u64 = 4096;

/// Where the bounded inventory stands: the open listing of every level from
/// the root down to the directory being read, and a directory found but
/// not yet admitted. The resume state of a reclamation continuation.
///
/// It owns everything its suspension needs, all installed before its first
/// listing is opened (`InMemoryStore::begin_walk`): the filesystem scope
/// the listings read, so the directory outlives them even after the store
/// is dropped; one reserved handle per open listing; and the deferred-path
/// allowance. Fields drop in declaration order: the listings close first,
/// then the reservations release, then the filesystem scope. Dropping the
/// walk cancels the pass; owed cleanup is the allocation table's and is not
/// affected.
///
/// What is measured and what is not: open listings are counted exactly
/// (`handles`); the deferred path is held within its allowance (`paths`);
/// the platform's directory-stream buffers behind each listing are not
/// measured in bytes and are accounted only as the listing's handle.
#[derive(Default)]
struct InventoryWalk {
    /// Open listings, root first; at most `DIRECTORY_DEPTH + 1`.
    stack: Vec<ReadDir>,
    /// A directory read from the deepest listing whose opening was not yet
    /// admitted.
    deferred: Option<PathBuf>,
    /// Whether the pass has begun.
    started: bool,
    /// One unit of the store's maintenance handle pool per open listing.
    handles: Option<Reservation>,
    /// `DEFERRED_PATH_ALLOWANCE` of the store's maintenance byte pool.
    paths: Option<Reservation>,
    /// The filesystem scope the listings read. Declared last: dropped
    /// after the listings.
    owner: Option<Arc<dyn Send + Sync>>,
}

/// One move of the walk.
enum Next {
    File(DirEntry),
    /// A directory was entered or left, or a stranger directory reported.
    Stepped,
    /// The whole cache was walked.
    Finished,
}

/// Why a step stopped short of its end: the step's budget or the retained
/// capacity it may hold (the walk pauses), or the storage (the step fails).
enum Halt {
    Work(WorkExhausted),
    Capacity(CapacityError),
    Store(StoreError),
}

impl From<WorkExhausted> for Halt {
    fn from(error: WorkExhausted) -> Self {
        Self::Work(error)
    }
}

impl From<CapacityError> for Halt {
    fn from(error: CapacityError) -> Self {
        Self::Capacity(error)
    }
}

impl From<StoreError> for Halt {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

impl From<std::io::Error> for Halt {
    fn from(error: std::io::Error) -> Self {
        Self::Store(error.into())
    }
}

impl InMemoryStore {
    fn scope(&self, operation: MaintenanceOperation) -> ContinuationScope {
        ContinuationScope {
            store: self.instance.clone(),
            operation,
        }
    }

    /// Install what a walk owns before it opens anything: the filesystem
    /// scope its listings will read, then its deferred-path allowance. A
    /// refused allowance leaves the walk unstarted.
    fn begin_walk(&self, walk: &mut InventoryWalk) -> Result<(), Halt> {
        walk.owner.clone_from(&self.resource_owner);
        walk.paths = Some(self.maintenance_bytes.reserve(DEFERRED_PATH_ALLOWANCE)?);
        walk.handles = Some(self.maintenance_handles.reserve(0)?);
        walk.started = true;
        Ok(())
    }

    /// Open `dir` as the next level of the walk: its listing's handle
    /// reserved and its opening charged first. A refused reservation or
    /// charge leaves `dir` deferred (within the walk's path allowance); a
    /// directory deeper than the layout is reported and not entered.
    fn enter(
        &self,
        walk: &mut InventoryWalk,
        dir: PathBuf,
        meter: &mut WorkMeter,
        into: &mut Reclamation,
    ) -> Result<Next, Halt> {
        // The root is level 0; the layout's directories are levels 1 to
        // DIRECTORY_DEPTH.
        if walk.stack.len() > DIRECTORY_DEPTH {
            tracing::warn!(path = %dir.display(), "directory deeper than the content cache layout");
            into.unrecognized += 1;
            return Ok(Next::Stepped);
        }
        if dir.as_os_str().len() as u64 >= DEFERRED_PATH_ALLOWANCE {
            return Err(Halt::Store(StoreError::Internal(format!(
                "content cache path {} exceeds the platform path limit",
                dir.display()
            ))));
        }
        let handle = match self.maintenance_handles.reserve(1) {
            Ok(handle) => handle,
            Err(refused) => {
                walk.deferred = Some(dir);
                return Err(Halt::Capacity(refused));
            }
        };
        if let Err(exhausted) = meter.charge(Dimension::Handles, 1) {
            walk.deferred = Some(dir);
            return Err(Halt::Work(exhausted));
        }
        match std::fs::read_dir(&dir) {
            Ok(entries) => {
                walk.stack.push(entries);
                match walk.handles.as_mut() {
                    Some(handles) => handles.merge(handle)?,
                    None => walk.handles = Some(handle),
                }
            }
            // The reserved handle drops unused.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                walk.deferred = Some(dir);
                return Err(error.into());
            }
        }
        Ok(Next::Stepped)
    }

    /// Close the deepest listing, then release its handle.
    fn leave(walk: &mut InventoryWalk) -> Result<(), Halt> {
        walk.stack.pop();
        let open = walk.stack.len() as u64;
        if let Some(handles) = walk.handles.as_mut() {
            handles.shrink(open)?;
        }
        Ok(())
    }

    /// The next move of the walk, charging one entry examined, and one
    /// handle for a directory it opens, before doing it. A refused charge
    /// leaves the walk where it was.
    fn next_file(
        &self,
        walk: &mut InventoryWalk,
        meter: &mut WorkMeter,
        into: &mut Reclamation,
    ) -> Result<Next, Halt> {
        meter.charge(Dimension::Entries, 1)?;
        if let Some(dir) = walk.deferred.take() {
            return self.enter(walk, dir, meter, into);
        }
        if !walk.started {
            self.begin_walk(walk)?;
            return self.enter(walk, self.allocations.root().to_path_buf(), meter, into);
        }
        let Some(entries) = walk.stack.last_mut() else {
            return Ok(Next::Finished);
        };
        let Some(entry) = entries.next() else {
            Self::leave(walk)?;
            return Ok(Next::Stepped);
        };
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            return self.enter(walk, entry.path(), meter, into);
        }
        Ok(Next::File(entry))
    }

    /// Decide one file: a file this table's records own and a preparation
    /// of this table are left in place; residue is removed; a path the
    /// layout does not explain is reported.
    fn examine_file(&self, entry: &DirEntry, into: &mut Reclamation) {
        let path = entry.path();
        let nonce = self.allocations.nonce();
        match classify(self.allocations.root(), &path) {
            CacheEntry::Temporary { table: Some(table) } if table == nonce => {
                into.protected += 1;
                return;
            }
            CacheEntry::Instance {
                storage,
                table,
                instance,
            } if table == nonce && self.allocations.accounts_for(&storage, instance) => {
                into.owned += 1;
                return;
            }
            CacheEntry::Stranger => {
                tracing::warn!(path = %path.display(), "unrecognized entry in the content cache");
                into.unrecognized += 1;
                return;
            }
            CacheEntry::Temporary { .. } | CacheEntry::Instance { .. } => {}
        }
        let bytes = match entry.metadata() {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                into.absent += 1;
                return;
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "cache residue could not be examined");
                into.failed += 1;
                return;
            }
        };
        match std::fs::remove_file(&path) {
            Ok(()) => {
                into.files += 1;
                into.bytes = into.bytes.saturating_add(bytes);
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => into.absent += 1,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "cache residue removal failed");
                into.failed += 1;
            }
        }
    }

    /// Discharge owed files one attempt at a time, each admitted first; an
    /// empty queue costs nothing. Returns whether the queue was drained
    /// (`false`: the budget ended the discharge first).
    fn discharge_owed(&self, meter: &mut WorkMeter, into: &mut Reclamation) -> bool {
        loop {
            if !self.allocations.owes() {
                return true;
            }
            if meter.charge(Dimension::Entries, 1).is_err() {
                return false;
            }
            let attempt = self.allocations.discharge(1);
            let attempted = attempt
                .files
                .saturating_add(attempt.absent)
                .saturating_add(attempt.retained);
            // Another step drained the queue between the check and the
            // attempt.
            if attempted == 0 {
                return true;
            }
            into.files = into.files.saturating_add(attempt.files);
            into.bytes = into.bytes.saturating_add(attempt.bytes);
            into.absent = into.absent.saturating_add(attempt.absent);
            into.failed = into.failed.saturating_add(attempt.retained);
            // A removal that failed stays owed and is requeued; retrying it
            // within this step would spend the step on one stuck file. The
            // step moves on to the walk and a later step retries it.
            if attempt.retained > 0 {
                return true;
            }
        }
    }
}

impl MaintenanceStore for InMemoryStore {
    /// Owed files first, then the walk, within `limit` together (see the
    /// module documentation).
    fn reclaim_unowned(
        &self,
        limit: &WorkLimit,
        from: Option<Continuation>,
    ) -> Result<Progress<Reclamation>, StoreError> {
        let scope = self.scope(MaintenanceOperation::Reclaim);
        let mut walk = from
            .map(|continuation| continuation.into_state::<InventoryWalk>(&scope))
            .transpose()?
            .unwrap_or_default();
        let mut meter = WorkMeter::new(*limit);
        let mut reclamation = Reclamation::default();
        let paused = |outcome, meter: &WorkMeter, walk| Progress {
            outcome,
            consumed: *meter.used(),
            continuation: Some(Continuation::new(scope, walk)),
        };
        if !self.discharge_owed(&mut meter, &mut reclamation) {
            return Ok(paused(reclamation, &meter, walk));
        }
        loop {
            match self.next_file(&mut walk, &mut meter, &mut reclamation) {
                Ok(Next::File(entry)) => self.examine_file(&entry, &mut reclamation),
                Ok(Next::Stepped) => {}
                Ok(Next::Finished) => {
                    return Ok(Progress {
                        outcome: reclamation,
                        consumed: *meter.used(),
                        continuation: None,
                    });
                }
                Err(Halt::Work(exhausted)) => {
                    tracing::debug!(%exhausted, "reclamation paused at its work budget");
                    return Ok(paused(reclamation, &meter, walk));
                }
                Err(Halt::Capacity(refused)) => {
                    tracing::debug!(%refused, "reclamation paused at its retained capacity");
                    return Ok(paused(reclamation, &meter, walk));
                }
                Err(Halt::Store(error)) => return Err(error),
            }
        }
    }

    /// Memory has no separately lagging persistent index to rebuild: its
    /// publication paths maintain each derived index in the same candidate
    /// view as the rows it indexes, and independent reconstruction in
    /// qualification checks that correspondence. A step admitted by
    /// `limit` reports a complete empty pass.
    fn repair_indexes(
        &self,
        limit: &WorkLimit,
        from: Option<Continuation>,
    ) -> Result<Progress<IndexRepair>, StoreError> {
        self.admit_empty(MaintenanceOperation::RepairIndexes, limit, from)
    }

    /// Memory has no deferred projection work: each publication registers
    /// its projection changes before its view is stored. A step admitted by
    /// `limit` reports a complete empty pass.
    fn settle(
        &self,
        limit: &WorkLimit,
        from: Option<Continuation>,
    ) -> Result<Progress<Settlement>, StoreError> {
        self.admit_empty(MaintenanceOperation::Settle, limit, from)
    }
}

impl InMemoryStore {
    /// A pass with no work: the deadline checked, any continuation refused
    /// (these passes never return one, so one offered is not of this pass),
    /// and a complete result with nothing consumed.
    fn admit_empty<T: Default>(
        &self,
        operation: MaintenanceOperation,
        limit: &WorkLimit,
        from: Option<Continuation>,
    ) -> Result<Progress<T>, StoreError> {
        WorkMeter::new(*limit).check_deadline()?;
        if let Some(continuation) = from {
            continuation.into_state::<()>(&self.scope(operation))?;
            return Err(StoreError::Rejected(format!(
                "{operation:?} returns no continuation; one offered is not of this pass"
            )));
        }
        Ok(Progress {
            outcome: T::default(),
            consumed: Work::default(),
            continuation: None,
        })
    }
}

#[cfg(test)]
#[path = "maintenance_tests.rs"]
mod tests;
