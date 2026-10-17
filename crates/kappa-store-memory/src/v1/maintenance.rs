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
//! The walk is bounded and resumable: a directory stream and the
//! directories still to visit are kept between steps, each step examines
//! at most its limit of entries, and each file is decided on its own from
//! its path (`cache_layout`) and this table's records. No listing of the
//! cache and no set of owned paths is built.
//!
//! A file of this table is decided against its record without a race: the
//! record is created before the file reaches its path and removed only
//! after the file is gone, so a file of this table without a record is
//! never one a live allocation may still open.

use std::fs::{DirEntry, ReadDir};
use std::path::PathBuf;

use kappa_store::traits::maintenance::{IndexRepair, MaintenanceStore, Reclamation};
use kappa_types::error::StoreError;

use super::InMemoryStore;
use super::cache_layout::{CacheEntry, classify};

/// Where the bounded inventory stands: the directory stream being read
/// and the directories found but not yet entered. Empty at the start of a
/// pass.
#[derive(Default)]
pub struct InventoryWalk {
    current: Option<ReadDir>,
    /// Directories found and not yet entered. The cache layout is three
    /// levels of fan-out under the root, so this holds at most one level's
    /// listing at a time, never the file population.
    pending: Vec<PathBuf>,
    /// Whether the pass has begun (the root was entered).
    started: bool,
    /// Whether the pass walked the whole cache.
    finished: bool,
}

impl InMemoryStore {
    /// The next entry of the walk: a regular file, or `None` when the walk
    /// entered a directory or ended a listing and consumed one unit of the
    /// step's limit doing so. `Ok(None)` with `walk.finished` set once the
    /// whole cache has been walked.
    fn next_file(&self, walk: &mut InventoryWalk) -> Result<Option<DirEntry>, std::io::Error> {
        if !walk.started {
            walk.started = true;
            walk.pending.push(self.allocations.root().to_path_buf());
        }
        loop {
            if let Some(entries) = walk.current.as_mut() {
                match entries.next() {
                    Some(entry) => {
                        let entry = entry?;
                        if entry.file_type()?.is_dir() {
                            walk.pending.push(entry.path());
                            return Ok(None);
                        }
                        return Ok(Some(entry));
                    }
                    None => walk.current = None,
                }
            }
            let Some(dir) = walk.pending.pop() else {
                walk.finished = true;
                return Ok(None);
            };
            match std::fs::read_dir(&dir) {
                Ok(entries) => walk.current = Some(entries),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
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
}

impl MaintenanceStore for InMemoryStore {
    /// Owed files first, then the walk, within `limit` entries together.
    fn reclaim_unowned(&self, limit: usize) -> Result<Reclamation, StoreError> {
        let mut reclamation = Reclamation::default();
        let discharged = self.allocations.discharge(limit);
        reclamation.files = discharged.files;
        reclamation.bytes = discharged.bytes;
        reclamation.absent = discharged.absent;
        reclamation.failed = discharged.retained;
        let used = discharged
            .files
            .saturating_add(discharged.absent)
            .saturating_add(discharged.retained);
        let mut remaining = limit.saturating_sub(usize::try_from(used).unwrap_or(usize::MAX));
        let mut walk = self
            .inventory
            .lock()
            .map_err(|_| StoreError::Internal("inventory walk lock poisoned".into()))?;
        // Every entry the walk meets, directory or file, counts against the
        // limit, so a step's work is bounded whatever the cache holds.
        while remaining > 0 {
            remaining -= 1;
            match self.next_file(&mut walk)? {
                Some(entry) => self.examine_file(&entry, &mut reclamation),
                None if walk.finished => {
                    reclamation.complete = true;
                    *walk = InventoryWalk::default();
                    break;
                }
                None => {}
            }
        }
        drop(walk);
        Ok(reclamation)
    }

    /// The reference indexes (`references`, `selected_by`, the edge and
    /// identity indexes) are part of each namespace view, written in the
    /// same candidate as the rows they index; a writer that finds one
    /// inconsistent refuses the publication. They cannot diverge from the
    /// view they are published in, so there is never anything to rebuild.
    fn repair_indexes(&self) -> Result<IndexRepair, StoreError> {
        Ok(IndexRepair::default())
    }

    /// Projections are registered by each publication before its view is
    /// stored, so nothing is ever behind.
    fn settle(&self, _limit: u64) -> Result<u64, StoreError> {
        Ok(0)
    }
}

#[cfg(test)]
#[path = "maintenance_tests.rs"]
mod tests;
