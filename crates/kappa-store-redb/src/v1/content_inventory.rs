//! The bounded inventory over `objects/`.
//!
//! It settles allocations that no retirement reached (aborted
//! publications, preparations that never installed, deletions a reader's
//! pin deferred): it walks the shard directories of `objects/` one entry
//! at a time through a directory stream kept open between steps, so a step
//! examines exactly the entries its limit allows, holds no listing of a
//! shard, and resumes where it stopped. Each entry is decided by
//! `PersistentStore::reclaim_allocation` (`content_reclaim`).

use std::fs::{DirEntry, ReadDir};

use kappa_store::error::StoreError;
use kappa_store::traits::maintenance::{IndexRepair, MaintenanceStore, Reclamation};

use crate::PersistentStore;
use crate::allocation::{classify, objects_root};
use crate::content_reclaim::Reclaimed;

/// Shard directories under `objects/`.
const INVENTORY_SHARDS: usize = 256;

/// Where the bounded inventory stands: the shard being walked and the
/// directory stream open into it. The stream is kept between steps, so a
/// step examines exactly the entries its limit allows and the next step
/// continues from the entry after; the shard's listing is never held in
/// memory. Entries created while a shard is being walked may be missed
/// by this pass and are found by the next; every such allocation is
/// pinned by its preparation until it is owned or abandoned, so a missed
/// entry is never an unprotected one.
#[derive(Default)]
pub struct InventoryCursor {
    shard: usize,
    entries: Option<ReadDir>,
}

impl PersistentStore {
    /// The next entry of the inventory, opening the next shard's stream
    /// as each is exhausted. `None` once the last shard is done.
    fn next_inventory_entry(
        &self,
        cursor: &mut InventoryCursor,
    ) -> Result<Option<DirEntry>, StoreError> {
        loop {
            if let Some(entries) = cursor.entries.as_mut() {
                if let Some(entry) = entries.next() {
                    return Ok(Some(entry?));
                }
                cursor.entries = None;
                cursor.shard += 1;
            }
            if cursor.shard >= INVENTORY_SHARDS {
                return Ok(None);
            }
            let dir = objects_root(&self.blob_root).join(format!("{:02x}", cursor.shard));
            match std::fs::read_dir(&dir) {
                Ok(entries) => cursor.entries = Some(entries),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => cursor.shard += 1,
                Err(error) => return Err(StoreError::Io(error)),
            }
        }
    }

    /// Examine one inventory entry: an allocation it names that no
    /// committed row of its installer owns, no pin holds, and no other
    /// claim owns is deleted. A payload, its sidecar and its owner marker
    /// are entries of one allocation; whichever is met first deletes all
    /// and the others are then absent. Entries that name no allocation
    /// are retained.
    fn examine_entry(&self, entry: &DirEntry, into: &mut Reclamation) -> Result<(), StoreError> {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            tracing::warn!(path = %entry.path().display(), "non-utf8 entry in objects");
            into.unrecognized += 1;
            return Ok(());
        };
        let Some((allocation, _)) = classify(name) else {
            tracing::warn!(path = %entry.path().display(), "unrecognized entry in objects");
            into.unrecognized += 1;
            return Ok(());
        };
        match self.reclaim_allocation(allocation)? {
            Reclaimed::Deleted(bytes) => {
                into.files += 1;
                into.bytes = into.bytes.saturating_add(bytes);
            }
            Reclaimed::Owned => into.owned += 1,
            Reclaimed::Protected => into.protected += 1,
            Reclaimed::Absent => into.absent += 1,
        }
        Ok(())
    }
}

impl MaintenanceStore for PersistentStore {
    /// Bounded, resumable inventory over `objects/`: at most `limit`
    /// directory entries are examined, continuing from the entry after the
    /// one the previous call stopped at; a pass that reaches the last
    /// shard reports completion and the next call starts over. Runs as one
    /// bounded step at open and from maintenance in steps. The cursor is
    /// held for the step, so steps never interleave. Each entry is decided
    /// by its own installer's committed state, so a namespace whose
    /// settlement lags, failed or is fenced protects only its own
    /// allocations.
    fn reclaim_unowned(&self, limit: usize) -> Result<Reclamation, StoreError> {
        let mut cursor = self
            .inventory
            .lock()
            .map_err(|_| StoreError::Internal("inventory cursor lock poisoned".into()))?;
        let mut reclamation = Reclamation::default();
        let mut examined = 0usize;
        while examined < limit {
            let Some(entry) = self.next_inventory_entry(&mut cursor)? else {
                reclamation.complete = true;
                *cursor = InventoryCursor::default();
                drop(cursor);
                return Ok(reclamation);
            };
            examined += 1;
            self.examine_entry(&entry, &mut reclamation)?;
        }
        // The limit was met with the stream still open; the pass ends only
        // when the stream reports the last shard exhausted.
        Ok(reclamation)
    }

    /// Rebuild `ALLOCATIONS` and `REFERRERS` of every namespace when a
    /// mutation recorded divergence; see
    /// `PersistentStore::repair_derived_indexes`.
    fn repair_indexes(&self) -> Result<IndexRepair, StoreError> {
        Ok(self
            .repair_derived_indexes()?
            .map_or_else(IndexRepair::default, |entries| IndexRepair {
                diverged: true,
                entries,
            }))
    }

    fn settle(&self, limit: u64) -> Result<u64, StoreError> {
        self.settlement_step(limit)
    }
}
