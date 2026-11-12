//! The store's bounded maintenance (`MaintenanceStore`): the inventory
//! over `objects/`, the repair of derived indexes (`index_repair`), and
//! settlement (`settlement_recovery`).
//!
//! The inventory settles allocations that no retirement reached (aborted
//! publications, preparations that never installed, deletions a reader's
//! pin deferred). It walks the shard directories of `objects/` one entry
//! at a time through a directory stream the caller's continuation owns, so
//! a step examines exactly the entries its limit admits, holds no listing
//! of a shard, and resumes where it stopped. The open stream is a storage
//! handle charged to the store's pool of suspended traversals for as long
//! as the continuation holds it; dropping the continuation closes the
//! stream and releases the charge. Each entry is decided by
//! `PersistentStore::reclaim_allocation` (`content_reclaim`) against its
//! installer's committed state at the moment it is examined.
//!
//! Coverage: entries created while a shard is walked may be missed by this
//! pass and are found by the next; every such allocation is pinned by its
//! preparation until it is owned or abandoned, so a missed entry is never
//! an unprotected one.

use std::fs::{DirEntry, ReadDir};

use kappa_store::capacity::Reservation;
use kappa_store::error::StoreError;
use kappa_store::traits::maintenance::{
    Continuation, IndexRepair, MaintenanceOperation, MaintenanceStore, Progress, Reclamation,
    Settlement,
};
use kappa_store::work::{Dimension, Meter, WorkLimit, WorkMeter};

use crate::PersistentStore;
use crate::allocation::{MAX_OWNER_MARKER_BYTES, classify, objects_root};
use crate::content_reclaim::Reclaimed;

/// Shard directories under `objects/`.
const INVENTORY_SHARDS: usize = 256;

/// Where an inventory pass stands: the shard being walked and, while one
/// is open, its directory stream with the reservation that charges it.
#[derive(Default)]
pub struct InventoryPass {
    shard: usize,
    stream: Option<(ReadDir, Reservation)>,
}

/// A settlement pass. Settlement's state (the cycle over the durable
/// records, the obligations, the epochs partly read) belongs to the store,
/// which must keep it whether or not a caller resumes: committed
/// publications stay owed and their protection stays charged when a
/// continuation is dropped. The continuation carries no resource; it
/// scopes the pass to this store.
pub struct SettlePass;

/// What the inventory's next step found.
enum Next {
    Entry(DirEntry),
    /// The budget refused opening the next shard.
    Paused,
    /// The last shard is done.
    End,
}

impl PersistentStore {
    /// The next entry of the inventory, opening the next shard's stream as
    /// each is exhausted; opening one is charged a handle and reserved
    /// from the suspended-traversal pool first.
    fn next_inventory_entry(
        &self,
        pass: &mut InventoryPass,
        meter: &mut WorkMeter,
    ) -> Result<Next, StoreError> {
        loop {
            if let Some((entries, _)) = pass.stream.as_mut() {
                if let Some(entry) = entries.next() {
                    return Ok(Next::Entry(entry?));
                }
                pass.stream = None;
                pass.shard += 1;
            }
            if pass.shard >= INVENTORY_SHARDS {
                return Ok(Next::End);
            }
            if meter.charge(Dimension::Handles, 1).is_err() {
                return Ok(Next::Paused);
            }
            let reservation = self
                .suspended_traversals
                .reserve(1)
                .map_err(|error| StoreError::CapacityExceeded(error.to_string()))?;
            let dir = objects_root(&self.blob_root).join(format!("{:02x}", pass.shard));
            match std::fs::read_dir(&dir) {
                Ok(entries) => pass.stream = Some((entries, reservation)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => pass.shard += 1,
                Err(error) => return Err(StoreError::Io(error)),
            }
        }
    }

    /// Examine one inventory entry: an allocation it names that no
    /// committed row of its installer owns, no pin holds, and no other
    /// claim owns is deleted. A payload, its sidecar and its owner marker
    /// are entries of one allocation; whichever is met first deletes all
    /// and the others are then absent. Entries that name no allocation are
    /// retained. A decision that could not be completed (a removal that
    /// failed, evidence that could not be read) leaves the entry owed and
    /// is counted as failed; a later pass retries it. The projection's
    /// owners of the allocation are read on `work`, the pass's meter; a
    /// refusal is such an undecided entry, never a deletion.
    fn examine_entry(&self, entry: &DirEntry, work: &mut dyn Meter, into: &mut Reclamation) {
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            tracing::warn!(path = %entry.path().display(), "non-utf8 entry in objects");
            into.unrecognized += 1;
            return;
        };
        let Some((allocation, _)) = classify(name) else {
            tracing::warn!(path = %entry.path().display(), "unrecognized entry in objects");
            into.unrecognized += 1;
            return;
        };
        match self.reclaim_allocation(allocation, work) {
            Ok(Reclaimed::Deleted(bytes)) => {
                into.files += 1;
                into.bytes = into.bytes.saturating_add(bytes);
            }
            Ok(Reclaimed::Owned) => into.owned += 1,
            Ok(Reclaimed::Protected) => into.protected += 1,
            Ok(Reclaimed::Absent) => into.absent += 1,
            Err(error) => {
                tracing::warn!(
                    allocation = %allocation.hex(),
                    %error,
                    "allocation decision not completed; retried by a later pass"
                );
                into.failed += 1;
            }
        }
    }

    /// The work charged before one allocation is decided (an inventory
    /// entry, or an allocation compaction released), at its checked upper
    /// bound: the entry, the installer's namespace it may open, the owner
    /// marker and the committed row it may read and decode.
    pub(crate) fn inventory_entry_charge(&self) -> [(Dimension, u64); 4] {
        let row = self.settlement_limits.record_bytes();
        let read = MAX_OWNER_MARKER_BYTES.saturating_add(row);
        [
            (Dimension::Entries, 1),
            (Dimension::Handles, 1),
            (Dimension::BytesRead, read),
            (Dimension::BytesDecoded, row),
        ]
    }
}

impl MaintenanceStore for PersistentStore {
    /// One bounded step of the inventory over `objects/` (see the module
    /// documentation), from `from` or from the first shard.
    fn reclaim_unowned(
        &self,
        limit: &WorkLimit,
        from: Option<Continuation>,
    ) -> Result<Progress<Reclamation>, StoreError> {
        let scope = self.continuation_scope(MaintenanceOperation::Reclaim);
        let mut pass = match from {
            Some(continuation) => continuation.into_state::<InventoryPass>(&scope)?,
            None => InventoryPass::default(),
        };
        let mut meter = WorkMeter::new(*limit);
        let mut outcome = Reclamation::default();
        let charge = self.inventory_entry_charge();
        loop {
            if meter.charge_all(&charge).is_err() {
                return Ok(Progress {
                    outcome,
                    consumed: *meter.used(),
                    continuation: Some(Continuation::new(scope, pass)),
                });
            }
            match self.next_inventory_entry(&mut pass, &mut meter)? {
                Next::Entry(entry) => self.examine_entry(&entry, &mut meter, &mut outcome),
                Next::Paused => {
                    return Ok(Progress {
                        outcome,
                        consumed: *meter.used(),
                        continuation: Some(Continuation::new(scope, pass)),
                    });
                }
                Next::End => {
                    return Ok(Progress {
                        outcome,
                        consumed: *meter.used(),
                        continuation: None,
                    });
                }
            }
        }
    }

    /// One bounded step of the repair pass (`index_repair`).
    fn repair_indexes(
        &self,
        limit: &WorkLimit,
        from: Option<Continuation>,
    ) -> Result<Progress<IndexRepair>, StoreError> {
        self.repair_step(limit, from)
    }

    /// One bounded step of settlement and recovery (`settlement_recovery`)
    /// on a meter of `limit`, which reports exactly what the step consumed.
    /// The pass is complete when the step ended a cycle over the durable
    /// records with no obligation queued and compaction at the end of its
    /// log.
    fn settle(
        &self,
        limit: &WorkLimit,
        from: Option<Continuation>,
    ) -> Result<Progress<Settlement>, StoreError> {
        let scope = self.continuation_scope(MaintenanceOperation::Settle);
        if let Some(continuation) = from {
            let SettlePass = continuation.into_state::<SettlePass>(&scope)?;
        }
        let mut meter = WorkMeter::new(*limit);
        let stepped = self.recovery_step(&mut meter)?;
        let continuation = (!stepped.idle).then(|| Continuation::new(scope, SettlePass));
        Ok(Progress {
            outcome: Settlement {
                epochs: stepped.settled,
            },
            consumed: *meter.used(),
            continuation,
        })
    }
}
