//! Bounded repair of a namespace's derived indexes through a private
//! generation (`derived_index`).
//!
//! A mutation that finds an index diverged from the committed state it
//! projects refuses to commit and records the divergence for its namespace
//! (`PersistentStore::index_diverged`); the namespace's indexes are fenced
//! from then on. A repair of that namespace:
//!
//! 1. lists the namespace in the registry (`INDEX_REPAIRS`), then commits
//!    its repair state in the namespace, naming the empty generation it
//!    builds and the divergence revision it answers;
//! 2. reconstructs that generation from the committed source tables (tags,
//!    edges, the epoch head, representations, pins) in chunks, each one
//!    write transaction of the namespace that commits the derived entries
//!    together with the source cursor, so a step that stops or a crash
//!    resumes exactly where the last chunk committed; authoritative writes
//!    meanwhile apply their changes to both generations, so coverage of
//!    concurrent writes does not depend on the traversal order;
//! 3. makes the reconstructed generation live in one transaction, which
//!    lifts the durable fence;
//! 4. empties the replaced generation in chunks, readers that opened it
//!    keeping their snapshot, then removes the repair state and the
//!    registry listing. The recorded divergence is cleared only when no
//!    divergence was recorded after the repair started; otherwise the
//!    namespace is repaired again.
//!
//! Every chunk runs under the namespace's writer gate, held for the
//! namespace's part of one step only. Work is charged before it is done:
//! one storage handle per namespace visited, one entry per source row or
//! index entry examined, and a row's bytes, read and decoded, before it is
//! decoded. A row the budget cannot cover is left for the next step.
//!
//! Coverage: one pass visits, in identity order, every namespace listed or
//! recorded divergent when the pass reaches it; a namespace recorded after
//! the pass passed it is visited by the next pass.

use std::collections::BTreeMap;
use std::ops::Bound;
use std::sync::Arc;

use redb::{ReadableMultimapTable, ReadableTable, WriteTransaction};

use kappa_store::canonical::from_canonical;
use kappa_store::traits::maintenance::{
    Continuation, ContinuationScope, IndexRepair, MaintenanceOperation, Progress,
};
use kappa_store::work::{Dimension, WorkLimit, WorkMeter};
use kappa_store::{EdgeInput, Kappa, NamespaceRef, StoreError, TagEntry};

use crate::PersistentStore;
use crate::derived_index::{DerivedState, Generation, Phase, Repair, Source, generation_empty};
use crate::referrers::Referrer;
use crate::representation::Representation;
use crate::storage::{NamespaceStorage, Refusal};
use crate::tables::{BLOB_INDEX, EDGES, EPOCH_CURRENT, INDEX_REPAIRS, NAMESPACE_CONFIG, TAGS};

/// Divergence recorded per namespace and not yet repaired: namespace to the
/// revision of its latest record.
#[derive(Default)]
pub struct Divergence {
    revisions: BTreeMap<[u8; 16], u64>,
}

/// Where a repair pass stands: the last namespace whose repair it
/// finished.
pub struct RepairPass {
    after: Option<[u8; 16]>,
}

/// The reconstruction cursor of a building repair: the generation being
/// built and the source position to continue after.
struct Cursor {
    staging: Generation,
    source: Source,
    after: Option<Vec<u8>>,
}

impl Cursor {
    fn into_phase(self) -> Phase {
        Phase::Building {
            staging: self.staging,
            source: self.source,
            after: self.after,
        }
    }
}

/// One committed source row a reconstruction reads.
#[derive(Clone, Copy)]
struct Row<'r> {
    source: Source,
    key: &'r [u8],
    value: &'r [u8],
}

/// How a bounded unit of work ended.
enum Flow {
    /// The unit finished.
    Done,
    /// The budget refused the next charge; the unit resumes from its
    /// committed progress.
    Stopped,
}

impl PersistentStore {
    /// The derived index `index` of namespace `ns` disagrees with the
    /// committed state it projects. The mutation that found it must not
    /// commit; the divergence is recorded for the namespace, which fences
    /// its indexes until a repair started after this record completes
    /// (`MaintenanceStore::repair_indexes`), after which the mutation can
    /// be retried.
    pub(crate) fn index_diverged(
        &self,
        ns: &[u8; 16],
        index: &'static str,
        detail: String,
    ) -> StoreError {
        {
            let mut divergence = self
                .divergence
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let revision = divergence.revisions.entry(*ns).or_insert(0);
            *revision = revision.saturating_add(1);
        }
        tracing::error!(
            namespace = %hex::encode(ns),
            index,
            %detail,
            "derived index diverged from committed state"
        );
        StoreError::Internal(detail)
    }

    /// Whether a divergence of `ns`'s derived indexes is recorded and not
    /// yet repaired.
    pub(crate) fn divergence_recorded(&self, ns: &[u8; 16]) -> bool {
        self.divergence_revision(ns).is_some()
    }

    /// Forget `ns`'s recorded divergence: a schedule that damaged the index
    /// deliberately and restored it by hand.
    #[cfg(test)]
    pub(crate) fn clear_divergence(&self, ns: &[u8; 16]) {
        self.divergence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .revisions
            .remove(ns);
    }

    fn divergence_revision(&self, ns: &[u8; 16]) -> Option<u64> {
        self.divergence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .revisions
            .get(ns)
            .copied()
    }

    /// Clear `ns`'s recorded divergence when `revision` is still its
    /// latest: a divergence recorded after the repair started stays.
    fn divergence_repaired(&self, ns: &[u8; 16], revision: u64) {
        let mut divergence = self
            .divergence
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if divergence.revisions.get(ns) == Some(&revision) {
            divergence.revisions.remove(ns);
        }
    }

    /// The scope of this store's continuations of `operation`.
    pub(crate) fn continuation_scope(&self, operation: MaintenanceOperation) -> ContinuationScope {
        ContinuationScope {
            store: self.maintenance_scope.clone(),
            operation,
        }
    }

    /// One bounded step of the repair pass `from` (a new pass without one)
    /// within `limit`; see the module documentation.
    pub(crate) fn repair_step(
        &self,
        limit: &WorkLimit,
        from: Option<Continuation>,
    ) -> Result<Progress<IndexRepair>, StoreError> {
        let scope = self.continuation_scope(MaintenanceOperation::RepairIndexes);
        let mut pass = match from {
            Some(continuation) => continuation.into_state::<RepairPass>(&scope)?,
            None => RepairPass { after: None },
        };
        let mut meter = WorkMeter::new(*limit);
        let mut outcome = IndexRepair::default();
        loop {
            if meter.charge(Dimension::Entries, 1).is_err() {
                return Ok(Progress {
                    outcome,
                    consumed: *meter.used(),
                    continuation: Some(Continuation::new(scope, pass)),
                });
            }
            let Some(namespace) = self.next_repair(pass.after)? else {
                return Ok(Progress {
                    outcome,
                    consumed: *meter.used(),
                    continuation: None,
                });
            };
            match self.repair_namespace(&namespace, &mut meter, &mut outcome)? {
                Flow::Done => pass.after = Some(namespace),
                Flow::Stopped => {
                    return Ok(Progress {
                        outcome,
                        consumed: *meter.used(),
                        continuation: Some(Continuation::new(scope, pass)),
                    });
                }
            }
        }
    }

    /// The first namespace after `after` that is listed under repair or
    /// recorded divergent.
    fn next_repair(&self, after: Option<[u8; 16]>) -> Result<Option<[u8; 16]>, StoreError> {
        let lower = after
            .as_ref()
            .map_or(Bound::Unbounded, |id| Bound::Excluded(id.as_slice()));
        let listed = {
            let txn = self.registry.begin_read()?;
            let table = txn.open_table(INDEX_REPAIRS).map_err(crate::error::redb)?;
            let mut range = table
                .range::<&[u8]>((lower, Bound::Unbounded))
                .map_err(crate::error::redb)?;
            range
                .next()
                .transpose()
                .map_err(crate::error::redb)?
                .map(|(key, _)| {
                    <[u8; 16]>::try_from(key.value()).map_err(|_| {
                        StoreError::Internal("index repair listing is not a namespace".into())
                    })
                })
                .transpose()?
        };
        let recorded = {
            let divergence = self
                .divergence
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
            divergence
                .revisions
                .range((lower, Bound::Unbounded))
                .next()
                .map(|(id, _)| *id)
        };
        Ok(match (listed, recorded) {
            (Some(listed), Some(recorded)) => Some(listed.min(recorded)),
            (one, other) => one.or(other),
        })
    }

    /// Advance the repair of `id` within `meter`. `Done` once its repair
    /// finished (or it needs none); `Stopped` when the budget ran out, with
    /// every chunk before committed.
    fn repair_namespace(
        &self,
        id: &[u8; 16],
        meter: &mut WorkMeter,
        outcome: &mut IndexRepair,
    ) -> Result<Flow, StoreError> {
        if meter.charge(Dimension::Handles, 1).is_err() {
            return Ok(Flow::Stopped);
        }
        let maintenance = match self.namespaces.maintain(id)? {
            Ok(maintenance) => maintenance,
            // The storage is going, with every derived index in it.
            Err(Refusal::Retiring | Refusal::Released) => {
                self.unlist_repair(id)?;
                if let Some(revision) = self.divergence_revision(id) {
                    self.divergence_repaired(id, revision);
                }
                return Ok(Flow::Done);
            }
            Err(refusal @ Refusal::Unresolved) => return Err(refusal.into_error(id)),
        };
        let db = Arc::clone(&maintenance.controller().db);
        let ns = NamespaceStorage::namespace_ref(*id);
        loop {
            let txn = db.begin_write().map_err(crate::error::redb)?;
            let mut state = DerivedState::in_txn(&txn)?;
            let Some(repair) = state.repair.clone() else {
                let Some(revision) = self.divergence_revision(id) else {
                    // Listed by a repair whose listing outlived it.
                    txn.abort().map_err(crate::error::redb)?;
                    maintenance.finish();
                    self.unlist_repair(id)?;
                    return Ok(Flow::Done);
                };
                let staging = state.live.other();
                if !generation_empty(&txn, staging)? {
                    return Err(StoreError::Internal(format!(
                        "the spare derived index generation of namespace {} is not empty",
                        hex::encode(id)
                    )));
                }
                txn.abort().map_err(crate::error::redb)?;
                // Listed before the fence is durable in the namespace, so a
                // restart finds every repair whose fence it would honor.
                self.list_repair(id)?;
                let txn = db.begin_write().map_err(crate::error::redb)?;
                state.repair = Some(Repair {
                    revision,
                    phase: Phase::Building {
                        staging,
                        source: Source::FIRST,
                        after: None,
                    },
                });
                state.write(&txn)?;
                txn.commit().map_err(crate::error::redb)?;
                outcome.diverged = true;
                continue;
            };
            outcome.diverged = true;
            match repair.phase {
                Phase::Building {
                    staging,
                    source,
                    after,
                } => {
                    let cursor = Cursor {
                        staging,
                        source,
                        after,
                    };
                    let (phase, flow) = self.build_chunk(&txn, &ns, cursor, meter, outcome)?;
                    match phase {
                        Some(phase) => {
                            state.repair = Some(Repair {
                                revision: repair.revision,
                                phase,
                            });
                        }
                        None => {
                            // Every source traversed: the reconstruction
                            // becomes live, and the replaced generation is
                            // emptied from here.
                            state.repair = Some(Repair {
                                revision: repair.revision,
                                phase: Phase::Cleanup { old: state.live },
                            });
                            state.live = staging;
                        }
                    }
                    state.write(&txn)?;
                    txn.commit().map_err(crate::error::redb)?;
                    if matches!(flow, Flow::Stopped) {
                        maintenance.finish();
                        return Ok(Flow::Stopped);
                    }
                }
                Phase::Cleanup { old } => {
                    let flow = clear_chunk(&txn, old, meter)?;
                    let emptied = matches!(flow, Flow::Done);
                    if emptied {
                        state.repair = None;
                        state.write(&txn)?;
                    }
                    txn.commit().map_err(crate::error::redb)?;
                    if emptied {
                        maintenance.finish();
                        self.unlist_repair(id)?;
                        self.divergence_repaired(id, repair.revision);
                        return Ok(Flow::Done);
                    }
                    maintenance.finish();
                    return Ok(Flow::Stopped);
                }
            }
        }
    }

    /// Reconstruct one chunk from `cursor` in `txn`. Returns the phase to
    /// commit with the chunk (`None` when every source is traversed) and
    /// whether the budget stopped the chunk.
    fn build_chunk(
        &self,
        txn: &WriteTransaction,
        ns: &NamespaceRef,
        mut cursor: Cursor,
        meter: &mut WorkMeter,
        outcome: &mut IndexRepair,
    ) -> Result<(Option<Phase>, Flow), StoreError> {
        loop {
            if meter.charge(Dimension::Entries, 1).is_err() {
                return Ok((Some(cursor.into_phase()), Flow::Stopped));
            }
            let Some((key, value)) = next_row(txn, cursor.source, cursor.after.as_deref())? else {
                match cursor.source.next() {
                    Some(next) => {
                        cursor.source = next;
                        cursor.after = None;
                        continue;
                    }
                    None => return Ok((None, Flow::Done)),
                }
            };
            let bytes = u64::try_from(key.len().saturating_add(value.len())).unwrap_or(u64::MAX);
            if meter
                .charge_all(&[
                    (Dimension::BytesRead, bytes),
                    (Dimension::BytesDecoded, bytes),
                ])
                .is_err()
            {
                return Ok((Some(cursor.into_phase()), Flow::Stopped));
            }
            let row = Row {
                source: cursor.source,
                key: &key,
                value: &value,
            };
            let written = self.derive(txn, ns, cursor.staging, &row)?;
            outcome.entries = outcome.entries.saturating_add(written);
            cursor.after = Some(key);
        }
    }

    /// Insert into `staging` every entry the source row `key`/`value` of
    /// `source` implies, by the rule each writer applies. Returns the
    /// entries written.
    fn derive(
        &self,
        txn: &WriteTransaction,
        ns: &NamespaceRef,
        staging: Generation,
        row: &Row<'_>,
    ) -> Result<u64, StoreError> {
        let Row { source, key, value } = *row;
        let mut entries: Vec<(Kappa, Referrer)> = Vec::new();
        match source {
            Source::Tags => {
                let name = std::str::from_utf8(own_suffix(ns, key)?)
                    .map_err(|error| StoreError::Internal(format!("tag name: {error}")))?;
                let tag: TagEntry =
                    from_canonical(&self.decrypt_bytes(&crate::tag::tag_context(key), value)?)?;
                if tag.symref.is_none() {
                    entries.push((tag.kappa, Referrer::tag(ns, name)?));
                }
            }
            Source::Edges => {
                let identity = Kappa::from_key_bytes(own_suffix(ns, key)?)?;
                let input: EdgeInput = from_canonical(
                    &self.decrypt_bytes(&crate::encrypted::bound("edge", key), value)?,
                )?;
                entries.push((identity.clone(), Referrer::edge_record(ns, &identity)));
                if input.relation.gc_reachable() {
                    entries.push((input.target, Referrer::edge_target(ns, &identity)));
                }
            }
            Source::Heads => {
                if key != ns.id().as_slice() {
                    return Err(StoreError::Internal(
                        "epoch head of another namespace in this database".into(),
                    ));
                }
                let root = Kappa::from_key_bytes(
                    &self.decrypt_bytes(&crate::epoch::pointer_context(ns.id()), value)?,
                )?;
                entries.push((root, Referrer::epoch_head(ns)));
            }
            Source::Representations => {
                let record = crate::blob_rows::decode_row(self, key, value)?;
                let owner = Kappa::from_key_bytes(key)?;
                for child in crate::content_install::referenced(&record) {
                    entries.push((child, Referrer::representation(&owner)));
                }
                if let Representation::External { allocation, .. } = record.representation() {
                    let mut allocations = txn
                        .open_table(staging.allocations())
                        .map_err(crate::error::redb)?;
                    let previous = allocations
                        .insert(allocation.0.as_slice(), key)
                        .map_err(crate::error::redb)?
                        .map(|guard| guard.value().to_vec());
                    if previous.as_deref().is_some_and(|held| held != key) {
                        return Err(StoreError::Internal(format!(
                            "allocation {} is selected by two committed rows",
                            allocation.hex()
                        )));
                    }
                }
            }
            Source::Pins => {
                let name = std::str::from_utf8(own_suffix(ns, key)?)
                    .map_err(|error| StoreError::Internal(format!("metadata key: {error}")))?;
                if let Some(pinned) = crate::namespace_write::pinned_content(name)? {
                    entries.push((pinned, Referrer::pin(ns)));
                }
            }
        }
        let mut referrers = txn
            .open_multimap_table(staging.referrers())
            .map_err(crate::error::redb)?;
        let mut written = 0u64;
        for (content, referrer) in entries {
            referrers
                .insert(content.key_bytes().as_slice(), referrer.encode().as_slice())
                .map_err(crate::error::redb)?;
            written += 1;
        }
        Ok(written)
    }

    /// List `id` as under repair, durably, before its repair state commits.
    fn list_repair(&self, id: &[u8; 16]) -> Result<(), StoreError> {
        let txn = self.registry.begin_write()?;
        txn.open_table(INDEX_REPAIRS)
            .map_err(crate::error::redb)?
            .insert(id.as_slice(), ())
            .map_err(crate::error::redb)?;
        match txn.commit() {
            Ok(()) => Ok(()),
            // No repair state is committed in the namespace after a failed
            // listing; a listing that persisted without one is removed by
            // the next pass (`repair_namespace`).
            Err(
                crate::error::CommitFailure::Known(error)
                | crate::error::CommitFailure::Unknown(error),
            ) => Err(error),
        }
    }

    /// Remove `id`'s repair listing once its repair state is gone.
    fn unlist_repair(&self, id: &[u8; 16]) -> Result<(), StoreError> {
        let txn = self.registry.begin_write()?;
        txn.open_table(INDEX_REPAIRS)
            .map_err(crate::error::redb)?
            .remove(id.as_slice())
            .map_err(crate::error::redb)?;
        match txn.commit() {
            Ok(()) => Ok(()),
            // A listing that remains names a namespace with no repair
            // state; the next pass removes it.
            Err(
                crate::error::CommitFailure::Known(error)
                | crate::error::CommitFailure::Unknown(error),
            ) => Err(error),
        }
    }

    /// Rebuild `ns`'s derived indexes from its committed state now, to
    /// completion: the repair protocol driven without a budget. Returns the
    /// entries the reconstructed generation holds. Changes no
    /// epoch-committed state and publishes nothing. Refused while the
    /// namespace is retiring or retired.
    pub fn rebuild_referrers(&self, ns: &NamespaceRef) -> Result<u64, StoreError> {
        {
            let mut divergence = self
                .divergence
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let revision = divergence.revisions.entry(*ns.id()).or_insert(0);
            *revision = revision.saturating_add(1);
        }
        match self.namespaces.maintain(ns.id())? {
            Ok(maintenance) => maintenance.finish(),
            Err(refusal) => return Err(refusal.into_error(ns.id())),
        }
        let mut meter = WorkMeter::unbounded();
        let mut outcome = IndexRepair::default();
        while matches!(
            self.repair_namespace(ns.id(), &mut meter, &mut outcome)?,
            Flow::Stopped
        ) {}
        Ok(outcome.entries)
    }
}

/// The suffix of a namespace-scoped key of `ns`, refused when the key is of
/// another namespace.
fn own_suffix<'k>(ns: &NamespaceRef, key: &'k [u8]) -> Result<&'k [u8], StoreError> {
    key.strip_prefix(ns.id().as_slice()).ok_or_else(|| {
        StoreError::Internal("a namespace-scoped row of another namespace in this database".into())
    })
}

/// The first row of `source`'s table after `after` in `txn`.
fn next_row(
    txn: &WriteTransaction,
    source: Source,
    after: Option<&[u8]>,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, StoreError> {
    let definition = match source {
        Source::Tags => TAGS,
        Source::Edges => EDGES,
        Source::Heads => EPOCH_CURRENT,
        Source::Representations => BLOB_INDEX,
        Source::Pins => NAMESPACE_CONFIG,
    };
    let table = txn.open_table(definition).map_err(crate::error::redb)?;
    let lower = after.map_or(Bound::Unbounded, Bound::Excluded);
    let mut range = table
        .range::<&[u8]>((lower, Bound::Unbounded))
        .map_err(crate::error::redb)?;
    Ok(range
        .next()
        .transpose()
        .map_err(crate::error::redb)?
        .map(|(key, value)| (key.value().to_vec(), value.value().to_vec())))
}

/// Remove entries of generation `old` within `meter`: `Done` once both of
/// its tables are empty.
fn clear_chunk(
    txn: &WriteTransaction,
    old: Generation,
    meter: &mut WorkMeter,
) -> Result<Flow, StoreError> {
    let mut referrers = txn
        .open_multimap_table(old.referrers())
        .map_err(crate::error::redb)?;
    let mut allocations = txn
        .open_table(old.allocations())
        .map_err(crate::error::redb)?;
    loop {
        if meter.charge(Dimension::Entries, 1).is_err() {
            return Ok(Flow::Stopped);
        }
        let first = {
            let mut entries = referrers.iter().map_err(crate::error::redb)?;
            match entries.next() {
                Some(entry) => {
                    let (key, mut values) = entry.map_err(crate::error::redb)?;
                    let value = values
                        .next()
                        .transpose()
                        .map_err(crate::error::redb)?
                        .map(|value| value.value().to_vec());
                    value.map(|value| (key.value().to_vec(), value))
                }
                None => None,
            }
        };
        if let Some((key, value)) = first {
            referrers
                .remove(key.as_slice(), value.as_slice())
                .map_err(crate::error::redb)?;
            continue;
        }
        if allocations
            .pop_first()
            .map_err(crate::error::redb)?
            .is_none()
        {
            return Ok(Flow::Done);
        }
    }
}

#[cfg(test)]
#[path = "index_repair_tests.rs"]
mod tests;
