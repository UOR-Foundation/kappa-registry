//! Reclamation of content no committed epoch state reaches.
//!
//! Roots are epoch-committed facts only: every direct tag target, every
//! namespace's current epoch head, and every unexpired pin. Staged
//! resources need no special root: an open resource's head is a tag
//! target, the head retains its anchor through an `Owns` edge, and the
//! anchor retains the members through `Member` edges, so staged content is
//! reachable exactly while its head is named. Reachability is walked over
//! the relations that retain (`EdgeRelation::gc_reachable`), and the edge
//! records themselves are content the walk marks.
//!
//! Retirement is epoch-committed: an unreachable identity is retired
//! through an execution in every namespace that admitted it
//! (`BlobStore::blob_owners`), each of which refuses the identity while
//! one of its committed references still names it, and the backend
//! reclaims the physical allocation after the retirements settle, subject
//! to reader and preparation protection. Nothing here deletes directly.

use std::sync::Arc;

use roaring::RoaringBitmap;

use crate::execution::ExecutionStore;
use crate::time::Clock;
use crate::traits::blob::BlobStore;
use crate::traits::edge::EdgeStore;
use crate::traits::epoch::EpochStore;
use crate::traits::namespace::{NamespaceInfo, NamespaceStore};
use crate::traits::tag::TagStore;
use kappa_types::clock::ClockMs;
use kappa_types::edge::{BuiltinRelation, EdgeRelation, SemanticRelation, semantic};
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::page::{NamespaceFilter, PageRequest};

#[derive(Debug, Clone)]
pub struct GcResult {
    pub objects_scanned: u64,
    pub objects_reachable: u64,
    pub objects_retired: u64,
    /// Candidates a committed reference acquired since the snapshot
    /// retained; left in place.
    pub objects_skipped: u64,
    /// Candidates whose representation was already gone when retirement
    /// reached them.
    pub objects_absent: u64,
    /// Logical bytes of the retired identities. Physical bytes are
    /// reported by the backend's reclamation.
    pub bytes_retired: u64,
}

/// Configuration for GC behavior.
pub struct GcConfig {
    /// Maximum blob count before GC rejects. 0 = unlimited.
    pub max_blob_count: u64,
    /// Identities retired per publication, so one sweep never holds the
    /// writer across the whole population.
    pub retire_batch: usize,
}

/// Snapshot of the blob trie at a point in time.
///
/// All GC phases use this one snapshot. Concurrent trie rebuild
/// does not invalidate ordinals because the snapshot holds the
/// trie alive via Arc.
pub struct TrieSnapshot {
    pub key_table: Arc<Vec<Vec<u8>>>,
    pub blob_cursor_fn: Box<dyn Fn() -> Box<dyn kappa_cursor::KappaCursor + 'static>>,
}

/// Snapshot every stored blob identity, in key order, for one sweep.
///
/// The key table and every cursor the snapshot hands out share one
/// allocation. A cursor that yields keys out of order or twice is refused:
/// ordinal positions are binary-searched, so an unordered table would
/// misclassify reachable blobs as garbage.
pub fn blob_snapshot<S: BlobStore + ?Sized>(store: &S) -> Result<TrieSnapshot, StoreError> {
    let mut keys: Vec<Vec<u8>> = Vec::new();
    let mut cursor = store.blob_cursor()?;
    let mut current = cursor.key()?.map(<[u8]>::to_vec);
    while let Some(key) = current {
        if keys
            .last()
            .is_some_and(|previous| previous.as_slice() >= key.as_slice())
        {
            return Err(StoreError::Internal(
                "blob cursor yielded keys out of order".into(),
            ));
        }
        keys.push(key);
        current = cursor.advance()?.map(<[u8]>::to_vec);
    }
    let key_table = Arc::new(keys);
    let cursor_keys = Arc::clone(&key_table);
    Ok(TrieSnapshot {
        key_table,
        blob_cursor_fn: Box::new(move || {
            Box::new(kappa_cursor::ArcSliceCursor::from_arc(Arc::clone(
                &cursor_keys,
            )))
        }),
    })
}

impl TrieSnapshot {
    /// Binary search for a key in the `key_table`. Returns the ordinal
    /// position if found.
    pub fn position_of(&self, key: &[u8]) -> Option<u32> {
        self.key_table
            .binary_search_by(|k| k.as_slice().cmp(key))
            .ok()
            .and_then(|i| u32::try_from(i).ok())
    }
}

/// Enumerated reachable relations for consumers requiring explicit filters.
/// GC itself evaluates the relation-owned policy directly.
pub fn gc_reachable_relations() -> Vec<EdgeRelation> {
    BuiltinRelation::ALL
        .into_iter()
        .map(EdgeRelation::Builtin)
        .chain(
            [
                semantic::DERIVED_FROM,
                semantic::COMPOSED_OF,
                semantic::IS_PART_OF,
            ]
            .into_iter()
            .map(|iri| EdgeRelation::Semantic(SemanticRelation(iri.into()))),
        )
        .filter(EdgeRelation::gc_reachable)
        .collect()
}

/// Every namespace, paged.
fn all_namespaces<S: NamespaceStore + ?Sized>(store: &S) -> Result<Vec<NamespaceInfo>, StoreError> {
    let mut namespaces = Vec::new();
    let mut request = PageRequest::first(256);
    loop {
        let page = store.namespace_list(&NamespaceFilter::default(), &request)?;
        namespaces.extend(page.items);
        match page.next_after {
            Some(next) if request.after.as_ref() != Some(&next) => request.after = Some(next),
            Some(_) => {
                return Err(StoreError::Rejected(
                    "namespace traversal did not advance".into(),
                ));
            }
            None => break,
        }
    }
    Ok(namespaces)
}

/// Epoch-committed roots of `ns`: direct tag targets, the epoch head, and
/// unexpired pins.
fn namespace_roots<S>(
    store: &S,
    ns: &NamespaceRef,
    now: ClockMs,
    roots: &mut Vec<Kappa>,
) -> Result<(), StoreError>
where
    S: TagStore + EpochStore + NamespaceStore + ?Sized,
{
    let mut cursor = store.tag_cursor(ns, None)?;
    while cursor.key() != kappa_cursor::TERMINATED {
        let name = std::str::from_utf8(cursor.key())
            .map_err(|error| StoreError::Rejected(format!("invalid tag cursor key: {error}")))?;
        let entry = store.tag_get_raw(ns, name)?;
        // A symbolic tag names a tag, not content.
        if entry.symref.is_none() {
            roots.push(entry.kappa);
        }
        cursor.advance();
    }
    match store.epoch_current(ns) {
        Ok((_, epoch_kappa)) => roots.push(epoch_kappa),
        Err(StoreError::NotFound(_)) => {}
        Err(error) => return Err(error),
    }
    let mut request = PageRequest::first(256);
    loop {
        let pin_keys = store.namespace_list_meta_keys(ns, "_pin/", &request)?;
        for pin_key in &pin_keys.items {
            if let Some(kappa) = active_pin(store, ns, pin_key, now)? {
                roots.push(kappa);
            }
        }
        match pin_keys.next_after {
            Some(next) if request.after.as_ref() != Some(&next) => request.after = Some(next),
            Some(_) => {
                return Err(StoreError::Rejected("pin traversal did not advance".into()));
            }
            None => break,
        }
    }
    Ok(())
}

/// One collection sweep over the committed state.
///
/// Builds the epoch-committed root set, walks reachability over
/// retaining relations, and retires every unreachable identity through
/// executions in each namespace that admitted it, `config.retire_batch`
/// per publication.
pub fn gc_sweep<S>(
    store: &S,
    trie_snapshot: &TrieSnapshot,
    config: &GcConfig,
    clock: &dyn Clock,
    now: ClockMs,
) -> Result<GcResult, StoreError>
where
    S: BlobStore + TagStore + EdgeStore + EpochStore + NamespaceStore + ExecutionStore + ?Sized,
{
    if config.max_blob_count > 0 && trie_snapshot.key_table.len() as u64 > config.max_blob_count {
        return Err(StoreError::Rejected(format!(
            "blob count {} exceeds gc_max_blob_count {}",
            trie_snapshot.key_table.len(),
            config.max_blob_count,
        )));
    }
    if config.retire_batch == 0 {
        return Err(StoreError::Rejected("retire_batch must be positive".into()));
    }
    let namespaces = all_namespaces(store)?;
    let mut roots: Vec<Kappa> = Vec::new();
    for info in &namespaces {
        namespace_roots(store, &info.ns, now, &mut roots)?;
    }
    let reachable = walk_reachable(store, &namespaces, &roots, trie_snapshot)?;
    retire_unreachable(store, trie_snapshot, &reachable, config, clock)
}

fn active_pin<S: NamespaceStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    key: &str,
    now: ClockMs,
) -> Result<Option<Kappa>, StoreError> {
    let identity = key
        .strip_prefix("_pin/")
        .ok_or_else(|| StoreError::Rejected("pin cursor escaped prefix".into()))?;
    let kappa = Kappa::parse(identity)
        .map_err(|error| StoreError::Rejected(format!("invalid pin identity: {error}")))?;
    let bytes = store.namespace_get_meta(namespace, key)?;
    // A pin without a complete, well-typed expiration never expires. Only
    // an epoch-committed removal (resource expiry, explicit unpin) retires
    // it; an expired pin is merely not a root.
    let expired = serde_json::from_slice::<serde_json::Value>(&bytes).is_ok_and(|metadata| {
        let ttl = metadata.get("ttl").and_then(serde_json::Value::as_u64);
        let created = metadata
            .get("created_at_ms")
            .and_then(serde_json::Value::as_i64);
        ttl.zip(created).is_some_and(|(ttl, created)| {
            ttl > 0 && i128::from(now.as_i64()) - i128::from(created) > i128::from(ttl)
        })
    });
    Ok((!expired).then_some(kappa))
}

/// Retire every unreachable identity in each namespace that admitted it.
/// A representation is a namespace's own row: retiring it is that
/// namespace's epoch, refused there while any of its committed
/// references still names the identity. Candidates are grouped by owner
/// and retired `config.retire_batch` per publication of that owner, so a
/// sweep holds no namespace's writer across the whole population and
/// never writes through a namespace that holds nothing.
fn retire_unreachable<S>(
    store: &S,
    trie_snapshot: &TrieSnapshot,
    reachable: &RoaringBitmap,
    config: &GcConfig,
    clock: &dyn Clock,
) -> Result<GcResult, StoreError>
where
    S: BlobStore + ExecutionStore + ?Sized,
{
    let mut all_cursor = (trie_snapshot.blob_cursor_fn)();
    let mut tally = Tally::default();
    let mut batches = OwnerBatches::new();

    loop {
        let key = all_cursor.key();
        if key == kappa_cursor::TERMINATED {
            break;
        }
        let position = trie_snapshot.position_of(key).ok_or_else(|| {
            StoreError::Rejected("GC candidate is absent from retained ordinal mapping".into())
        })?;
        tally.scanned += 1;
        if !reachable.contains(position) {
            let kappa = Kappa::from_key_bytes(key).map_err(|error| {
                StoreError::Internal(format!("blob snapshot key is not an identity: {error}"))
            })?;
            let owners = store.blob_owners(&kappa)?;
            if owners.is_empty() {
                tally.absent += 1;
            }
            for owner in owners {
                let size = match store.blob_size_in(&owner, &kappa) {
                    Ok(size) => size,
                    // Retired in that namespace since the snapshot.
                    Err(StoreError::NotFound(_)) => {
                        tally.absent += 1;
                        continue;
                    }
                    Err(error) => return Err(error),
                };
                let (ns, batch) = batches
                    .entry(*owner.id())
                    .or_insert_with(|| (owner.clone(), Vec::with_capacity(config.retire_batch)));
                batch.push((kappa.clone(), size));
                if batch.len() >= config.retire_batch {
                    retire_batch(store, ns, clock, batch, &mut tally)?;
                }
            }
        }
        all_cursor.advance();
    }
    for (ns, mut batch) in batches.into_values() {
        retire_batch(store, &ns, clock, &mut batch, &mut tally)?;
    }

    Ok(GcResult {
        objects_scanned: tally.scanned,
        objects_reachable: reachable.len(),
        objects_retired: tally.retired,
        objects_skipped: tally.skipped,
        objects_absent: tally.absent,
        bytes_retired: tally.bytes,
    })
}

/// Retirement candidates grouped by owning namespace: each namespace's
/// reference and its pending `(identity, logical size)` batch.
type OwnerBatches = std::collections::BTreeMap<[u8; 16], (NamespaceRef, Vec<(Kappa, u64)>)>;

#[derive(Default)]
struct Tally {
    scanned: u64,
    retired: u64,
    skipped: u64,
    absent: u64,
    bytes: u64,
}

/// Retire one batch in one execution of the owning namespace `owner`.
/// Each member is decided under that namespace's writer: a member a
/// committed reference still names (committed since the snapshot) is
/// retained and counted as skipped, an absent one is counted as absent,
/// and neither affects the rest of the batch. The execution publishes
/// when it retired anything and is aborted otherwise, so a batch that
/// changed nothing publishes no epoch.
fn retire_batch<S: ExecutionStore + ?Sized>(
    store: &S,
    owner: &NamespaceRef,
    clock: &dyn Clock,
    batch: &mut Vec<(Kappa, u64)>,
    tally: &mut Tally,
) -> Result<(), StoreError> {
    use crate::execution::Retirement;
    if batch.is_empty() {
        return Ok(());
    }
    let mut execution = store.begin_execution(owner, clock)?;
    let mut retired: u64 = 0;
    let mut bytes: u64 = 0;
    for (identity, size) in batch.drain(..) {
        match execution.content_retire(&identity)? {
            Retirement::Retired => {
                retired += 1;
                bytes = bytes.saturating_add(size);
            }
            Retirement::Retained => tally.skipped += 1,
            Retirement::Absent => tally.absent += 1,
        }
    }
    if retired == 0 {
        execution.abort()?;
        return Ok(());
    }
    execution.publish()?;
    tally.retired += retired;
    tally.bytes = tally.bytes.saturating_add(bytes);
    Ok(())
}

/// BFS from the root set, marking reachable positions.
///
/// Edge targets and edge records are both marked, and every marked
/// identity's representation dependencies (composite components, manifest
/// nodes, alias holders) are marked transitively, so a dependency is never
/// a candidate while something reachable selects it. Errors propagate: an
/// incomplete reachable set is a false commitment that causes data loss.
fn walk_reachable<S>(
    store: &S,
    namespaces: &[NamespaceInfo],
    roots: &[Kappa],
    snapshot: &TrieSnapshot,
) -> Result<RoaringBitmap, StoreError>
where
    S: EdgeStore + BlobStore + ?Sized,
{
    let mut reachable = RoaringBitmap::new();
    let mut pending: Vec<Kappa> = Vec::new();
    let namespaces: Vec<_> = namespaces.iter().map(|info| info.ns.clone()).collect();
    crate::graph::walk_edges(
        store,
        &namespaces,
        roots,
        EdgeRelation::gc_reachable,
        |identity| {
            if let Some(position) = snapshot.position_of(&identity.key_bytes())
                && reachable.insert(position)
            {
                pending.push(identity.clone());
            }
            Ok(())
        },
    )?;
    while let Some(identity) = pending.pop() {
        let components = match store.blob_components(&identity) {
            Ok(components) => components,
            // Marked through an edge but not stored in this snapshot: nothing
            // to follow, and nothing to retire.
            Err(StoreError::NotFound(_)) => continue,
            Err(error) => return Err(error),
        };
        for component in components {
            if let Some(position) = snapshot.position_of(&component.key_bytes())
                && reachable.insert(position)
            {
                pending.push(component);
            }
        }
    }
    Ok(reachable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gc_reachable_relations_is_exhaustive() {
        let relations = gc_reachable_relations();
        for builtin in BuiltinRelation::ALL {
            assert_eq!(
                relations.contains(&EdgeRelation::Builtin(builtin)),
                builtin.gc_reachable()
            );
        }
        assert!(relations.iter().all(EdgeRelation::gc_reachable));
        assert_eq!(relations.len(), 14);
    }
}
