use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use arc_swap::ArcSwap;
use kappa_cursor::KappaCursor;

use crate::cursor::TrieCursor;
use crate::digest::IncrementalDigest;
use crate::trie::{LoudsDsTrie, TrieConfig, TrieError};

/// Snapshot of the trie for GC and bitmap operations.
///
/// Capture retains the immutable base and copies only pending overlays.
/// Cursors traverse that retained state without enumerating the base.
/// `keys()` lazily materializes one positional mapping when requested.
///
/// Constructed via `TrieIndex::trie_snapshot()`. Holds an Arc to
/// the trie, keeping it alive for the snapshot's lifetime even if
/// the trie rebuilds during the operation.
pub struct TrieSnapshot {
    key_table: OnceLock<Vec<Vec<u8>>>,
    base: Option<Arc<LoudsDsTrie>>,
    inserts: Arc<Vec<Vec<u8>>>,
    deletes: Arc<Vec<Vec<u8>>>,
    comparisons: Arc<AtomicU64>,
    generation: u64,
    logical_digest: [u8; 32],
}

impl TrieSnapshot {
    pub fn keys(&self) -> &[Vec<u8>] {
        self.key_table
            .get_or_init(|| {
                let mut cursor = self.cursor();
                let mut keys = Vec::new();
                while cursor.key() != kappa_cursor::TERMINATED {
                    keys.push(cursor.key().to_vec());
                    cursor.advance();
                }
                keys
            })
            .as_slice()
    }

    pub fn cursor(&self) -> Box<dyn KappaCursor> {
        let base: Box<dyn KappaCursor> = match &self.base {
            Some(trie) => Box::new(TrieCursor::from_arc(trie.clone())),
            None => Box::new(kappa_cursor::EmptyCursor),
        };
        Box::new(kappa_cursor::Difference::new(
            kappa_cursor::Union::new(
                base,
                crate::snapshot_cursor::CountedCursor::new(
                    kappa_cursor::ArcSliceCursor::from_arc(self.inserts.clone()),
                    self.comparisons.clone(),
                ),
            ),
            crate::snapshot_cursor::CountedCursor::new(
                kappa_cursor::ArcSliceCursor::from_arc(self.deletes.clone()),
                self.comparisons.clone(),
            ),
        ))
    }

    /// Base generation captured with the logical keyset and its overlays.
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Digest of this snapshot, unaffected by subsequent index mutations.
    pub const fn logical_digest(&self) -> &[u8; 32] {
        &self.logical_digest
    }
}

struct TrieState {
    trie: Arc<LoudsDsTrie>,
    key_count: u64,
}

pub struct TrieIndex {
    mutation_lock: Mutex<()>,
    rebuild_lock: Mutex<()>,
    revisions: Mutex<BTreeMap<Vec<u8>, u64>>,
    next_revision: AtomicU64,
    current: ArcSwap<Option<TrieState>>,
    overflow_inserts: Mutex<BTreeSet<Vec<u8>>>,
    overflow_deletes: Mutex<BTreeSet<Vec<u8>>>,
    digest: Mutex<IncrementalDigest>,
    generation: AtomicU64,
    config: TrieConfig,
    /// Nonempty overlay consultations made by snapshot set-algebra cursors.
    /// Shared with cursors via Arc clone at cursor construction.
    overflow_comparisons: ArcSwap<AtomicU64>,
    /// Last time `should_rebuild` checked the comparison rate.
    last_check: Mutex<Instant>,
    /// Comparisons-per-second threshold above which rebuild fires.
    /// Self-tunes: write-heavy workloads with few reads never trigger.
    /// Read-heavy workloads trigger quickly when overflow impacts seeks.
    overhead_threshold: u64,
}

fn merge_keys(
    trie_arc: &Arc<Option<TrieState>>,
    inserts: &BTreeSet<Vec<u8>>,
    deletes: &BTreeSet<Vec<u8>>,
) -> Vec<Vec<u8>> {
    let base: Box<dyn KappaCursor + '_> = match trie_arc.as_ref().as_ref() {
        Some(state) => Box::new(TrieCursor::new(&state.trie)),
        None => Box::new(kappa_cursor::EmptyCursor),
    };
    let mut merged = Vec::new();
    let mut cursor = kappa_cursor::Difference::new(
        kappa_cursor::Union::new(base, kappa_cursor::BTreeCursor::new(inserts)),
        kappa_cursor::BTreeCursor::new(deletes),
    );
    while cursor.key() != kappa_cursor::TERMINATED {
        merged.push(cursor.key().to_vec());
        cursor.advance();
    }
    merged
}

impl TrieIndex {
    pub fn new(config: TrieConfig) -> Self {
        let overhead_threshold = config.rebuild_overhead_threshold;
        Self {
            mutation_lock: Mutex::new(()),
            rebuild_lock: Mutex::new(()),
            revisions: Mutex::new(BTreeMap::new()),
            next_revision: AtomicU64::new(0),
            current: ArcSwap::from_pointee(None),
            overflow_inserts: Mutex::new(BTreeSet::new()),
            overflow_deletes: Mutex::new(BTreeSet::new()),
            digest: Mutex::new(IncrementalDigest::new()),
            generation: AtomicU64::new(0),
            overflow_comparisons: ArcSwap::from_pointee(AtomicU64::new(0)),
            last_check: Mutex::new(Instant::now()),
            overhead_threshold,
            config,
        }
    }

    /// Counter for the current base publication's overlay key consultations.
    /// Retained cursors keep their original counter after base replacement.
    pub fn overflow_counter(&self) -> Arc<AtomicU64> {
        self.overflow_comparisons.load_full()
    }

    /// Build from an initial sorted key set.
    pub fn build_initial<'a, I>(&self, keys: I) -> Result<(), TrieError>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let rebuild = self
            .rebuild_lock
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let mutation = self
            .mutation_lock
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let collected: BTreeSet<&[u8]> = keys.into_iter().collect();
        let key_count = collected.len() as u64;
        let state = if collected.is_empty() {
            None
        } else {
            Some(TrieState {
                trie: Arc::new(LoudsDsTrie::build(&self.config, collected.iter().copied())?),
                key_count,
            })
        };

        let mut next_digest = IncrementalDigest::new();
        for &key in &collected {
            next_digest.insert(key);
        }
        // Acquire every fallible resource before touching published state.
        let mut inserts = self
            .overflow_inserts
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let mut deletes = self
            .overflow_deletes
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let mut revisions = self.revisions.lock().map_err(|_| TrieError::LockPoisoned)?;
        let mut digest = self.digest.lock().map_err(|_| TrieError::LockPoisoned)?;
        let mut last = self
            .last_check
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        *digest = next_digest;
        drop(digest);
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.current.store(Arc::new(state));
        inserts.clear();
        drop(inserts);
        deletes.clear();
        drop(deletes);
        revisions.clear();
        drop(revisions);
        self.overflow_comparisons.store(Arc::new(AtomicU64::new(0)));
        *last = Instant::now();
        drop(last);
        drop(mutation);
        drop(rebuild);
        Ok(())
    }

    /// Insert a key.
    pub fn insert(&self, key: Vec<u8>) -> Result<(), TrieError> {
        let mutation = self
            .mutation_lock
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let mut inserts = self
            .overflow_inserts
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let mut deletes = self
            .overflow_deletes
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let mut revisions = self.revisions.lock().map_err(|_| TrieError::LockPoisoned)?;
        let mut digest = self.digest.lock().map_err(|_| TrieError::LockPoisoned)?;
        let base = self.current.load_full();
        if inserts.contains(&key)
            || (!deletes.contains(&key)
                && base
                    .as_ref()
                    .as_ref()
                    .is_some_and(|state| state.trie.ordinal(&key).is_some()))
        {
            return Ok(());
        }
        digest.insert(&key);
        drop(digest);
        deletes.remove(&key);
        let revision = self.next_revision.fetch_add(1, Ordering::Relaxed);
        drop(deletes);
        revisions.insert(key.clone(), revision);
        drop(revisions);
        inserts.insert(key);
        drop(inserts);
        drop(mutation);
        Ok(())
    }

    /// Delete a key.
    pub fn delete(&self, key: Vec<u8>) -> Result<(), TrieError> {
        let mutation = self
            .mutation_lock
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let mut inserts = self
            .overflow_inserts
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let mut deletes = self
            .overflow_deletes
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let mut revisions = self.revisions.lock().map_err(|_| TrieError::LockPoisoned)?;
        let mut digest = self.digest.lock().map_err(|_| TrieError::LockPoisoned)?;
        let base = self.current.load_full();
        if deletes.contains(&key)
            || (!inserts.contains(&key)
                && base
                    .as_ref()
                    .as_ref()
                    .is_none_or(|state| state.trie.ordinal(&key).is_none()))
        {
            return Ok(());
        }
        digest.remove(&key);
        drop(digest);
        inserts.remove(&key);
        drop(inserts);
        // Keep a tombstone even for an overflow insertion: an in-flight rebuild
        // may already have copied that insertion into its new base trie.
        let revision = self.next_revision.fetch_add(1, Ordering::Relaxed);
        revisions.insert(key.clone(), revision);
        drop(revisions);
        deletes.insert(key);
        drop(deletes);
        drop(mutation);
        Ok(())
    }

    /// Rebuild the trie from the current logical key set.
    ///
    /// Clone-then-drain-after-swap:
    /// 1. Clone overflow under lock (keys remain in live overflow).
    /// 2. Build trie from clone + existing trie keys.
    /// 3. Swap trie (readers see new trie with cloned keys).
    /// 4. Drain cloned keys from overflow (now redundant).
    ///
    /// At no point are keys absent from both trie and overflow.
    /// Before step 3: keys in overflow. After step 3: keys in trie.
    /// Step 4 removes redundant overflow entries.
    pub fn rebuild(&self) -> Result<(), TrieError> {
        self.rebuild_after_capture(|| {})
    }

    fn rebuild_after_capture(&self, after_capture: impl FnOnce()) -> Result<(), TrieError> {
        let rebuild = self
            .rebuild_lock
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let cloned_inserts: BTreeSet<Vec<u8>>;
        let cloned_deletes: BTreeSet<Vec<u8>>;
        let cloned_revisions;
        let snapshot;
        {
            let mutation = self
                .mutation_lock
                .lock()
                .map_err(|_| TrieError::LockPoisoned)?;
            cloned_inserts = self
                .overflow_inserts
                .lock()
                .map_err(|_| TrieError::LockPoisoned)?
                .clone();
            cloned_deletes = self
                .overflow_deletes
                .lock()
                .map_err(|_| TrieError::LockPoisoned)?
                .clone();
            cloned_revisions = self
                .revisions
                .lock()
                .map_err(|_| TrieError::LockPoisoned)?
                .clone();
            snapshot = self.current.load_full();
            drop(mutation);
        }

        after_capture();
        let merged = merge_keys(&snapshot, &cloned_inserts, &cloned_deletes);

        let state = if merged.is_empty() {
            None
        } else {
            Some(TrieState {
                trie: Arc::new(LoudsDsTrie::build(
                    &self.config,
                    merged.iter().map(Vec::as_slice),
                )?),
                key_count: merged.len() as u64,
            })
        };
        let mutation = self
            .mutation_lock
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let mut inserts = self
            .overflow_inserts
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let mut deletes = self
            .overflow_deletes
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let mut revisions = self.revisions.lock().map_err(|_| TrieError::LockPoisoned)?;
        let mut last = self
            .last_check
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.current.store(Arc::new(state));
        for (key, revision) in &cloned_revisions {
            if revisions.get(key) == Some(revision) {
                inserts.remove(key);
                deletes.remove(key);
                revisions.remove(key);
            }
        }
        drop(inserts);
        drop(deletes);
        drop(revisions);
        self.overflow_comparisons.store(Arc::new(AtomicU64::new(0)));
        *last = Instant::now();
        drop(last);
        drop(mutation);
        drop(rebuild);
        Ok(())
    }

    /// Whether reads are impacted enough by the overflow to justify rebuild.
    ///
    /// Measures nonempty overlay key consultations per second
    /// since the last check. If the rate exceeds the threshold, rebuild
    /// is justified. Write-heavy workloads with few reads produce low
    /// rates and do not trigger. Read-heavy workloads trigger quickly.
    ///
    /// Also triggers unconditionally when there is overflow but no trie
    /// (first build needed).
    pub fn should_rebuild(&self) -> Result<bool, TrieError> {
        let mutation = self
            .mutation_lock
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let overflow = self.overflow_size()?;
        if overflow == 0 {
            return Ok(false);
        }
        if self.config.max_overflow_bound > 0 && overflow >= self.config.max_overflow_bound {
            return Ok(true);
        }
        let trie_size = match self.current.load_full().as_ref() {
            Some(state) => state.key_count,
            None => return Ok(true),
        };
        if trie_size == 0 {
            return Ok(true);
        }

        let mut last = self
            .last_check
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let elapsed = last.elapsed();
        if elapsed.as_nanos() == 0 {
            return Ok(false);
        }
        let comparisons = self
            .overflow_comparisons
            .load_full()
            .swap(0, Ordering::Relaxed);
        *last = Instant::now();
        drop(last);
        drop(mutation);
        Ok(comparison_rate_exceeds(
            comparisons,
            elapsed,
            self.overhead_threshold,
        ))
    }

    /// Create a snapshot for GC and bitmap operations.
    pub fn trie_snapshot(&self) -> Result<TrieSnapshot, TrieError> {
        let (arc, inserts, deletes, logical_digest, generation, comparisons) = {
            let mutation = self
                .mutation_lock
                .lock()
                .map_err(|_| TrieError::LockPoisoned)?;
            let captured = (
                self.current.load_full(),
                self.overflow_inserts
                    .lock()
                    .map_err(|_| TrieError::LockPoisoned)?
                    .clone(),
                self.overflow_deletes
                    .lock()
                    .map_err(|_| TrieError::LockPoisoned)?
                    .clone(),
                *self
                    .digest
                    .lock()
                    .map_err(|_| TrieError::LockPoisoned)?
                    .value(),
                self.generation.load(Ordering::SeqCst),
                self.overflow_comparisons.load_full(),
            );
            drop(mutation);
            captured
        };
        Ok(TrieSnapshot {
            key_table: OnceLock::new(),
            base: arc.as_ref().as_ref().map(|state| state.trie.clone()),
            inserts: Arc::new(inserts.into_iter().collect()),
            deletes: Arc::new(deletes.into_iter().collect()),
            comparisons,
            generation,
            logical_digest,
        })
    }

    /// Current logical digest.
    pub fn logical_digest(&self) -> Result<[u8; 32], TrieError> {
        let digest = self.digest.lock().map_err(|_| TrieError::LockPoisoned)?;
        let value = *digest.value();
        drop(digest);
        Ok(value)
    }

    /// Current trie serialization digest, or None if no trie built.
    pub fn trie_digest(&self) -> Option<[u8; 32]> {
        let snapshot = self.current.load_full();
        snapshot.as_ref().as_ref().map(|s| *s.trie.digest())
    }

    /// Current generation number.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Number of entries in the overflow buffers.
    pub fn overflow_size(&self) -> Result<usize, TrieError> {
        let inserts = self
            .overflow_inserts
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let deletes = self
            .overflow_deletes
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let size = inserts.len() + deletes.len();
        drop(inserts);
        drop(deletes);
        Ok(size)
    }

    /// The current logical key set as a sorted Vec.
    pub fn live_keys(&self) -> Result<Vec<Vec<u8>>, TrieError> {
        Ok(self.trie_snapshot()?.keys().to_vec())
    }

    /// Find the position of a key in a sorted key table.
    pub fn position_of(key_table: &[Vec<u8>], key: &[u8]) -> Option<u32> {
        key_table
            .binary_search_by(|k| k.as_slice().cmp(key))
            .ok()
            .and_then(|pos| u32::try_from(pos).ok())
    }
}

fn comparison_rate_exceeds(comparisons: u64, elapsed: std::time::Duration, threshold: u64) -> bool {
    let observed = u128::from(comparisons) * 1_000_000_000;
    // Overflow on the threshold side means it exceeds every possible observed count.
    u128::from(threshold)
        .checked_mul(elapsed.as_nanos())
        .is_some_and(|limit| observed > limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisoned_publication_resource_preserves_base_digest_and_overlays() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice()])?;
        index.insert(b"bb".to_vec())?;
        let retained = index.trie_snapshot()?;
        let generation = index.generation();
        let base = index.trie_digest();
        let digest = index.logical_digest()?;
        let counter = index.overflow_counter();
        // A panic while holding this resource makes publication inadmissible.
        // Both publication paths must report the failure before changing state.
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let Ok(guard) = index.revisions.lock() else {
                return;
            };
            std::hint::black_box(&guard);
            std::panic::resume_unwind(Box::new("injected revision-owner failure"));
        }));
        assert!(failure.is_err());
        assert!(matches!(
            index.build_initial([b"cc".as_slice()]),
            Err(TrieError::LockPoisoned)
        ));
        assert!(matches!(index.rebuild(), Err(TrieError::LockPoisoned)));
        assert!(matches!(
            index.insert(b"cc".to_vec()),
            Err(TrieError::LockPoisoned)
        ));
        assert!(matches!(
            index.delete(b"aa".to_vec()),
            Err(TrieError::LockPoisoned)
        ));
        assert_eq!(index.generation(), generation);
        assert_eq!(index.trie_digest(), base);
        assert_eq!(index.logical_digest()?, digest);
        assert_eq!(index.overflow_size()?, 1);
        assert!(Arc::ptr_eq(&counter, &index.overflow_counter()));
        assert_eq!(index.live_keys()?, retained.keys());
        Ok(())
    }

    #[test]
    fn comparison_rate_preserves_integer_precision_and_strict_boundary() {
        let second = std::time::Duration::from_secs(1);
        assert!(!comparison_rate_exceeds(u64::MAX - 1, second, u64::MAX));
        assert!(!comparison_rate_exceeds(u64::MAX, second, u64::MAX));
        assert!(comparison_rate_exceeds(u64::MAX, second, u64::MAX - 1));
        assert!(!comparison_rate_exceeds(
            u64::MAX,
            std::time::Duration::MAX,
            u64::MAX
        ));
    }

    #[test]
    fn failed_initial_build_preserves_publication_and_read_interval() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice()])?;
        index.insert(b"bb".to_vec())?;
        let retained = index.trie_snapshot()?;
        let generation = index.generation();
        let digest = index.logical_digest()?;
        let counter = index.overflow_counter();
        let interval = *index
            .last_check
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        let invalid = vec![0; 66];
        assert!(matches!(
            index.build_initial([invalid.as_slice()]),
            Err(TrieError::KeyTooLong { .. })
        ));
        assert_eq!(index.generation(), generation);
        assert_eq!(index.logical_digest()?, digest);
        assert!(Arc::ptr_eq(&counter, &index.overflow_counter()));
        assert_eq!(
            *index
                .last_check
                .lock()
                .map_err(|_| TrieError::LockPoisoned)?,
            interval
        );
        assert_eq!(index.live_keys()?, retained.keys());
        Ok(())
    }

    #[test]
    fn publication_starts_a_new_counter_and_interval() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice()])?;
        index.insert(b"bb".to_vec())?;
        let counter = index.overflow_counter();
        let stale = Instant::now()
            .checked_sub(std::time::Duration::from_secs(60))
            .ok_or(TrieError::VerificationFailed)?;
        *index
            .last_check
            .lock()
            .map_err(|_| TrieError::LockPoisoned)? = stale;
        index.rebuild()?;
        assert!(!Arc::ptr_eq(&counter, &index.overflow_counter()));
        assert!(
            *index
                .last_check
                .lock()
                .map_err(|_| TrieError::LockPoisoned)?
                > stale
        );
        Ok(())
    }

    #[test]
    fn failed_rebuild_preserves_overlays_and_can_recover() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice()])?;
        let invalid = vec![0; 66];
        index.insert(invalid.clone())?;
        index.delete(b"aa".to_vec())?;
        index.insert(b"bb".to_vec())?;
        let retained = index.trie_snapshot()?;
        let generation = index.generation();
        let base_digest = index.trie_digest();
        let digest = index.logical_digest()?;
        let counter = index.overflow_counter();
        let interval = *index
            .last_check
            .lock()
            .map_err(|_| TrieError::LockPoisoned)?;
        assert!(matches!(index.rebuild(), Err(TrieError::KeyTooLong { .. })));
        assert_eq!(index.generation(), generation);
        assert_eq!(index.trie_digest(), base_digest);
        assert_eq!(index.logical_digest()?, digest);
        assert_eq!(index.overflow_size()?, 3);
        assert!(Arc::ptr_eq(&counter, &index.overflow_counter()));
        assert_eq!(
            *index
                .last_check
                .lock()
                .map_err(|_| TrieError::LockPoisoned)?,
            interval
        );
        assert_eq!(index.live_keys()?, retained.keys());
        index.delete(invalid)?;
        let repaired_digest = index.logical_digest()?;
        index.rebuild()?;
        assert_eq!(index.live_keys()?, vec![b"bb".to_vec()]);
        assert_eq!(index.logical_digest()?, repaired_digest);
        assert_eq!(index.overflow_size()?, 0);
        assert_eq!(retained.logical_digest(), &digest);
        Ok(())
    }

    #[test]
    fn empty_base_publication_preserves_newer_reinsert_and_new_key() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice()])?;
        index.delete(b"aa".to_vec())?;
        let retained = index.trie_snapshot()?;
        let captured = std::sync::Barrier::new(2);
        let mutated = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                index.rebuild_after_capture(|| {
                    captured.wait();
                    mutated.wait();
                })
            });
            captured.wait();
            let first = index.insert(b"aa".to_vec());
            let second = index.insert(b"bb".to_vec());
            mutated.wait();
            let published = worker.join().map_err(|_| TrieError::VerificationFailed)?;
            first?;
            second?;
            published
        })?;
        assert!(retained.keys().is_empty());
        assert_eq!(index.live_keys()?, vec![b"aa".to_vec(), b"bb".to_vec()]);
        assert_eq!(index.overflow_size()?, 2);
        let digest = index.logical_digest()?;
        index.rebuild()?;
        assert_eq!(index.live_keys()?, vec![b"aa".to_vec(), b"bb".to_vec()]);
        assert_eq!(index.logical_digest()?, digest);
        assert_eq!(index.overflow_size()?, 0);
        Ok(())
    }

    #[test]
    fn snapshot_capture_and_cursor_do_not_materialize_mapping() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice(), b"cc"])?;
        index.insert(b"bb".to_vec())?;
        let snapshot = index.trie_snapshot()?;
        assert!(snapshot.key_table.get().is_none());
        let mut cursor = snapshot.cursor();
        assert_eq!(cursor.seek(b"bb"), b"bb");
        assert!(snapshot.key_table.get().is_none());
        assert_eq!(
            snapshot.keys(),
            &[b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec()]
        );
        assert!(snapshot.key_table.get().is_some());
        Ok(())
    }

    #[test]
    fn rebuild_preserves_newer_delete_reinsert_and_new_keys() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice(), b"cc"])?;
        index.insert(b"bb".to_vec())?;
        let retained = index.trie_snapshot()?;
        let captured = std::sync::Barrier::new(2);
        let mutated = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                index.rebuild_after_capture(|| {
                    captured.wait();
                    mutated.wait();
                })
            });
            captured.wait();
            let mutations = [
                index.delete(b"bb".to_vec()),
                index.insert(b"bb".to_vec()),
                index.delete(b"cc".to_vec()),
                index.insert(b"dd".to_vec()),
            ];
            mutated.wait();
            let published = worker.join().map_err(|_| TrieError::VerificationFailed)?;
            for result in mutations {
                result?;
            }
            published
        })?;
        let expected = vec![b"aa".to_vec(), b"bb".to_vec(), b"dd".to_vec()];
        assert_eq!(index.live_keys()?, expected);
        assert_eq!(
            retained.keys(),
            &[b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec()]
        );
        let digest = index.logical_digest()?;
        index.rebuild()?;
        assert_eq!(index.live_keys()?, expected);
        assert_eq!(index.logical_digest()?, digest);
        assert_eq!(index.overflow_size()?, 0);
        Ok(())
    }

    #[test]
    fn build_and_query() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        let keys: Vec<&[u8]> = vec![b"aa", b"bb", b"cc"];
        index.build_initial(keys)?;
        assert_eq!(index.generation(), 1);
        assert!(index.trie_digest().is_some());
        Ok(())
    }

    #[test]
    fn insert_shows_in_live_keys() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice(), b"cc"])?;
        index.insert(b"bb".to_vec())?;
        let keys = index.live_keys()?;
        assert_eq!(keys, vec![b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec()]);
        Ok(())
    }

    #[test]
    fn delete_removes_from_live_keys() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice(), b"bb", b"cc"])?;
        index.delete(b"bb".to_vec())?;
        let keys = index.live_keys()?;
        assert_eq!(keys, vec![b"aa".to_vec(), b"cc".to_vec()]);
        Ok(())
    }

    #[test]
    fn rebuild_incorporates_overflow() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice()])?;
        index.insert(b"bb".to_vec())?;
        index.rebuild()?;
        let keys = index.live_keys()?;
        assert_eq!(keys, vec![b"aa".to_vec(), b"bb".to_vec()]);
        Ok(())
    }

    #[test]
    fn rebuild_increments_generation() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice()])?;
        let gen1 = index.generation();
        index.rebuild()?;
        let gen2 = index.generation();
        assert_eq!(gen2, gen1 + 1);
        Ok(())
    }

    #[test]
    fn logical_digest_order_independent() -> Result<(), TrieError> {
        let i1 = TrieIndex::new(TrieConfig::default());
        i1.build_initial(std::iter::empty::<&[u8]>())?;
        i1.insert(b"alpha".to_vec())?;
        i1.insert(b"beta".to_vec())?;
        i1.insert(b"gamma".to_vec())?;

        let i2 = TrieIndex::new(TrieConfig::default());
        i2.build_initial(std::iter::empty::<&[u8]>())?;
        i2.insert(b"gamma".to_vec())?;
        i2.insert(b"alpha".to_vec())?;
        i2.insert(b"beta".to_vec())?;

        assert_eq!(i1.logical_digest()?, i2.logical_digest()?);
        Ok(())
    }

    #[test]
    fn insert_then_delete_returns_to_original_digest() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice()])?;
        let d1 = index.logical_digest()?;
        index.insert(b"bb".to_vec())?;
        assert_ne!(index.logical_digest()?, d1);
        index.delete(b"bb".to_vec())?;
        assert_eq!(index.logical_digest()?, d1);
        Ok(())
    }

    #[test]
    fn delete_from_overflow_does_not_double_count() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice()])?;
        index.insert(b"bb".to_vec())?;
        index.delete(b"bb".to_vec())?;
        assert_eq!(index.logical_digest()?, {
            let mut expected = IncrementalDigest::new();
            expected.insert(b"aa");
            *expected.value()
        });
        index.rebuild()?;
        assert_eq!(index.overflow_size()?, 0);
        Ok(())
    }

    #[test]
    fn trie_snapshot_captures_live_keys() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice(), b"cc"])?;
        index.insert(b"bb".to_vec())?;
        let snap = index.trie_snapshot()?;
        assert_eq!(
            snap.keys(),
            [b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec()]
        );
        let mut cursor = snap.cursor();
        assert_eq!(cursor.key(), b"aa".as_slice());
        cursor.advance();
        assert_eq!(cursor.key(), b"bb".as_slice());
        cursor.advance();
        assert_eq!(cursor.key(), b"cc".as_slice());
        cursor.advance();
        assert_eq!(cursor.key(), kappa_cursor::TERMINATED);
        Ok(())
    }

    #[test]
    fn position_of_finds_key() {
        let table = vec![b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec()];
        assert_eq!(TrieIndex::position_of(&table, b"bb"), Some(1));
        assert_eq!(TrieIndex::position_of(&table, b"dd"), None);
    }

    #[test]
    fn should_rebuild_false_when_empty_overflow() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice()])?;
        assert!(!index.should_rebuild()?);
        Ok(())
    }

    #[test]
    fn should_rebuild_true_when_no_trie() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.insert(b"aa".to_vec())?;
        assert!(index.should_rebuild()?);
        Ok(())
    }

    #[test]
    fn should_rebuild_fires_on_high_comparison_rate() -> Result<(), TrieError> {
        let config = TrieConfig {
            rebuild_overhead_threshold: 100,
            ..Default::default()
        };
        let index = TrieIndex::new(config);
        index.build_initial([b"aa".as_slice()])?;
        index.insert(b"bb".to_vec())?;
        // Simulate high comparison rate by directly setting the counter.
        index
            .overflow_comparisons
            .load_full()
            .store(1_000_000, Ordering::Relaxed);
        // Reset the check time so elapsed > 0.
        {
            let mut last = index
                .last_check
                .lock()
                .map_err(|_| TrieError::LockPoisoned)?;
            *last = Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .ok_or(TrieError::VerificationFailed)?;
        }
        assert!(index.should_rebuild()?);
        Ok(())
    }

    #[test]
    fn should_rebuild_does_not_fire_on_low_comparison_rate() -> Result<(), TrieError> {
        let config = TrieConfig {
            rebuild_overhead_threshold: 10_000,
            ..Default::default()
        };
        let index = TrieIndex::new(config);
        index.build_initial([b"aa".as_slice()])?;
        index.insert(b"bb".to_vec())?;
        // Low comparison count.
        index
            .overflow_comparisons
            .load_full()
            .store(5, Ordering::Relaxed);
        {
            let mut last = index
                .last_check
                .lock()
                .map_err(|_| TrieError::LockPoisoned)?;
            *last = Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .ok_or(TrieError::VerificationFailed)?;
        }
        assert!(!index.should_rebuild()?);
        Ok(())
    }

    #[test]
    fn overflow_counter_is_shared() {
        let index = TrieIndex::new(TrieConfig::default());
        let counter = index.overflow_counter();
        counter.fetch_add(42, Ordering::Relaxed);
        assert_eq!(
            index
                .overflow_comparisons
                .load_full()
                .load(Ordering::Relaxed),
            42
        );
    }

    #[test]
    fn rebuild_clone_preserves_reader_visibility() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice()])?;
        index.insert(b"bb".to_vec())?;

        let snap1 = index.trie_snapshot()?;
        assert!(snap1.keys().contains(&b"bb".to_vec()));

        index.rebuild()?;

        let snap2 = index.trie_snapshot()?;
        assert!(snap2.keys().contains(&b"bb".to_vec()));

        index.insert(b"cc".to_vec())?;
        let snap3 = index.trie_snapshot()?;
        assert!(snap3.keys().contains(&b"bb".to_vec()));
        assert!(snap3.keys().contains(&b"cc".to_vec()));
        Ok(())
    }

    #[test]
    fn rebuild_resets_comparison_counter() -> Result<(), TrieError> {
        let index = TrieIndex::new(TrieConfig::default());
        index.build_initial([b"aa".as_slice()])?;
        index
            .overflow_comparisons
            .load_full()
            .store(999, Ordering::Relaxed);
        index.rebuild()?;
        assert_eq!(
            index
                .overflow_comparisons
                .load_full()
                .load(Ordering::Relaxed),
            0
        );
        Ok(())
    }
}
