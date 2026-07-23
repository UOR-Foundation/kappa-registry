//! Multi-object transaction with quarantine staging and atomic promotion (P3).
//!
//! Defense in depth against storage exhaustion:
//! - Per-transaction TTL with periodic auto-reap
//! - Max concurrent transactions (default 64)
//! - Per-transaction byte limit (reuses max_blob_size)
//! - Global staging byte limit (default 256 MiB)
//! - Lazy staging dir creation (begin is in-memory only)
//! - Startup cleanup of orphaned staging dirs

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;
use std::time::Instant;

use crate::kappa::verify_kappa;
use crate::store::fs::atomic_write;
use crate::store::StoreError;

/// Transaction manager state, held in AppState alongside SessionStore.
pub struct TransactionManager {
    active: RwLock<HashMap<String, TransactionState>>,
    active_count: AtomicUsize,
    total_staging_bytes: AtomicUsize,
    store_root: PathBuf,
    max_concurrent: usize,
    max_bytes_per_txn: usize,
    max_bytes_global: usize,
    timeout_secs: u64,
}

struct TransactionState {
    #[allow(dead_code)]
    ns: String,
    created_at: Instant,
    staging_bytes: usize,
    staging_dir_created: bool,
}

/// Result of a successful transaction commit.
#[derive(Debug, serde::Serialize)]
pub struct CommitResult {
    pub promoted: Vec<String>,
}

impl TransactionManager {
    pub fn new(
        store_root: PathBuf,
        max_concurrent: usize,
        max_bytes_per_txn: usize,
        max_bytes_global: usize,
        timeout_secs: u64,
    ) -> Self {
        // Startup cleanup: remove orphaned staging dirs from prior crashes.
        let staging_root = store_root.join("staging");
        if staging_root.exists() {
            if let Ok(entries) = std::fs::read_dir(&staging_root) {
                for entry in entries.flatten() {
                    let _ = std::fs::remove_dir_all(entry.path());
                }
            }
        }

        TransactionManager {
            active: RwLock::new(HashMap::new()),
            active_count: AtomicUsize::new(0),
            total_staging_bytes: AtomicUsize::new(0),
            store_root,
            max_concurrent,
            max_bytes_per_txn,
            max_bytes_global,
            timeout_secs,
        }
    }

    /// Begin a new transaction. No disk I/O -- staging dir is created lazily.
    /// Returns 429-equivalent error if at capacity.
    pub fn begin(&self, ns: &str) -> Result<String, StoreError> {
        let count = self.active_count.load(Ordering::Relaxed);
        if count >= self.max_concurrent {
            return Err(StoreError::Conflict(format!(
                "max concurrent transactions ({}) reached",
                self.max_concurrent
            )));
        }

        let id = uuid::Uuid::new_v4().to_string();
        let state = TransactionState {
            ns: ns.to_string(),
            created_at: Instant::now(),
            staging_bytes: 0,
            staging_dir_created: false,
        };

        let mut map = self.active.write().unwrap();
        map.insert(id.clone(), state);
        self.active_count.fetch_add(1, Ordering::Relaxed);
        Ok(id)
    }

    /// Write a blob into the transaction's staging area.
    /// Verify-on-put: the content must hash to the provided kappa-label.
    pub fn put(&self, txn_id: &str, kappa: &str, content: &[u8]) -> Result<bool, StoreError> {
        // Verify content matches kappa-label
        match verify_kappa(kappa, content) {
            Ok(true) => {}
            Ok(false) => {
                return Err(StoreError::Conflict(format!(
                    "content hash mismatch for {kappa}"
                )));
            }
            Err(e) => {
                return Err(StoreError::Conflict(format!(
                    "invalid kappa-label {kappa}: {e}"
                )));
            }
        }

        let content_len = content.len();

        // Check per-transaction and global byte limits
        {
            let map = self.active.read().unwrap();
            let state = map.get(txn_id).ok_or(StoreError::NotFound)?;
            if state.staging_bytes + content_len > self.max_bytes_per_txn {
                return Err(StoreError::Conflict(format!(
                    "transaction staging limit ({} bytes) exceeded",
                    self.max_bytes_per_txn
                )));
            }
        }

        let global = self.total_staging_bytes.load(Ordering::Relaxed);
        if global + content_len > self.max_bytes_global {
            return Err(StoreError::Conflict(format!(
                "global staging limit ({} bytes) exceeded",
                self.max_bytes_global
            )));
        }

        // Create staging dir lazily
        let staging_dir = self.staging_dir(txn_id);
        {
            let mut map = self.active.write().unwrap();
            let state = map.get_mut(txn_id).ok_or(StoreError::NotFound)?;
            if !state.staging_dir_created {
                std::fs::create_dir_all(&staging_dir)?;
                state.staging_dir_created = true;
            }
        }

        // Write blob to staging using the same shard layout as the main store
        let blob_path = blob_path_in(&staging_dir, kappa);
        if blob_path.exists() {
            return Ok(false); // idempotent
        }
        atomic_write(&blob_path, content)?;

        // Update byte counters
        {
            let mut map = self.active.write().unwrap();
            if let Some(state) = map.get_mut(txn_id) {
                state.staging_bytes += content_len;
            }
        }
        self.total_staging_bytes
            .fetch_add(content_len, Ordering::Relaxed);

        Ok(true)
    }

    /// Commit a transaction: promote all staged objects into the main store.
    /// Returns the list of kappa-labels that were promoted.
    ///
    /// Promotion ordering: objects durable in store THEN caller creates
    /// edges THEN caller updates tags/refs. This method handles step 1 only.
    pub fn commit(
        &self,
        txn_id: &str,
        main_store: &dyn crate::store::KappaStore,
    ) -> Result<CommitResult, StoreError> {
        let staging_dir = self.staging_dir(txn_id);
        let staging_bytes;

        // Verify transaction exists
        {
            let map = self.active.read().unwrap();
            let state = map.get(txn_id).ok_or(StoreError::NotFound)?;
            staging_bytes = state.staging_bytes;
            if !state.staging_dir_created {
                // No objects staged -- commit is a no-op
                drop(map);
                self.cleanup(txn_id);
                return Ok(CommitResult {
                    promoted: Vec::new(),
                });
            }
        }

        // Enumerate staged blobs
        let staged = list_staged_blobs(&staging_dir)?;

        // Promote each blob to the main store (idempotent -- content-addressed)
        let mut promoted = Vec::with_capacity(staged.len());
        for (kappa, path) in &staged {
            let content = std::fs::read(path)?;
            main_store.put(kappa, &content)?;
            promoted.push(kappa.clone());
        }

        // Remove staging dir and clean up state
        let _ = std::fs::remove_dir_all(&staging_dir);
        self.total_staging_bytes
            .fetch_sub(staging_bytes, Ordering::Relaxed);
        self.cleanup(txn_id);

        Ok(CommitResult { promoted })
    }

    /// Abort a transaction: discard all staged objects.
    pub fn abort(&self, txn_id: &str) -> Result<(), StoreError> {
        let staging_dir = self.staging_dir(txn_id);
        let staging_bytes;

        {
            let map = self.active.read().unwrap();
            let state = map.get(txn_id).ok_or(StoreError::NotFound)?;
            staging_bytes = state.staging_bytes;
        }

        if staging_dir.exists() {
            let _ = std::fs::remove_dir_all(&staging_dir);
        }

        self.total_staging_bytes
            .fetch_sub(staging_bytes, Ordering::Relaxed);
        self.cleanup(txn_id);

        Ok(())
    }

    /// Periodic reaper: remove transactions older than timeout_secs.
    /// Called from the same interval loop as upload session cleanup.
    pub fn evict_expired(&self) -> usize {
        let mut to_remove = Vec::new();
        {
            let map = self.active.read().unwrap();
            for (id, state) in map.iter() {
                if state.created_at.elapsed().as_secs() > self.timeout_secs {
                    to_remove.push(id.clone());
                }
            }
        }

        let count = to_remove.len();
        for id in to_remove {
            let _ = self.abort(&id);
        }
        count
    }

    /// List active transaction IDs (for status/diagnostics).
    pub fn active_count(&self) -> usize {
        self.active_count.load(Ordering::Relaxed)
    }

    fn staging_dir(&self, txn_id: &str) -> PathBuf {
        self.store_root.join("staging").join(txn_id)
    }

    fn cleanup(&self, txn_id: &str) {
        let mut map = self.active.write().unwrap();
        if map.remove(txn_id).is_some() {
            self.active_count.fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Blob path within a staging directory, using the same shard layout
/// as the main store: {staging_dir}/blobs/{axis}/{shard}/{kappa}
fn blob_path_in(staging_dir: &Path, kappa: &str) -> PathBuf {
    let (axis, hex) = kappa.split_once(':').unwrap_or(("unknown", "00"));
    let shard = if hex.len() >= 2 { &hex[..2] } else { "xx" };
    staging_dir.join("blobs").join(axis).join(shard).join(kappa)
}

/// List all staged blobs in a staging directory.
/// Returns (kappa-label, file path) pairs.
fn list_staged_blobs(staging_dir: &Path) -> Result<Vec<(String, PathBuf)>, StoreError> {
    let blobs_dir = staging_dir.join("blobs");
    if !blobs_dir.exists() {
        return Ok(Vec::new());
    }
    let mut results = Vec::new();
    for axis_entry in std::fs::read_dir(&blobs_dir)? {
        let axis_entry = axis_entry?;
        if !axis_entry.file_type()?.is_dir() {
            continue;
        }
        for shard_entry in std::fs::read_dir(axis_entry.path())? {
            let shard_entry = shard_entry?;
            if !shard_entry.file_type()?.is_dir() {
                continue;
            }
            for blob_entry in std::fs::read_dir(shard_entry.path())? {
                let blob_entry = blob_entry?;
                let name = blob_entry.file_name().to_string_lossy().to_string();
                if name.ends_with(".meta") || name.ends_with(".tmp") {
                    continue;
                }
                // The filename IS the kappa-label (e.g., "sha256:abcdef...")
                if name.contains(':') {
                    results.push((name, blob_entry.path()));
                }
            }
        }
    }
    results.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kappa::KappaLabel;
    use crate::store::fs::FsStore;
    use crate::store::KappaStore;

    fn test_manager(dir: &Path) -> TransactionManager {
        TransactionManager::new(
            dir.to_path_buf(),
            4,    // max 4 concurrent
            1024, // max 1 KiB per txn
            4096, // max 4 KiB global
            1,    // 1 second timeout for reaper tests
        )
    }

    fn test_kappa(content: &[u8]) -> String {
        KappaLabel::sha256(content).as_str().to_string()
    }

    #[test]
    fn begin_returns_unique_ids() {
        let dir = tempfile::TempDir::new().unwrap();
        let mgr = test_manager(dir.path());
        let id1 = mgr.begin("ns").unwrap();
        let id2 = mgr.begin("ns").unwrap();
        assert_ne!(id1, id2);
        assert_eq!(mgr.active_count(), 2);
    }

    #[test]
    fn max_concurrent_enforced() {
        let dir = tempfile::TempDir::new().unwrap();
        let mgr = test_manager(dir.path()); // max 4
        for _ in 0..4 {
            mgr.begin("ns").unwrap();
        }
        assert_eq!(mgr.active_count(), 4);
        let result = mgr.begin("ns");
        assert!(result.is_err(), "5th transaction should be rejected");
    }

    #[test]
    fn per_txn_byte_limit_enforced() {
        let dir = tempfile::TempDir::new().unwrap();
        let mgr = test_manager(dir.path()); // max 1024 per txn
        let id = mgr.begin("ns").unwrap();

        // 512 bytes -- should succeed
        let small = vec![0x41u8; 512];
        let small_k = test_kappa(&small);
        assert!(mgr.put(&id, &small_k, &small).is_ok());

        // Another 600 bytes -- total 1112, exceeds 1024
        let big = vec![0x42u8; 600];
        let big_k = test_kappa(&big);
        let result = mgr.put(&id, &big_k, &big);
        assert!(result.is_err(), "should exceed per-txn limit");
    }

    #[test]
    fn global_byte_limit_enforced() {
        let dir = tempfile::TempDir::new().unwrap();
        let mgr = test_manager(dir.path()); // max 4096 global

        // 4 transactions each putting 900 bytes = 3600, under limit
        let mut ids = Vec::new();
        for i in 0..4u8 {
            let id = mgr.begin("ns").unwrap();
            let content = vec![0x50 + i; 900];
            let k = test_kappa(&content);
            mgr.put(&id, &k, &content).unwrap();
            ids.push(id);
        }

        // 5th transaction -- begin a new one (abort one first to free a slot)
        mgr.abort(&ids[0]).unwrap();
        let id5 = mgr.begin("ns").unwrap();
        // Put 600 bytes -- global total was 3600, minus 900 (aborted) = 2700, plus 600 = 3300, ok
        let content5 = vec![0x55u8; 600];
        let k5 = test_kappa(&content5);
        assert!(mgr.put(&id5, &k5, &content5).is_ok());

        // Now try to put another 1000 -- global = 3300 + 1000 = 4300 > 4096
        let big = vec![0x56u8; 1000];
        let big_k = test_kappa(&big);
        let result = mgr.put(&id5, &big_k, &big);
        assert!(result.is_err(), "should exceed global limit");
    }

    #[test]
    fn abort_frees_capacity() {
        let dir = tempfile::TempDir::new().unwrap();
        let mgr = test_manager(dir.path()); // max 4 concurrent

        let ids: Vec<String> = (0..4).map(|_| mgr.begin("ns").unwrap()).collect();
        assert!(mgr.begin("ns").is_err(), "at capacity");

        mgr.abort(&ids[0]).unwrap();
        assert_eq!(mgr.active_count(), 3);
        assert!(mgr.begin("ns").is_ok(), "slot freed by abort");
    }

    #[test]
    fn commit_frees_capacity() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = FsStore::new(dir.path().to_path_buf()).unwrap();
        let mgr = test_manager(dir.path());

        let id = mgr.begin("ns").unwrap();
        let content = b"commit-frees";
        let k = test_kappa(content);
        mgr.put(&id, &k, content).unwrap();
        mgr.commit(&id, &store).unwrap();

        assert_eq!(mgr.active_count(), 0);
        // Blob should be in the main store
        assert!(store.get(&k).unwrap().is_some());
    }

    #[test]
    fn evict_expired_removes_old_transactions() {
        let dir = tempfile::TempDir::new().unwrap();
        let mgr = test_manager(dir.path()); // 1 second timeout

        let id = mgr.begin("ns").unwrap();
        let content = b"will-expire";
        let k = test_kappa(content);
        mgr.put(&id, &k, content).unwrap();

        // Wait for expiry. elapsed().as_secs() truncates, and the check
        // is `> timeout_secs` (strictly greater), so we need >2 seconds
        // elapsed for a 1-second timeout.
        std::thread::sleep(std::time::Duration::from_millis(2100));

        let evicted = mgr.evict_expired();
        assert_eq!(evicted, 1);
        assert_eq!(mgr.active_count(), 0);

        // Staging dir should be gone
        let staging = dir.path().join("staging").join(&id);
        assert!(!staging.exists(), "staging dir removed after eviction");
    }

    #[test]
    fn startup_cleanup_removes_orphaned_staging() {
        let dir = tempfile::TempDir::new().unwrap();
        let orphan_dir = dir.path().join("staging").join("orphaned-txn");
        std::fs::create_dir_all(&orphan_dir).unwrap();
        std::fs::write(orphan_dir.join("leftover"), b"data").unwrap();

        // Creating the manager should clean up orphaned staging dirs
        let _mgr = test_manager(dir.path());
        assert!(
            !orphan_dir.exists(),
            "orphaned staging dir removed on startup"
        );
    }

    #[test]
    fn put_to_nonexistent_transaction_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let mgr = test_manager(dir.path());
        let content = b"no-txn";
        let k = test_kappa(content);
        let result = mgr.put("nonexistent-id", &k, content);
        assert!(result.is_err());
    }

    #[test]
    fn commit_empty_transaction_succeeds() {
        let dir = tempfile::TempDir::new().unwrap();
        let store = FsStore::new(dir.path().to_path_buf()).unwrap();
        let mgr = test_manager(dir.path());

        let id = mgr.begin("ns").unwrap();
        let result = mgr.commit(&id, &store).unwrap();
        assert!(result.promoted.is_empty());
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn lazy_staging_dir_creation() {
        let dir = tempfile::TempDir::new().unwrap();
        let mgr = test_manager(dir.path());

        let id = mgr.begin("ns").unwrap();
        let staging = dir.path().join("staging").join(&id);
        assert!(!staging.exists(), "staging dir not created on begin");

        let content = b"trigger-create";
        let k = test_kappa(content);
        mgr.put(&id, &k, content).unwrap();
        assert!(staging.exists(), "staging dir created on first put");
    }

    #[test]
    fn digest_mismatch_rejected() {
        let dir = tempfile::TempDir::new().unwrap();
        let mgr = test_manager(dir.path());
        let id = mgr.begin("ns").unwrap();

        let wrong_kappa = format!("sha256:{}", "0".repeat(64));
        let result = mgr.put(&id, &wrong_kappa, b"real content");
        assert!(result.is_err(), "mismatched digest rejected");
    }
}
