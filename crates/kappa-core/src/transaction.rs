//! Multi-object transaction with quarantine staging and atomic promotion.
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
use crate::store::KappaStore;

#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("transaction not found")]
    NotFound,
    #[error("max concurrent transactions ({0}) reached")]
    AtCapacity(usize),
    #[error("per-transaction staging limit ({0} bytes) exceeded")]
    PerTxnLimitExceeded(usize),
    #[error("global staging limit ({0} bytes) exceeded")]
    GlobalLimitExceeded(usize),
    #[error("content hash mismatch for {0}")]
    DigestMismatch(String),
    #[error("invalid kappa-label {kappa}: {reason}")]
    InvalidLabel { kappa: String, reason: String },
}

/// Result of a successful transaction commit.
#[derive(Debug)]
pub struct CommitResult {
    pub promoted: Vec<String>,
}

/// Transaction manager state.
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
    pub fn begin(&self, ns: &str) -> Result<String, TransactionError> {
        let count = self.active_count.load(Ordering::Relaxed);
        if count >= self.max_concurrent {
            return Err(TransactionError::AtCapacity(self.max_concurrent));
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
    pub fn put(&self, txn_id: &str, kappa: &str, content: &[u8]) -> Result<bool, TransactionError> {
        match verify_kappa(kappa, content) {
            Ok(true) => {}
            Ok(false) => {
                return Err(TransactionError::DigestMismatch(kappa.to_string()));
            }
            Err(e) => {
                return Err(TransactionError::InvalidLabel {
                    kappa: kappa.to_string(),
                    reason: e.to_string(),
                });
            }
        }

        let content_len = content.len();

        // Check per-transaction byte limit
        {
            let map = self.active.read().unwrap();
            let state = map.get(txn_id).ok_or(TransactionError::NotFound)?;
            if state.staging_bytes + content_len > self.max_bytes_per_txn {
                return Err(TransactionError::PerTxnLimitExceeded(
                    self.max_bytes_per_txn,
                ));
            }
        }

        // Check global byte limit
        let global = self.total_staging_bytes.load(Ordering::Relaxed);
        if global + content_len > self.max_bytes_global {
            return Err(TransactionError::GlobalLimitExceeded(self.max_bytes_global));
        }

        // Create staging dir lazily
        let staging_dir = self.staging_dir(txn_id);
        {
            let mut map = self.active.write().unwrap();
            let state = map.get_mut(txn_id).ok_or(TransactionError::NotFound)?;
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
        main_store: &dyn KappaStore,
    ) -> Result<CommitResult, TransactionError> {
        let staging_dir = self.staging_dir(txn_id);
        let staging_bytes;

        // Verify transaction exists
        {
            let map = self.active.read().unwrap();
            let state = map.get(txn_id).ok_or(TransactionError::NotFound)?;
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
            main_store
                .blob_put(kappa, &content)
                .map_err(|e| TransactionError::Io(std::io::Error::other(e.to_string())))?;
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
    pub fn abort(&self, txn_id: &str) -> Result<(), TransactionError> {
        let staging_dir = self.staging_dir(txn_id);
        let staging_bytes;

        {
            let map = self.active.read().unwrap();
            let state = map.get(txn_id).ok_or(TransactionError::NotFound)?;
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

    /// Number of active transactions.
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

/// Write data to a file atomically: write to .tmp, then rename.
fn atomic_write(path: &Path, data: &[u8]) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// List all staged blobs in a staging directory.
/// Returns (kappa-label, file path) pairs.
fn list_staged_blobs(staging_dir: &Path) -> Result<Vec<(String, PathBuf)>, std::io::Error> {
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
    use crate::clock::ntp_lamport::NtpLamportClock;
    use crate::kappa::KappaLabel;
    use crate::store::memory::{InMemoryStore, MemoryStoreConfig};
    use std::sync::Arc;

    fn test_manager(dir: &Path) -> TransactionManager {
        TransactionManager::new(
            dir.to_path_buf(),
            4,    // max 4 concurrent
            1024, // max 1 KiB per txn
            4096, // max 4 KiB global
            1,    // 1 second timeout for reaper tests
        )
    }

    fn test_store(dir: &Path) -> Arc<InMemoryStore> {
        let clock = Arc::new(NtpLamportClock::new());
        Arc::new(
            InMemoryStore::new(
                MemoryStoreConfig {
                    blob_root: dir.join("blobs"),
                },
                clock,
            )
            .unwrap(),
        )
    }

    fn test_kappa(content: &[u8]) -> String {
        KappaLabel::sha256(content).as_str().to_string()
    }

    #[test]
    fn begin_returns_unique_ids() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager(dir.path());
        let id1 = mgr.begin("ns").unwrap();
        let id2 = mgr.begin("ns").unwrap();
        assert_ne!(id1, id2);
        assert_eq!(mgr.active_count(), 2);
    }

    #[test]
    fn max_concurrent_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager(dir.path());
        for _ in 0..4 {
            mgr.begin("ns").unwrap();
        }
        assert_eq!(mgr.active_count(), 4);
        let result = mgr.begin("ns");
        assert!(result.is_err(), "5th transaction should be rejected");
    }

    #[test]
    fn per_txn_byte_limit_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager(dir.path());
        let id = mgr.begin("ns").unwrap();

        let small = vec![0x41u8; 512];
        let small_k = test_kappa(&small);
        assert!(mgr.put(&id, &small_k, &small).is_ok());

        let big = vec![0x42u8; 600];
        let big_k = test_kappa(&big);
        let result = mgr.put(&id, &big_k, &big);
        assert!(result.is_err(), "should exceed per-txn limit");
    }

    #[test]
    fn abort_frees_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager(dir.path());

        let ids: Vec<String> = (0..4).map(|_| mgr.begin("ns").unwrap()).collect();
        assert!(mgr.begin("ns").is_err(), "at capacity");

        mgr.abort(&ids[0]).unwrap();
        assert_eq!(mgr.active_count(), 3);
        assert!(mgr.begin("ns").is_ok(), "slot freed by abort");
    }

    #[test]
    fn commit_promotes_to_store() {
        let dir = tempfile::tempdir().unwrap();
        let store = test_store(dir.path());
        let mgr = test_manager(dir.path());

        let id = mgr.begin("ns").unwrap();
        let content = b"commit-promotes";
        let k = test_kappa(content);
        mgr.put(&id, &k, content).unwrap();
        mgr.commit(&id, &*store).unwrap();

        assert_eq!(mgr.active_count(), 0);
        assert!(store.blob_exists(&k).unwrap());
    }

    #[test]
    fn commit_empty_transaction_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let store = test_store(dir.path());
        let mgr = test_manager(dir.path());

        let id = mgr.begin("ns").unwrap();
        let result = mgr.commit(&id, &*store).unwrap();
        assert!(result.promoted.is_empty());
        assert_eq!(mgr.active_count(), 0);
    }

    #[test]
    fn lazy_staging_dir_creation() {
        let dir = tempfile::tempdir().unwrap();
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
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager(dir.path());
        let id = mgr.begin("ns").unwrap();

        let wrong_kappa = format!("sha256:{}", "0".repeat(64));
        let result = mgr.put(&id, &wrong_kappa, b"real content");
        assert!(result.is_err(), "mismatched digest rejected");
    }

    #[test]
    fn put_to_nonexistent_transaction_fails() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager(dir.path());
        let content = b"no-txn";
        let k = test_kappa(content);
        let result = mgr.put("nonexistent-id", &k, content);
        assert!(result.is_err());
    }

    #[test]
    fn startup_cleanup_removes_orphaned_staging() {
        let dir = tempfile::tempdir().unwrap();
        let orphan_dir = dir.path().join("staging").join("orphaned-txn");
        std::fs::create_dir_all(&orphan_dir).unwrap();
        std::fs::write(orphan_dir.join("leftover"), b"data").unwrap();

        let _mgr = test_manager(dir.path());
        assert!(
            !orphan_dir.exists(),
            "orphaned staging dir removed on startup"
        );
    }

    #[test]
    fn evict_expired_removes_old_transactions() {
        let dir = tempfile::tempdir().unwrap();
        let mgr = test_manager(dir.path()); // 1 second timeout

        let id = mgr.begin("ns").unwrap();
        let content = b"will-expire";
        let k = test_kappa(content);
        mgr.put(&id, &k, content).unwrap();

        // Wait for expiry. elapsed().as_secs() truncates, and the check
        // is > timeout_secs (strictly greater), so we need >2 seconds
        // elapsed for a 1-second timeout.
        std::thread::sleep(std::time::Duration::from_millis(2100));

        let evicted = mgr.evict_expired();
        assert_eq!(evicted, 1);
        assert_eq!(mgr.active_count(), 0);

        let staging = dir.path().join("staging").join(&id);
        assert!(!staging.exists(), "staging dir removed after eviction");
    }
}
