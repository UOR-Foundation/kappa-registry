//! Merkle search tree reconciliation for kappa-registry federation.
//!
//! Provides deterministic tag-name diff between peers using a Blake3-backed
//! MST. The same set of (name, kappa) pairs always produces the same root
//! hash regardless of insertion order.

use std::collections::BTreeMap;

use merkle_search_tree::diff::PageRangeSnapshot;
use merkle_search_tree::digest::{Digest, Hasher};
use merkle_search_tree::MerkleSearchTree;

/// Blake3 hasher for collision-resistant MST node hashing.
#[derive(Debug, Clone)]
pub struct Blake3Hasher;

impl<T: AsRef<[u8]>> Hasher<32, T> for Blake3Hasher {
    fn hash(&self, value: &T) -> Digest<32> {
        Digest::new(*blake3::hash(value.as_ref()).as_bytes())
    }
}

/// Result of comparing two namespace MSTs.
#[derive(Debug)]
pub struct ReconciliationDiff {
    /// Keys that differ between local and remote.
    pub inconsistent_ranges: Vec<InconsistentRange>,
}

/// A range of keys where local and remote state diverge.
#[derive(Debug, Clone)]
pub struct InconsistentRange {
    /// The smallest key in the inconsistent range.
    pub start: String,
    /// The largest key in the inconsistent range.
    pub end: String,
}

/// A namespace-scoped Merkle search tree for tag reconciliation.
///
/// Maps tag names to kappa-labels. Deterministic: the same set of
/// (name, kappa) pairs always produces the same root hash.
pub struct NamespaceMst {
    namespace: String,
    tree: MerkleSearchTree<String, String, Blake3Hasher, 32>,
}

impl NamespaceMst {
    pub fn new(namespace: String) -> Self {
        Self {
            namespace,
            tree: merkle_search_tree::builder::Builder::default()
                .with_hasher(Blake3Hasher)
                .build(),
        }
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Rebuild the tree from a complete tag index.
    pub fn rebuild(&mut self, tags: &BTreeMap<String, String>) {
        self.tree = merkle_search_tree::builder::Builder::default()
            .with_hasher(Blake3Hasher)
            .build();
        for (name, kappa) in tags {
            self.tree.upsert(name.clone(), kappa);
        }
    }

    /// Insert or update a single tag binding.
    pub fn upsert(&mut self, name: &str, kappa: &str) {
        self.tree.upsert(name.to_owned(), &kappa.to_owned());
    }

    /// Compute and return the root hash.
    ///
    /// First call after modification is O(N). Subsequent calls without
    /// modification are O(1).
    pub fn root_hash(&mut self) -> [u8; 16] {
        *self.tree.root_hash().as_bytes()
    }

    /// Return the cached root hash without recomputation.
    /// Returns None if the tree has been modified since last hash.
    pub fn root_hash_cached(&self) -> Option<[u8; 16]> {
        self.tree.root_hash_cached().map(|r| *r.as_bytes())
    }

    /// Create a snapshot of page ranges for transmission to a peer.
    ///
    /// Ensures the tree is hashed before snapshotting.
    pub fn snapshot(&mut self) -> Result<MstSnapshot, ReconcileError> {
        let _ = self.root_hash();
        let ranges = self
            .tree
            .serialise_page_ranges()
            .ok_or(ReconcileError::TreeNotHashed)?;
        Ok(MstSnapshot {
            namespace: self.namespace.clone(),
            snapshot: ranges.into_iter().collect(),
        })
    }

    /// Diff this tree against a remote peer's snapshot.
    ///
    /// Returns the ranges where local and remote state diverge.
    /// The tree must be hashed before diffing.
    pub fn diff(&mut self, remote: &MstSnapshot) -> Result<ReconciliationDiff, ReconcileError> {
        if remote.namespace != self.namespace {
            return Err(ReconcileError::NamespaceMismatch {
                local: self.namespace.clone(),
                remote: remote.namespace.clone(),
            });
        }

        let _ = self.root_hash();
        let local_ranges = self
            .tree
            .serialise_page_ranges()
            .ok_or(ReconcileError::TreeNotHashed)?;

        let diff_ranges = merkle_search_tree::diff::diff(local_ranges, remote.snapshot.iter());

        let inconsistent_ranges = diff_ranges
            .into_iter()
            .map(|range| InconsistentRange {
                start: range.start().clone(),
                end: range.end().clone(),
            })
            .collect();

        Ok(ReconciliationDiff {
            inconsistent_ranges,
        })
    }
}

/// A serializable snapshot of an MST's page ranges.
pub struct MstSnapshot {
    pub namespace: String,
    pub snapshot: PageRangeSnapshot<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ReconcileError {
    #[error("tree not hashed: call root_hash() before snapshotting or diffing")]
    TreeNotHashed,
    #[error("namespace mismatch: local '{local}' vs remote '{remote}'")]
    NamespaceMismatch { local: String, remote: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_root() {
        let mut index = BTreeMap::new();
        index.insert("alpha".to_owned(), "sha256:aaa".to_owned());
        index.insert("beta".to_owned(), "sha256:bbb".to_owned());

        let mut mst1 = NamespaceMst::new("ns".into());
        mst1.rebuild(&index);
        let root1 = mst1.root_hash();

        let mut mst2 = NamespaceMst::new("ns".into());
        mst2.rebuild(&index);
        let root2 = mst2.root_hash();

        assert_eq!(root1, root2);
    }

    #[test]
    fn insertion_order_independent() {
        let mut mst1 = NamespaceMst::new("ns".into());
        mst1.upsert("alpha", "sha256:aaa");
        mst1.upsert("beta", "sha256:bbb");
        let root1 = mst1.root_hash();

        let mut mst2 = NamespaceMst::new("ns".into());
        mst2.upsert("beta", "sha256:bbb");
        mst2.upsert("alpha", "sha256:aaa");
        let root2 = mst2.root_hash();

        assert_eq!(root1, root2);
    }

    #[test]
    fn upsert_changes_root() {
        let mut mst = NamespaceMst::new("ns".into());
        mst.upsert("alpha", "sha256:aaa");
        let root1 = mst.root_hash();

        mst.upsert("beta", "sha256:bbb");
        let root2 = mst.root_hash();

        assert_ne!(root1, root2);
    }

    #[test]
    fn cached_root_cleared_on_modification() {
        let mut mst = NamespaceMst::new("ns".into());
        mst.upsert("alpha", "sha256:aaa");
        let _ = mst.root_hash();
        assert!(mst.root_hash_cached().is_some());

        mst.upsert("beta", "sha256:bbb");
        assert!(mst.root_hash_cached().is_none());
    }

    #[test]
    fn snapshot_requires_hash() {
        let mut mst = NamespaceMst::new("ns".into());
        mst.upsert("alpha", "sha256:aaa");
        // snapshot calls root_hash internally, so it succeeds
        assert!(mst.snapshot().is_ok());
    }

    #[test]
    fn diff_identical_trees_empty() {
        let mut mst1 = NamespaceMst::new("ns".into());
        mst1.upsert("alpha", "sha256:aaa");
        mst1.upsert("beta", "sha256:bbb");
        let snap1 = mst1.snapshot().unwrap();

        let mut mst2 = NamespaceMst::new("ns".into());
        mst2.upsert("alpha", "sha256:aaa");
        mst2.upsert("beta", "sha256:bbb");

        let diff = mst2.diff(&snap1).unwrap();
        assert!(diff.inconsistent_ranges.is_empty());
    }

    #[test]
    fn diff_detects_inconsistency() {
        let mut mst1 = NamespaceMst::new("ns".into());
        mst1.upsert("alpha", "sha256:aaa");
        mst1.upsert("beta", "sha256:bbb");
        let snap1 = mst1.snapshot().unwrap();

        let mut mst2 = NamespaceMst::new("ns".into());
        mst2.upsert("alpha", "sha256:aaa");
        mst2.upsert("beta", "sha256:DIFFERENT");

        let diff = mst2.diff(&snap1).unwrap();
        assert!(!diff.inconsistent_ranges.is_empty());
    }

    #[test]
    fn diff_rejects_namespace_mismatch() {
        let mut mst1 = NamespaceMst::new("ns1".into());
        mst1.upsert("a", "v");
        let snap = mst1.snapshot().unwrap();

        let mut mst2 = NamespaceMst::new("ns2".into());
        mst2.upsert("a", "v");

        assert!(matches!(
            mst2.diff(&snap),
            Err(ReconcileError::NamespaceMismatch { .. })
        ));
    }

    #[test]
    fn empty_tree() {
        let mut mst = NamespaceMst::new("ns".into());
        let root = mst.root_hash();
        assert_ne!(root, [0u8; 16]);
    }

    #[test]
    fn namespace_accessor() {
        let mst = NamespaceMst::new("test/ns".into());
        assert_eq!(mst.namespace(), "test/ns");
    }
}
