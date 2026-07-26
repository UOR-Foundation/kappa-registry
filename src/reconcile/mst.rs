//! Merkle search tree for tag-name reconciliation.
//!
//! Uses the domodwyer/merkle-search-tree crate with a Blake3 hasher
//! (NOT the default SipHash, which is not collision-resistant).
//!
//! The MST provides `diff()` over `serialise_page_ranges()` for
//! identifying inconsistent tag-name ranges between peers.
//! It does NOT provide inclusion proofs (the crate has no path-to-leaf
//! API). Inclusion proofs come from AKD.
//!
//! The MST is deterministic: the same set of (name, value) pairs
//! always produces the same root hash regardless of insertion order.

use std::collections::BTreeMap;

use merkle_search_tree::diff::{PageRange, PageRangeSnapshot};
use merkle_search_tree::digest::{Digest, Hasher};
use merkle_search_tree::MerkleSearchTree;

/// Blake3 hasher for the MST.
///
/// Replaces the default SipHash-128 which is not collision-resistant.
/// All peers MUST use the same hasher for reconciliation to work.
#[derive(Debug, Clone)]
pub struct Blake3Hasher;

impl<T: AsRef<[u8]>> Hasher<32, T> for Blake3Hasher {
    fn hash(&self, value: &T) -> Digest<32> {
        let h = blake3::hash(value.as_ref());
        Digest::new(*h.as_bytes())
    }
}

/// A namespace MST mapping tag names to tag values.
///
/// The tree is deterministic: rebuilding from the same set of (name, value)
/// pairs always produces the same root hash regardless of order.
pub struct NamespaceMst {
    tree: MerkleSearchTree<String, String, Blake3Hasher, 32>,
}

impl NamespaceMst {
    pub fn new() -> Self {
        Self {
            tree: merkle_search_tree::builder::Builder::default()
                .with_hasher(Blake3Hasher)
                .build(),
        }
    }

    /// Rebuild the MST from a tag index.
    pub fn rebuild_from_index(&mut self, index: &BTreeMap<String, String>) {
        self.tree = merkle_search_tree::builder::Builder::default()
            .with_hasher(Blake3Hasher)
            .build();
        for (name, value) in index {
            self.tree.upsert(name.clone(), value);
        }
    }

    /// Insert or update a single tag.
    pub fn upsert(&mut self, name: &str, value: &str) {
        self.tree.upsert(name.to_owned(), &value.to_owned());
    }

    /// Root hash. First call computes (O(N)); subsequent calls are O(1)
    /// if the tree has not been modified.
    ///
    /// Returns 16 bytes: the MST's page/root hashing is always 128-bit
    /// (SipHash24 internally) regardless of the value hasher's output size.
    pub fn root_hash(&mut self) -> [u8; 16] {
        let root = self.tree.root_hash();
        *root.as_bytes()
    }

    /// Cached root hash. Returns None if tree has been modified since
    /// last hash computation.
    pub fn root_hash_cached(&self) -> Option<[u8; 16]> {
        self.tree.root_hash_cached().map(|r| *r.as_bytes())
    }

    /// Serialize page ranges for reconciliation exchange.
    ///
    /// Returns None if tree needs rehashing (call root_hash first).
    pub fn page_ranges(&self) -> Option<Vec<PageRange<'_, String>>> {
        self.tree.serialise_page_ranges()
    }

    /// Create a snapshot of page ranges for storage/transmission.
    pub fn page_range_snapshot(&mut self) -> PageRangeSnapshot<String> {
        let _ = self.root_hash(); // ensure hashed
        self.tree
            .serialise_page_ranges()
            .expect("root_hash was just called")
            .into_iter()
            .collect()
    }
}

impl Default for NamespaceMst {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use merkle_search_tree::diff::diff;

    #[test]
    fn deterministic_root() {
        let mut index = BTreeMap::new();
        index.insert("alpha".to_owned(), "sha256:aaa".to_owned());
        index.insert("beta".to_owned(), "sha256:bbb".to_owned());

        let mut mst1 = NamespaceMst::new();
        mst1.rebuild_from_index(&index);
        let root1 = mst1.root_hash();

        let mut mst2 = NamespaceMst::new();
        mst2.rebuild_from_index(&index);
        let root2 = mst2.root_hash();

        assert_eq!(root1, root2);
    }

    #[test]
    fn insertion_order_independent() {
        let mut mst1 = NamespaceMst::new();
        mst1.upsert("alpha", "sha256:aaa");
        mst1.upsert("beta", "sha256:bbb");
        let root1 = mst1.root_hash();

        let mut mst2 = NamespaceMst::new();
        mst2.upsert("beta", "sha256:bbb");
        mst2.upsert("alpha", "sha256:aaa");
        let root2 = mst2.root_hash();

        assert_eq!(root1, root2);
    }

    #[test]
    fn upsert_changes_root() {
        let mut mst = NamespaceMst::new();
        mst.upsert("alpha", "sha256:aaa");
        let root1 = mst.root_hash();

        mst.upsert("beta", "sha256:bbb");
        let root2 = mst.root_hash();

        assert_ne!(root1, root2);
    }

    #[test]
    fn cached_root_none_after_modification() {
        let mut mst = NamespaceMst::new();
        mst.upsert("alpha", "sha256:aaa");
        let _ = mst.root_hash();
        assert!(mst.root_hash_cached().is_some());

        mst.upsert("beta", "sha256:bbb");
        assert!(mst.root_hash_cached().is_none());
    }

    #[test]
    fn page_ranges_available_after_hash() {
        let mut mst = NamespaceMst::new();
        mst.upsert("alpha", "sha256:aaa");
        mst.upsert("beta", "sha256:bbb");

        assert!(mst.page_ranges().is_none()); // not hashed yet
        let _ = mst.root_hash();
        assert!(mst.page_ranges().is_some());
    }

    #[test]
    fn diff_identical_trees_empty() {
        let mut mst1 = NamespaceMst::new();
        mst1.upsert("alpha", "sha256:aaa");
        mst1.upsert("beta", "sha256:bbb");
        let snapshot1 = mst1.page_range_snapshot();

        let mut mst2 = NamespaceMst::new();
        mst2.upsert("alpha", "sha256:aaa");
        mst2.upsert("beta", "sha256:bbb");
        let _ = mst2.root_hash();

        let local_ranges = mst2.page_ranges().unwrap();
        let diff_result = diff(local_ranges, snapshot1.iter());
        assert!(diff_result.is_empty());
    }

    #[test]
    fn diff_detects_inconsistency() {
        let mut mst1 = NamespaceMst::new();
        mst1.upsert("alpha", "sha256:aaa");
        mst1.upsert("beta", "sha256:bbb");
        let snapshot1 = mst1.page_range_snapshot();

        let mut mst2 = NamespaceMst::new();
        mst2.upsert("alpha", "sha256:aaa");
        mst2.upsert("beta", "sha256:DIFFERENT");
        let _ = mst2.root_hash();

        let local_ranges = mst2.page_ranges().unwrap();
        let diff_result = diff(local_ranges, snapshot1.iter());
        assert!(!diff_result.is_empty());
    }
}
