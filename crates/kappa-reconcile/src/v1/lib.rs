use std::collections::BTreeMap;

use merkle_search_tree::MerkleSearchTree;
use merkle_search_tree::diff::PageRangeSnapshot;
use merkle_search_tree::digest::{Digest, Hasher};

#[derive(Debug, Clone)]
pub struct Blake3Hasher;

impl<T: AsRef<[u8]>> Hasher<32, T> for Blake3Hasher {
    fn hash(&self, value: &T) -> Digest<32> {
        Digest::new(*blake3::hash(value.as_ref()).as_bytes())
    }
}

#[derive(Debug)]
pub struct ReconciliationDiff {
    pub inconsistent_ranges: Vec<InconsistentRange>,
}

#[derive(Debug, Clone)]
pub struct InconsistentRange {
    pub start: String,
    pub end: String,
}

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

    pub fn rebuild(&mut self, tags: &BTreeMap<String, String>) {
        self.tree = merkle_search_tree::builder::Builder::default()
            .with_hasher(Blake3Hasher)
            .build();
        for (name, kappa) in tags {
            self.tree.upsert(name.clone(), kappa);
        }
    }

    pub fn upsert(&mut self, name: &str, kappa: &str) {
        self.tree.upsert(name.to_owned(), &kappa.to_owned());
    }

    pub fn root_hash(&mut self) -> [u8; 16] {
        *self.tree.root_hash().as_bytes()
    }

    pub fn root_hash_cached(&self) -> Option<[u8; 16]> {
        self.tree.root_hash_cached().map(|r| *r.as_bytes())
    }

    pub fn snapshot(&mut self) -> Result<MstSnapshot, ReconcileError> {
        self.root_hash();
        let ranges = self
            .tree
            .serialise_page_ranges()
            .ok_or(ReconcileError::TreeNotHashed)?;
        Ok(MstSnapshot {
            namespace: self.namespace.clone(),
            snapshot: ranges.into_iter().collect(),
        })
    }

    pub fn diff(&mut self, remote: &MstSnapshot) -> Result<ReconciliationDiff, ReconcileError> {
        if remote.namespace != self.namespace {
            return Err(ReconcileError::NamespaceMismatch {
                local: self.namespace.clone(),
                remote: remote.namespace.clone(),
            });
        }
        self.root_hash();
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
