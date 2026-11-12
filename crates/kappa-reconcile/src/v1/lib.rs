//! Tag reconciliation between two copies of a namespace over a Merkle
//! search tree, and the two seams a reconciliation round needs: the peers
//! it talks to (`membership`) and the transport it talks over
//! (`transport`).
//!
//! The diff contract is `merkle_search_tree::diff::diff`: given the local
//! tree's page ranges and a peer's, it returns the inclusive key ranges of
//! the peer that the local tree must fetch to converge. A one-way pull may
//! never terminate (the crate's own documentation); convergence requires
//! both directions. Every key of the peer inside a returned range must be
//! fetched, not only the keys the local tree already holds there: a key
//! only the peer has lies strictly inside such a range and is exactly what
//! the diff found.

pub mod membership;
pub mod transport;

use std::collections::BTreeMap;

use merkle_search_tree::MerkleSearchTree;
use merkle_search_tree::diff::{OwnedPageRange, PageRangeSnapshot};
use merkle_search_tree::digest::{Digest, Hasher, PageDigest};

pub use membership::{
    MemberRecord, MemberRole, MembershipState, MembershipView, PeerInfo, PeerSource,
    StaticMembership,
};
pub use transport::{NoOpTransport, ReconcileTransport, TransportError};

#[derive(Debug, Clone)]
pub struct Blake3Hasher;

impl<T: AsRef<[u8]>> Hasher<32, T> for Blake3Hasher {
    fn hash(&self, value: &T) -> Digest<32> {
        Digest::new(*blake3::hash(value.as_ref()).as_bytes())
    }
}

/// The key ranges of a peer's tree the local tree must fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReconciliationDiff {
    pub inconsistent_ranges: Vec<InconsistentRange>,
}

impl ReconciliationDiff {
    /// Nothing to fetch: the local tree is a superset of the peer's, or
    /// the two are identical.
    pub fn is_empty(&self) -> bool {
        self.inconsistent_ranges.is_empty()
    }

    /// Whether `key` lies in a range that must be fetched.
    pub fn covers(&self, key: &str) -> bool {
        self.inconsistent_ranges
            .iter()
            .any(|range| range.start.as_str() <= key && key <= range.end.as_str())
    }
}

/// An inclusive key range of the peer to fetch in full.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Replace the tree's contents with `tags` (name to content identity).
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
        self.tree.root_hash_cached().map(|root| *root.as_bytes())
    }

    /// An owned snapshot of this tree's page ranges, for a peer to diff
    /// against or for the wire (`MstSnapshot::to_wire`).
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

    /// The ranges of `remote` this tree must fetch to converge toward it.
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
        let inconsistent_ranges =
            merkle_search_tree::diff::diff(local_ranges, remote.snapshot.iter())
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

/// One page range as it crosses the wire: the inclusive key bounds and
/// the page digest. `MstSnapshot::from_wire` rebuilds a snapshot from a
/// peer's list, refusing a range whose start exceeds its end before the
/// tree's own constructor would panic on it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct WirePageRange {
    pub start: String,
    pub end: String,
    pub hash: [u8; 16],
}

/// A point-in-time snapshot of one namespace tree's page ranges.
#[derive(Debug, Clone, PartialEq)]
pub struct MstSnapshot {
    pub namespace: String,
    pub snapshot: PageRangeSnapshot<String>,
}

impl MstSnapshot {
    /// The wire form of every page range, in tree order.
    pub fn to_wire(&self) -> Vec<WirePageRange> {
        self.snapshot
            .iter()
            .map(|range| WirePageRange {
                start: range.start().clone(),
                end: range.end().clone(),
                hash: *range.hash().as_bytes(),
            })
            .collect()
    }

    /// A snapshot of `namespace` from a peer's wire ranges. An empty list
    /// is an empty tree, against which a diff fetches nothing.
    pub fn from_wire(
        namespace: String,
        ranges: Vec<WirePageRange>,
    ) -> Result<Self, ReconcileError> {
        let mut owned = Vec::with_capacity(ranges.len());
        for range in ranges {
            if range.start > range.end {
                return Err(ReconcileError::InvalidRange {
                    start: range.start,
                    end: range.end,
                });
            }
            owned.push(OwnedPageRange::new(
                range.start,
                range.end,
                PageDigest::new(range.hash),
            ));
        }
        Ok(Self {
            namespace,
            snapshot: PageRangeSnapshot::from(owned),
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ReconcileError {
    #[error("tree not hashed: call root_hash() before snapshotting or diffing")]
    TreeNotHashed,
    #[error("namespace mismatch: local '{local}' vs remote '{remote}'")]
    NamespaceMismatch { local: String, remote: String },
    #[error("page range start '{start}' exceeds its end '{end}'")]
    InvalidRange { start: String, end: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn tree(namespace: &str, names: &[&str]) -> NamespaceMst {
        let mut tree = NamespaceMst::new(namespace.to_owned());
        for name in names {
            tree.upsert(name, &format!("sha256:{name}"));
        }
        tree
    }

    /// The case the initiator must handle: a key only the peer holds,
    /// strictly between two keys both hold. The diff covers it; an
    /// initiator that fetches only the local names of the range misses it.
    #[test]
    fn a_remote_only_key_strictly_inside_a_range_is_covered() -> TestResult {
        let mut local = tree("images", &["a", "m", "z"]);
        let mut remote = tree("images", &["a", "m", "q", "z"]);
        let diff = local.diff(&remote.snapshot()?)?;
        assert!(!diff.is_empty(), "the trees differ");
        assert!(diff.covers("q"), "{diff:?}");
        let own = local.snapshot()?;
        assert!(local.diff(&own)?.is_empty(), "a tree against itself");
        Ok(())
    }

    /// A local superset fetches nothing, by the diff contract; the other
    /// direction fetches the missing key. Convergence is two directions.
    #[test]
    fn a_local_superset_fetches_nothing_and_the_peer_fetches_the_rest() -> TestResult {
        let mut superset = tree("charts", &["a", "b", "c"]);
        let mut subset = tree("charts", &["a", "c"]);
        assert!(superset.diff(&subset.snapshot()?)?.is_empty());
        let other_way = subset.diff(&superset.snapshot()?)?;
        assert!(other_way.covers("b"), "{other_way:?}");
        Ok(())
    }

    #[test]
    fn wire_form_round_trips_and_refuses_an_inverted_range() -> TestResult {
        let mut tree = tree("ns", &["alpha", "beta", "gamma"]);
        let snapshot = tree.snapshot()?;
        let wire = snapshot.to_wire();
        assert!(!wire.is_empty());
        let rebuilt = MstSnapshot::from_wire("ns".into(), wire)?;
        assert_eq!(rebuilt, snapshot);
        assert!(
            tree.diff(&rebuilt)?.is_empty(),
            "a tree matches its own wire snapshot"
        );
        let inverted = vec![WirePageRange {
            start: "b".into(),
            end: "a".into(),
            hash: [0; 16],
        }];
        match MstSnapshot::from_wire("ns".into(), inverted) {
            Err(ReconcileError::InvalidRange { start, end }) => {
                assert_eq!((start.as_str(), end.as_str()), ("b", "a"));
            }
            other => return Err(format!("expected InvalidRange, got {other:?}").into()),
        }
        let empty = MstSnapshot::from_wire("ns".into(), Vec::new())?;
        assert!(
            tree.diff(&empty)?.is_empty(),
            "nothing to fetch from an empty peer"
        );
        Ok(())
    }

    #[test]
    fn a_namespace_mismatch_is_refused_before_any_diff() -> TestResult {
        let mut local = tree("a", &["x"]);
        let mut other = tree("b", &["x"]);
        match local.diff(&other.snapshot()?) {
            Err(ReconcileError::NamespaceMismatch { local, remote }) => {
                assert_eq!((local.as_str(), remote.as_str()), ("a", "b"));
            }
            other => return Err(format!("expected NamespaceMismatch, got {other:?}").into()),
        }
        Ok(())
    }
}
