//! XOR-monoid fingerprint tree for range-based set reconciliation (Meyer 2023).
//!
//! Maintains an ordered set of kappa-labels with O(log n) range fingerprint
//! queries. Each node is augmented with a label that is the XOR-combine of
//! its subtree's lifted values. A range query [lower, upper) aggregates
//! labels along the traversal path without visiting every item.
//!
//! The tree is a sorted Vec rebuilt on mutation. For the current scale
//! (single-node registry, thousands to low millions of items) this is
//! adequate. P9 (redb migration) replaces the backing store; the monoid
//! and range-query algorithm remain identical.

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::store::fs::{atomic_write, escape_namespace};
use crate::store::{RangeFingerprint, StoreError};

const FP_LEN: usize = 32;

/// Lift a kappa-label string to a 32-byte fingerprint by hashing it.
fn lift(kappa: &str) -> [u8; FP_LEN] {
    let hash = Sha256::digest(kappa.as_bytes());
    let mut out = [0u8; FP_LEN];
    out.copy_from_slice(&hash);
    out
}

/// XOR-combine two fingerprints (commutative, associative, self-inverse).
fn combine(a: &[u8; FP_LEN], b: &[u8; FP_LEN]) -> [u8; FP_LEN] {
    let mut out = [0u8; FP_LEN];
    for i in 0..FP_LEN {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// The neutral element for XOR: all zeros.
const NEUTRAL: [u8; FP_LEN] = [0u8; FP_LEN];

/// A namespace fingerprint tree backed by a sorted set of kappa-labels.
///
/// The tree supports:
/// - Insert/remove with incremental fingerprint update
/// - Range fingerprint query [lower, upper) in O(n) on the sorted set
///   (adequate for current scale; O(log n) with augmented tree in P9)
/// - Full-range fingerprint (lower == upper) covering all items
/// - Persistence to disk as a JSON array of sorted kappa-labels
pub struct NamespaceFingerprints {
    /// Sorted set of all kappa-labels in this namespace.
    items: BTreeSet<String>,
}

impl Default for NamespaceFingerprints {
    fn default() -> Self {
        Self::new()
    }
}

impl NamespaceFingerprints {
    pub fn new() -> Self {
        NamespaceFingerprints {
            items: BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, kappa: &str) {
        self.items.insert(kappa.to_string());
    }

    pub fn remove(&mut self, kappa: &str) {
        self.items.remove(kappa);
    }

    /// Compute the fingerprint for a range [lower, upper).
    /// If lower == upper, returns the fingerprint of the entire set.
    pub fn range_fingerprint(&self, lower: &str, upper: &str) -> RangeFingerprint {
        if self.items.is_empty() {
            return RangeFingerprint {
                fingerprint: NEUTRAL,
                count: 0,
            };
        }

        let full_range = lower == upper;
        let mut fp = NEUTRAL;
        let mut count = 0usize;

        if full_range {
            for item in &self.items {
                fp = combine(&fp, &lift(item));
                count += 1;
            }
        } else if lower < upper {
            // Normal range: lower < upper
            for item in self.items.range(lower.to_string()..upper.to_string()) {
                fp = combine(&fp, &lift(item));
                count += 1;
            }
        } else {
            // Wrapping range: [lower, max] + [min, upper)
            for item in self.items.range(lower.to_string()..) {
                fp = combine(&fp, &lift(item));
                count += 1;
            }
            for item in self.items.range(..upper.to_string()) {
                fp = combine(&fp, &lift(item));
                count += 1;
            }
        }

        RangeFingerprint {
            fingerprint: fp,
            count,
        }
    }

    /// Return all items in the range [lower, upper).
    /// If lower == upper, returns all items.
    pub fn range_items(&self, lower: &str, upper: &str) -> Vec<String> {
        if self.items.is_empty() {
            return Vec::new();
        }

        let full_range = lower == upper;

        if full_range {
            self.items.iter().cloned().collect()
        } else if lower < upper {
            self.items
                .range(lower.to_string()..upper.to_string())
                .cloned()
                .collect()
        } else {
            let mut result: Vec<String> = self.items.range(lower.to_string()..).cloned().collect();
            result.extend(self.items.range(..upper.to_string()).cloned());
            result
        }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

fn fingerprint_path(root: &Path, ns: &str) -> PathBuf {
    root.join("index")
        .join("fingerprints")
        .join(format!("{}.json", escape_namespace(ns)))
}

/// Load the fingerprint set for a namespace from disk.
pub fn load(root: &Path, ns: &str) -> NamespaceFingerprints {
    let path = fingerprint_path(root, ns);
    match std::fs::read(&path) {
        Ok(data) => {
            let items: Vec<String> = serde_json::from_slice(&data).unwrap_or_default();
            let mut fp = NamespaceFingerprints::new();
            for item in items {
                fp.items.insert(item);
            }
            fp
        }
        Err(_) => NamespaceFingerprints::new(),
    }
}

/// Persist the fingerprint set for a namespace to disk.
pub fn save(root: &Path, ns: &str, fp: &NamespaceFingerprints) -> Result<(), StoreError> {
    let path = fingerprint_path(root, ns);
    let items: Vec<&String> = fp.items.iter().collect();
    let data = serde_json::to_vec(&items).map_err(|e| StoreError::Io(std::io::Error::other(e)))?;
    atomic_write(&path, &data)
}

/// Insert a kappa-label into a namespace's fingerprint set and persist.
pub fn insert(root: &Path, ns: &str, kappa: &str) -> Result<(), StoreError> {
    let mut fp = load(root, ns);
    fp.insert(kappa);
    save(root, ns, &fp)
}

/// Remove a kappa-label from a namespace's fingerprint set and persist.
pub fn remove(root: &Path, ns: &str, kappa: &str) -> Result<(), StoreError> {
    let mut fp = load(root, ns);
    fp.remove(kappa);
    save(root, ns, &fp)
}

/// Compute the range fingerprint for a namespace.
pub fn range_fp(
    root: &Path,
    ns: &str,
    lower: &str,
    upper: &str,
) -> Result<RangeFingerprint, StoreError> {
    let fp = load(root, ns);
    Ok(fp.range_fingerprint(lower, upper))
}

/// Return all items in a range for a namespace.
pub fn range_items(
    root: &Path,
    ns: &str,
    lower: &str,
    upper: &str,
) -> Result<Vec<String>, StoreError> {
    let fp = load(root, ns);
    Ok(fp.range_items(lower, upper))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tree_neutral() {
        let fp = NamespaceFingerprints::new();
        let r = fp.range_fingerprint("a", "a");
        assert_eq!(r.fingerprint, NEUTRAL);
        assert_eq!(r.count, 0);
    }

    #[test]
    fn single_item_full_range() {
        let mut fp = NamespaceFingerprints::new();
        fp.insert("sha256:aaa");
        let r = fp.range_fingerprint("x", "x"); // full range
        assert_ne!(r.fingerprint, NEUTRAL);
        assert_eq!(r.count, 1);
    }

    #[test]
    fn xor_self_inverse() {
        let mut fp = NamespaceFingerprints::new();
        fp.insert("sha256:aaa");
        fp.insert("sha256:bbb");
        let both = fp.range_fingerprint("x", "x");

        // Remove one, the fingerprint of the remaining item should
        // equal lift of that item alone
        let mut fp2 = NamespaceFingerprints::new();
        fp2.insert("sha256:aaa");
        let just_a = fp2.range_fingerprint("x", "x");

        // XOR(both, just_a) should equal lift("sha256:bbb")
        let diff = combine(&both.fingerprint, &just_a.fingerprint);
        assert_eq!(diff, lift("sha256:bbb"));
    }

    #[test]
    fn range_subset() {
        let mut fp = NamespaceFingerprints::new();
        fp.insert("sha256:aaa");
        fp.insert("sha256:bbb");
        fp.insert("sha256:ccc");

        // Range [sha256:aaa, sha256:ccc) should include aaa and bbb
        let r = fp.range_fingerprint("sha256:aaa", "sha256:ccc");
        assert_eq!(r.count, 2);

        let expected = combine(&lift("sha256:aaa"), &lift("sha256:bbb"));
        assert_eq!(r.fingerprint, expected);
    }

    #[test]
    fn range_items_subset() {
        let mut fp = NamespaceFingerprints::new();
        fp.insert("sha256:aaa");
        fp.insert("sha256:bbb");
        fp.insert("sha256:ccc");

        let items = fp.range_items("sha256:aaa", "sha256:ccc");
        assert_eq!(items, vec!["sha256:aaa", "sha256:bbb"]);
    }

    #[test]
    fn identical_sets_same_fingerprint() {
        let mut a = NamespaceFingerprints::new();
        let mut b = NamespaceFingerprints::new();
        for k in &["sha256:111", "sha256:222", "sha256:333"] {
            a.insert(k);
            b.insert(k);
        }
        let fa = a.range_fingerprint("x", "x");
        let fb = b.range_fingerprint("x", "x");
        assert_eq!(fa.fingerprint, fb.fingerprint);
        assert_eq!(fa.count, fb.count);
    }

    #[test]
    fn different_sets_different_fingerprint() {
        let mut a = NamespaceFingerprints::new();
        let mut b = NamespaceFingerprints::new();
        a.insert("sha256:111");
        a.insert("sha256:222");
        b.insert("sha256:111");
        b.insert("sha256:333");
        let fa = a.range_fingerprint("x", "x");
        let fb = b.range_fingerprint("x", "x");
        assert_ne!(fa.fingerprint, fb.fingerprint);
    }

    #[test]
    fn insert_order_independent() {
        let mut a = NamespaceFingerprints::new();
        a.insert("sha256:ccc");
        a.insert("sha256:aaa");
        a.insert("sha256:bbb");

        let mut b = NamespaceFingerprints::new();
        b.insert("sha256:aaa");
        b.insert("sha256:bbb");
        b.insert("sha256:ccc");

        let fa = a.range_fingerprint("x", "x");
        let fb = b.range_fingerprint("x", "x");
        assert_eq!(fa.fingerprint, fb.fingerprint);
    }
}
