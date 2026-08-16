//! Garbage collection: reachability walk over the content-addressed store.
//!
//! `compute_reachable` performs a BFS from a root set following edges.
//! `build_root_set` constructs the root set from all tagged kappas,
//! the current epoch chain, and AKD tree node kappas.

use std::collections::{HashSet, VecDeque};

use crate::store::KappaStore;
use crate::types::{NamespaceRef, StoreError};

/// Result of a GC sweep.
#[derive(Debug, Clone)]
pub struct GcResult {
    pub objects_scanned: u64,
    pub objects_reachable: u64,
    pub objects_collected: u64,
    pub bytes_freed: u64,
}

/// Compute the set of reachable kappa-labels via breadth-first traversal.
///
/// Starting from root_kappas, follows edges returned by resolve_edges.
/// The resolve_edges callback returns target kappa-labels reachable
/// from the given source kappa via gc-walked edge relations.
/// EdgeRelation::gc_reachable() determines which relations are followed.
pub fn compute_reachable(
    root_kappas: &[String],
    resolve_edges: &dyn Fn(&str) -> Vec<String>,
) -> HashSet<String> {
    let mut reachable = HashSet::new();
    let mut queue: VecDeque<String> = root_kappas.iter().cloned().collect();

    while let Some(kappa) = queue.pop_front() {
        if !reachable.insert(kappa.clone()) {
            continue;
        }
        for target in resolve_edges(&kappa) {
            if !reachable.contains(&target) {
                queue.push_back(target);
            }
        }
    }

    reachable
}

/// Build the GC root set from a store.
///
/// The root set contains:
/// 1. All kappas referenced by tags in every namespace (live bindings).
/// 2. The full epoch chain for each namespace (walk prev_root_kappa links).
/// 3. All kappas tagged under AKD prefixes (akd tree nodes).
///
/// Everything reachable from the root set via gc-walked edge relations
/// is retained. Everything else is eligible for collection.
pub fn build_root_set(store: &dyn KappaStore) -> Result<Vec<String>, StoreError> {
    let mut roots = Vec::new();
    let namespaces = store.namespace_list()?;

    for ns in &namespaces {
        let ns_ref = NamespaceRef::from(ns.as_str());
        // All tagged kappas are roots (live name bindings)
        let tags = store.tag_list(&ns_ref)?;
        for tag in &tags {
            roots.push(tag.kappa.clone());
        }

        // Walk the epoch chain: current -> prev -> prev -> ...
        let mut epoch_kappa = store.epoch_current(&ns_ref)?;
        while let Some(ref ek) = epoch_kappa {
            roots.push(ek.clone());
            match store.epoch_get(ek) {
                Ok(root) => {
                    epoch_kappa = root.prev_root_kappa.clone();
                }
                Err(_) => break,
            }
        }
    }

    roots.sort();
    roots.dedup();
    Ok(roots)
}

/// Run a full GC sweep: build root set, compute reachable, delete unreachable.
///
/// Returns the number of blobs deleted and bytes freed.
pub fn sweep(
    store: &dyn KappaStore,
    resolve_edges: &dyn Fn(&str) -> Vec<String>,
) -> Result<GcResult, StoreError> {
    let roots = build_root_set(store)?;
    let reachable = compute_reachable(&roots, resolve_edges);

    let all_blobs = store.blob_list()?;
    let mut collected = 0u64;
    let mut bytes_freed = 0u64;

    for kappa in &all_blobs {
        if !reachable.contains(kappa) {
            if let Ok(size) = store.blob_size(kappa) {
                bytes_freed += size;
            }
            store.blob_delete(kappa)?;
            collected += 1;
        }
    }

    Ok(GcResult {
        objects_scanned: all_blobs.len() as u64,
        objects_reachable: reachable.len() as u64,
        objects_collected: collected,
        bytes_freed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_root_set() {
        assert!(compute_reachable(&[], &|_| vec![]).is_empty());
    }

    #[test]
    fn root_set_retained() {
        let roots = vec!["a".into(), "b".into()];
        let reachable = compute_reachable(&roots, &|_| vec![]);
        assert!(reachable.contains("a"));
        assert!(reachable.contains("b"));
        assert_eq!(reachable.len(), 2);
    }

    #[test]
    fn transitive_edges() {
        let reachable = compute_reachable(&["root".into()], &|k| match k {
            "root" => vec!["child1".into(), "child2".into()],
            "child1" => vec!["grandchild".into()],
            _ => vec![],
        });
        assert_eq!(reachable.len(), 4);
        assert!(reachable.contains("grandchild"));
    }

    #[test]
    fn cycles_terminate() {
        let reachable = compute_reachable(&["a".into()], &|k| match k {
            "a" => vec!["b".into()],
            "b" => vec!["a".into()],
            _ => vec![],
        });
        assert_eq!(reachable.len(), 2);
    }

    #[test]
    fn unreachable_excluded() {
        let reachable = compute_reachable(&["a".into()], &|_| vec![]);
        assert!(!reachable.contains("orphan"));
    }

    #[test]
    fn build_root_set_includes_tags_and_epochs() {
        use crate::clock::ntp_lamport::NtpLamportClock;
        use crate::kappa::kappa_from_bytes;
        use crate::store::memory::{InMemoryStore, MemoryStoreConfig};
        use crate::store::KappaStore;
        let tmp = tempfile::tempdir().unwrap();
        let clock = std::sync::Arc::new(NtpLamportClock::new());
        let store = InMemoryStore::new(
            MemoryStoreConfig::new(tmp.path().join("blobs")),
            clock,
        )
        .unwrap();

        let ns = NamespaceRef::from("ns");
        let content = b"content-a";
        let k = kappa_from_bytes(content);
        store.ingest_verified(&k, content).unwrap();
        store.tag_set(&ns, "latest", &k).unwrap();

        let epoch_k = store.epoch_advance(&ns, vec![]).unwrap();

        let roots = build_root_set(&store).unwrap();
        assert!(roots.contains(&k));
        assert!(roots.contains(&epoch_k));
    }

    #[test]
    fn sweep_deletes_unreachable() {
        use crate::clock::ntp_lamport::NtpLamportClock;
        use crate::kappa::kappa_from_bytes;
        use crate::store::memory::{InMemoryStore, MemoryStoreConfig};
        use crate::store::KappaStore;
        let tmp = tempfile::tempdir().unwrap();
        let clock = std::sync::Arc::new(NtpLamportClock::new());
        let store = InMemoryStore::new(
            MemoryStoreConfig::new(tmp.path().join("blobs")),
            clock,
        )
        .unwrap();

        let ns = NamespaceRef::from("ns");
        let tagged_content = b"tagged-content";
        let tagged_k = kappa_from_bytes(tagged_content);
        let orphan_content = b"orphan-content";
        let orphan_k = kappa_from_bytes(orphan_content);

        store.ingest_verified(&tagged_k, tagged_content).unwrap();
        store.ingest_verified(&orphan_k, orphan_content).unwrap();
        store.tag_set(&ns, "keep", &tagged_k).unwrap();

        let result = sweep(&store, &|_| vec![]).unwrap();
        assert!(result.objects_collected >= 1);
        assert!(store.blob_exists(&tagged_k).unwrap());
        assert!(!store.blob_exists(&orphan_k).unwrap());
    }

    #[test]
    fn sweep_follows_edges() {
        use crate::clock::ntp_lamport::NtpLamportClock;
        use crate::kappa::kappa_from_bytes;
        use crate::store::memory::{InMemoryStore, MemoryStoreConfig};
        use crate::store::KappaStore;
        let tmp = tempfile::tempdir().unwrap();
        let clock = std::sync::Arc::new(NtpLamportClock::new());
        let store = InMemoryStore::new(
            MemoryStoreConfig::new(tmp.path().join("blobs")),
            clock,
        )
        .unwrap();

        let ns = NamespaceRef::from("ns");
        let root_content = b"root-content";
        let root_k = kappa_from_bytes(root_content);
        let child_content = b"child-content";
        let child_k = kappa_from_bytes(child_content);
        let orphan_content = b"orphan-content-edge";
        let orphan_k = kappa_from_bytes(orphan_content);

        store.ingest_verified(&root_k, root_content).unwrap();
        store.ingest_verified(&child_k, child_content).unwrap();
        store.ingest_verified(&orphan_k, orphan_content).unwrap();
        store.tag_set(&ns, "entry", &root_k).unwrap();

        let root_k_clone = root_k.clone();
        let child_k_clone = child_k.clone();
        let result = sweep(&store, &|k| {
            if k == root_k_clone {
                vec![child_k_clone.clone()]
            } else {
                vec![]
            }
        })
        .unwrap();

        assert!(store.blob_exists(&root_k).unwrap());
        assert!(store.blob_exists(&child_k).unwrap());
        assert!(!store.blob_exists(&orphan_k).unwrap());
        assert_eq!(result.objects_collected, 1);
    }
}
