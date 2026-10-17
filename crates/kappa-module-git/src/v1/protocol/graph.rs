use std::collections::{HashMap, HashSet, VecDeque};

use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::blob::BlobStore;

use crate::envelope;

use super::{FetchOptions, FilterSpec};

/// Compute the set of objects the client needs.
///
/// Walks from wants, excludes objects reachable from common (have) set,
/// reading objects as the repository namespace admitted them.
/// Returns (needed_kappas, new_shallow_oids).
pub(crate) fn compute_need_set<S: BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    wants: &[String],
    common: &HashSet<String>,
    object_hash: gix_hash::Kind,
    opts: &FetchOptions,
) -> (Vec<Kappa>, HashSet<String>) {
    let prefix = envelope::hash_prefix(object_hash);
    let hash_len = object_hash.len_in_bytes();

    let have_set = walk_reachable(
        store,
        namespace,
        common.iter().cloned().collect(),
        object_hash,
    );

    let mut needed: Vec<Kappa> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut new_shallows: HashSet<String> = HashSet::new();
    let mut depth_map: HashMap<String, u32> = HashMap::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    for oid_hex in wants {
        let kappa_str = format!("{}:{}", prefix, oid_hex);
        if !have_set.contains(&kappa_str) && !visited.contains(&kappa_str) {
            depth_map.insert(kappa_str.clone(), 1);
            queue.push_back(kappa_str);
        }
    }

    while let Some(kappa_str) = queue.pop_front() {
        if visited.contains(&kappa_str) || have_set.contains(&kappa_str) {
            continue;
        }
        visited.insert(kappa_str.clone());

        let kappa = match Kappa::parse(&kappa_str) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let envelope_bytes = match store.blob_get_in(namespace, &kappa) {
            Ok(b) => b,
            Err(_) => continue,
        };

        let (kind, content) = match envelope::unwrap(&envelope_bytes) {
            Ok(r) => r,
            Err(_) => continue,
        };

        if let Some(ref filter) = opts.filter {
            match filter {
                FilterSpec::BlobNone if kind == gix_object::Kind::Blob => continue,
                FilterSpec::BlobLimit(limit)
                    if kind == gix_object::Kind::Blob && content.len() as u64 > *limit =>
                {
                    continue;
                }
                _ => {}
            }
        }

        needed.push(kappa);

        let current_depth = depth_map.get(&kappa_str).copied().unwrap_or(0);

        if kind == gix_object::Kind::Commit
            && let Some(max_depth) = opts.deepen
            && current_depth >= max_depth
        {
            let hex_oid = envelope::kappa_to_hex_oid(&kappa_str);
            new_shallows.insert(hex_oid.to_string());
            // Walk tree children but not parent commits
            for child_str in envelope::extract_children(&envelope_bytes, hash_len, prefix) {
                if visited.contains(&child_str) || have_set.contains(&child_str) {
                    continue;
                }
                let child_kappa = match Kappa::parse(&child_str) {
                    Ok(k) => k,
                    Err(_) => continue,
                };
                if let Ok(child_bytes) = store.blob_get_in(namespace, &child_kappa)
                    && let Ok((child_kind, _)) = envelope::unwrap(&child_bytes)
                    && child_kind != gix_object::Kind::Commit
                {
                    queue.push_back(child_str.clone());
                    depth_map.insert(child_str, current_depth);
                }
            }
            continue;
        }

        for child_str in envelope::extract_children(&envelope_bytes, hash_len, prefix) {
            if !visited.contains(&child_str) && !have_set.contains(&child_str) {
                if !depth_map.contains_key(&child_str) {
                    depth_map.insert(child_str.clone(), current_depth + 1);
                }
                queue.push_back(child_str);
            }
        }
    }

    (needed, new_shallows)
}

/// Walk from root hex OIDs and collect all reachable kappa-label strings.
pub fn walk_reachable<S: BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    roots: Vec<String>,
    object_hash: gix_hash::Kind,
) -> HashSet<String> {
    let prefix = envelope::hash_prefix(object_hash);
    let hash_len = object_hash.len_in_bytes();
    let mut reachable: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<String> = VecDeque::new();

    for oid_hex in roots {
        queue.push_back(format!("{}:{}", prefix, oid_hex));
    }

    while let Some(kappa_str) = queue.pop_front() {
        if reachable.contains(&kappa_str) {
            continue;
        }
        reachable.insert(kappa_str.clone());

        let kappa = match Kappa::parse(&kappa_str) {
            Ok(k) => k,
            Err(_) => continue,
        };

        let envelope_bytes = match store.blob_get_in(namespace, &kappa) {
            Ok(b) => b,
            Err(_) => continue,
        };

        for child_str in envelope::extract_children(&envelope_bytes, hash_len, prefix) {
            if !reachable.contains(&child_str) {
                queue.push_back(child_str);
            }
        }
    }

    reachable
}
