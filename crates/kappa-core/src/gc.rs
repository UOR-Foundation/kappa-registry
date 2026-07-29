//! Garbage collection: reachability walk over the content-addressed store.

use std::collections::{HashSet, VecDeque};

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
}
