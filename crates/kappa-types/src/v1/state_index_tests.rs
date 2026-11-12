//! The state index against independent models: every batch's root equals
//! the root of the tree built from scratch over the same entries; every
//! present and absent path proves against the root; superseded nodes stay
//! readable for every retained older root and are reclaimable only once
//! no retained root reaches them; and a batch refuses before it passes its
//! work budget.

use std::collections::{BTreeMap, BTreeSet};

use super::*;
use crate::work::WorkLimit;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Every node any retained root may need: created nodes are inserted, and
/// nothing is removed on a batch's report; [`Nodes::reclaim`] removes
/// what no retained root reaches.
#[derive(Default)]
struct Nodes(BTreeMap<[u8; 32], Node>);

impl NodeSource for Nodes {
    fn node(&self, hash: &[u8; 32]) -> Result<Node, StoreError> {
        self.0
            .get(hash)
            .copied()
            .ok_or_else(|| StoreError::Unavailable(format!("node {}", hex::encode(hash))))
    }
}

impl Nodes {
    fn absorb(&mut self, update: &Update) {
        for node in &update.created {
            self.0.insert(node.hash(), *node);
        }
    }

    /// Hashes reachable from `root`.
    fn reachable(&self, root: [u8; 32]) -> Result<BTreeSet<[u8; 32]>, StoreError> {
        let mut seen = BTreeSet::new();
        let mut pending = vec![root];
        while let Some(hash) = pending.pop() {
            if hash == EMPTY || !seen.insert(hash) {
                continue;
            }
            if let Node::Internal { left, right } = self.node(&hash)? {
                pending.push(left);
                pending.push(right);
            }
        }
        Ok(seen)
    }

    /// Remove every candidate no root of `retained` reaches; returns what
    /// was removed.
    fn reclaim(
        &mut self,
        candidates: &BTreeSet<[u8; 32]>,
        retained: &[[u8; 32]],
    ) -> Result<BTreeSet<[u8; 32]>, StoreError> {
        let mut needed = BTreeSet::new();
        for root in retained {
            needed.extend(self.reachable(*root)?);
        }
        let removed: BTreeSet<[u8; 32]> = candidates.difference(&needed).copied().collect();
        for hash in &removed {
            self.0.remove(hash);
        }
        Ok(removed)
    }
}

fn path(seed: u64) -> Path {
    crate::sha256::digest(&seed.to_be_bytes())
}

fn value(seed: u64) -> Value {
    crate::sha256::digest(&[seed.to_be_bytes(), [1; 8]].concat())
}

fn unbounded() -> WorkMeter {
    WorkMeter::unbounded()
}

fn sorted(batch: &[(u64, Option<u64>)]) -> Vec<Change> {
    let mut changes: Vec<Change> = batch
        .iter()
        .map(|(p, v)| (path(*p), v.map(value)))
        .collect();
    changes.sort_by_key(|(p, _)| *p);
    changes
}

/// The root of the entries of `model` built from nothing.
fn fresh_root(model: &BTreeMap<Path, Value>) -> Result<[u8; 32], StoreError> {
    let changes: Vec<Change> = model.iter().map(|(p, v)| (*p, Some(*v))).collect();
    Ok(apply(&Nodes::default(), EMPTY, &changes, &mut unbounded())?.root)
}

/// Every probe answers `model` and proves against `root`; a lie fails.
fn check_proofs(nodes: &Nodes, root: [u8; 32], model: &BTreeMap<Path, Value>) -> TestResult {
    for seed in 0..64 {
        let probe = path(seed);
        let (found, proof) = lookup(nodes, root, &probe, &mut unbounded())?;
        assert_eq!(found.as_ref(), model.get(&probe));
        assert!(verify(&root, &probe, found.as_ref(), &proof), "seed {seed}");
        let wrong = found.map_or_else(|| Some(value(999)), |_| None);
        assert!(
            !verify(&root, &probe, wrong.as_ref(), &proof),
            "seed {seed} lied"
        );
    }
    Ok(())
}

#[test]
fn incremental_batches_match_fresh_builds_and_prove_every_path() -> TestResult {
    let mut nodes = Nodes::default();
    let mut model = BTreeMap::new();
    let mut root = EMPTY;
    check_proofs(&nodes, root, &model)?;
    let batches: Vec<Vec<(u64, Option<u64>)>> = vec![
        vec![(1, Some(1))],
        vec![(2, Some(2)), (3, Some(3)), (4, Some(4))],
        vec![(2, Some(20))],
        vec![(1, None), (5, Some(5))],
        vec![(3, None), (4, None)],
        vec![(2, None), (5, None)],
        (0..40).map(|seed| (seed, Some(seed))).collect(),
        (0..40).step_by(3).map(|seed| (seed, None)).collect(),
        vec![(7, Some(7))],
        vec![(41, None)],
    ];
    for batch in batches {
        let changes = sorted(&batch);
        let update = apply(&nodes, root, &changes, &mut unbounded())?;
        nodes.absorb(&update);
        let superseded: BTreeSet<[u8; 32]> = update.superseded.iter().copied().collect();
        let current = nodes.reachable(update.root)?;
        for node in &update.created {
            assert!(
                current.contains(&node.hash()),
                "a created node is unreachable"
            );
        }
        assert!(
            superseded
                .iter()
                .all(|hash| !current.contains(hash)
                    || update.created.iter().any(|n| n.hash() == *hash)),
            "a superseded node is still in the new tree without being recreated"
        );
        root = update.root;
        for (p, v) in &changes {
            match v {
                Some(v) => model.insert(*p, *v),
                None => model.remove(p),
            };
        }
        assert_eq!(
            root,
            fresh_root(&model)?,
            "incremental root differs from a fresh build"
        );
        check_proofs(&nodes, root, &model)?;
    }
    Ok(())
}

/// Superseded nodes are not deletion permission: a retained older root
/// keeps proving until its retention ends, and reclamation then removes
/// only what no retained root reaches.
#[test]
fn superseded_nodes_serve_retained_roots_until_their_retention_ends() -> TestResult {
    let mut nodes = Nodes::default();
    let first = sorted(&(0..24).map(|seed| (seed, Some(seed))).collect::<Vec<_>>());
    let a = apply(&nodes, EMPTY, &first, &mut unbounded())?;
    nodes.absorb(&a);
    let model_a: BTreeMap<Path, Value> = first
        .iter()
        .map(|(p, v)| (*p, v.unwrap_or_default()))
        .collect();
    let second = sorted(&[(1, None), (2, Some(200)), (30, Some(30))]);
    let b = apply(&nodes, a.root, &second, &mut unbounded())?;
    nodes.absorb(&b);
    let mut model_b = model_a.clone();
    for (p, v) in &second {
        match v {
            Some(v) => model_b.insert(*p, *v),
            None => model_b.remove(p),
        };
    }
    // Both roots prove while both are retained.
    check_proofs(&nodes, a.root, &model_a)?;
    check_proofs(&nodes, b.root, &model_b)?;
    let candidates: BTreeSet<[u8; 32]> = b.superseded.iter().copied().collect();
    assert!(!candidates.is_empty());
    // Nothing is reclaimable while A is retained.
    let none = nodes.reclaim(&candidates, &[a.root, b.root])?;
    assert!(none.is_empty(), "reclaimed a node a retained root reaches");
    check_proofs(&nodes, a.root, &model_a)?;
    // Once A's retention ends, exactly the nodes only A reached go.
    let only_a: BTreeSet<[u8; 32]> = nodes
        .reachable(a.root)?
        .difference(&nodes.reachable(b.root)?)
        .copied()
        .collect();
    let removed = nodes.reclaim(&candidates, &[b.root])?;
    assert_eq!(removed, only_a);
    check_proofs(&nodes, b.root, &model_b)?;
    assert!(
        lookup(&nodes, a.root, &path(1), &mut unbounded()).is_err(),
        "a released root's nodes are gone"
    );
    Ok(())
}

#[test]
fn a_batch_refuses_before_passing_its_budget() -> TestResult {
    let nodes = Nodes::default();
    let changes = sorted(&(0..16).map(|seed| (seed, Some(seed))).collect::<Vec<_>>());
    let full = apply(&nodes, EMPTY, &changes, &mut unbounded())?;
    let needed = full.created.len() as u64 * NODE_BYTES;
    let mut short =
        WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, needed - 1));
    let refused = apply(&nodes, EMPTY, &changes, &mut short);
    assert!(
        matches!(
            &refused,
            Err(StoreError::WorkRefused(crate::work::WorkExhausted::Limit {
                dimension: Dimension::BytesAllocated,
                limit,
                used,
                requested: NODE_BYTES,
            })) if *limit == needed - 1 && *used == needed - NODE_BYTES
        ),
        "expected allocation work refusal before the last node, got {refused:?}"
    );
    assert!(short.used().get(Dimension::BytesAllocated) < needed);
    let mut exact = WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, needed));
    assert_eq!(apply(&nodes, EMPTY, &changes, &mut exact)?.root, full.root);
    assert_eq!(exact.used().get(Dimension::BytesAllocated), needed);
    Ok(())
}

#[test]
fn unsorted_or_repeated_changes_are_refused() {
    let nodes = Nodes::default();
    let (a, b) = (path(1), path(2));
    let (low, high) = if a < b { (a, b) } else { (b, a) };
    assert!(
        apply(
            &nodes,
            EMPTY,
            &[(high, None), (low, None)],
            &mut unbounded()
        )
        .is_err()
    );
    assert!(
        apply(
            &nodes,
            EMPTY,
            &[(low, None), (low, Some(value(1)))],
            &mut unbounded()
        )
        .is_err()
    );
}

/// The last execution-ordered effect at each path survives, replacement,
/// deletion and recurrence included, and the result is what `apply`
/// admits.
#[test]
fn final_changes_keep_the_last_effect_per_path() -> TestResult {
    let (a, b) = (path(1), path(2));
    assert_eq!(
        final_changes(vec![(a, Some(value(1))), (a, Some(value(2)))]),
        vec![(a, Some(value(2)))]
    );
    assert_eq!(
        final_changes(vec![(a, Some(value(1))), (a, None)]),
        vec![(a, None)]
    );
    assert_eq!(
        final_changes(vec![
            (a, Some(value(1))),
            (a, Some(value(2))),
            (a, Some(value(1)))
        ]),
        vec![(a, Some(value(1)))]
    );
    let mixed = final_changes(vec![
        (b, Some(value(3))),
        (a, None),
        (b, None),
        (a, Some(value(4))),
    ]);
    let (low, high) = if a < b { (a, b) } else { (b, a) };
    let expected = |p: Path| if p == a { Some(value(4)) } else { None };
    assert_eq!(mixed, vec![(low, expected(low)), (high, expected(high))]);
    apply(&Nodes::default(), EMPTY, &mixed, &mut unbounded())?;
    Ok(())
}

#[test]
fn proofs_bind_their_path_and_value() -> TestResult {
    let mut nodes = Nodes::default();
    let changes = sorted(&(0..9).map(|seed| (seed, Some(seed))).collect::<Vec<_>>());
    let update = apply(&nodes, EMPTY, &changes, &mut unbounded())?;
    nodes.absorb(&update);
    let (found, proof) = lookup(&nodes, update.root, &path(3), &mut unbounded())?;
    assert_eq!(found, Some(value(3)));
    assert!(
        !verify(&update.root, &path(4), found.as_ref(), &proof),
        "another path"
    );
    assert!(
        !verify(&[9; 32], &path(3), found.as_ref(), &proof),
        "another root"
    );
    let mut extended = proof.clone();
    extended.siblings.push(EMPTY);
    assert!(
        !verify(&update.root, &path(3), found.as_ref(), &extended),
        "deeper"
    );
    let mut trimmed = proof;
    trimmed.siblings.pop();
    assert!(
        !verify(&update.root, &path(3), found.as_ref(), &trimmed),
        "shallower"
    );
    Ok(())
}

#[test]
fn nodes_roundtrip_and_malformed_nodes_are_refused() -> TestResult {
    for node in [
        Node::Leaf {
            path: [1; 32],
            value: [2; 32],
        },
        Node::Internal {
            left: [3; 32],
            right: [4; 32],
        },
    ] {
        assert_eq!(Node::from_bytes(&node.to_bytes())?, node);
    }
    assert!(Node::from_bytes(&[LEAF; 64]).is_err());
    let mut unknown = [0u8; 65];
    unknown[0] = 0x12;
    assert!(Node::from_bytes(&unknown).is_err());
    Ok(())
}
