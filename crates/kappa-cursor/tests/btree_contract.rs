use std::collections::BTreeSet;

use kappa_cursor::{BTreeCursor, Difference, KappaCursor, TERMINATED, Union};
use proptest::prelude::*;

fn key(value: u16) -> Vec<u8> {
    let mut bytes = vec![0];
    bytes.extend_from_slice(&value.to_be_bytes());
    bytes
}

// Rust alloc's BTree range tests exercise leaf/internal-node boundaries and
// borrowed lookup keys. Exercise those mechanisms through our cursor contract,
// including binary prefix keys and maximum-length admitted identities.
#[test]
fn every_lower_bound_matches_oracle_across_tree_heights() {
    for population in [0, 1, 4, 200, 1000] {
        let source: BTreeSet<_> = (0..population).map(|i| key(i * 2)).collect();
        let oracle: Vec<_> = source.iter().collect();
        for target in 0..=population * 2 + 1 {
            let target = key(target);
            let mut cursor = BTreeCursor::new(&source);
            let position = oracle.partition_point(|value| value.as_slice() < target.as_slice());
            let expected = oracle
                .get(position)
                .map_or(TERMINATED, |value| value.as_slice());
            assert_eq!(cursor.seek(&target), expected);
            for value in &oracle[position..] {
                assert_eq!(cursor.key(), value.as_slice());
                assert_eq!(cursor.key().as_ptr(), value.as_ptr());
                cursor.advance();
            }
            assert_eq!(cursor.key(), TERMINATED);
            assert_eq!(cursor.size_hint(), 0);
        }
    }
}

#[test]
fn binary_prefixes_and_long_identities_remain_distinct() {
    let source: BTreeSet<_> = [
        vec![0],
        vec![0, 0],
        vec![0, 0, 255],
        vec![0, 255],
        vec![5; 65],
    ]
    .into();
    let mut cursor = BTreeCursor::new(&source);
    for expected in &source {
        assert_eq!(cursor.key(), expected.as_slice());
        cursor.advance();
    }
    assert_eq!(cursor.key(), TERMINATED);
    assert_eq!(cursor.seek(&[0]), TERMINATED);
}

proptest! {
    #[test]
    fn mixed_navigation_matches_independent_sorted_vector(
        values in prop::collection::vec(any::<u16>(), 0..256),
        operations in prop::collection::vec((any::<bool>(), any::<u16>()), 0..256),
    ) {
        let mut oracle: Vec<_> = values.into_iter().map(key).collect();
        oracle.sort_unstable();
        oracle.dedup();
        let source: BTreeSet<_> = oracle.iter().cloned().collect();
        let mut cursor = BTreeCursor::new(&source);
        let mut position = 0;
        for (advance, target) in operations {
            if advance {
                position = (position + 1).min(oracle.len());
                cursor.advance();
            } else {
                let target = key(target);
                while position < oracle.len() && oracle[position] < target {
                    position += 1;
                }
                cursor.seek(&target);
            }
            let expected = oracle.get(position).map_or(TERMINATED, Vec::as_slice);
            prop_assert_eq!(cursor.key(), expected);
            prop_assert!(cursor.size_hint() >= (oracle.len() - position) as u64);
            if position == oracle.len() {
                prop_assert_eq!(cursor.size_hint(), 0);
            }
        }
    }

    #[test]
    fn borrowed_overlay_algebra_matches_membership_oracle(
        base in prop::collection::vec(any::<u16>(), 0..128),
        inserts in prop::collection::vec(any::<u16>(), 0..128),
        deletes in prop::collection::vec(any::<u16>(), 0..128),
    ) {
        let base: BTreeSet<_> = base.into_iter().map(key).collect();
        let inserts: BTreeSet<_> = inserts.into_iter().map(key).collect();
        let deletes: BTreeSet<_> = deletes.into_iter().map(key).collect();
        let mut expected: Vec<_> = base.iter().chain(inserts.iter())
            .filter(|key| !deletes.contains(*key)).cloned().collect();
        expected.sort_unstable();
        expected.dedup();
        let mut cursor = Difference::new(
            Union::new(BTreeCursor::new(&base), BTreeCursor::new(&inserts)),
            BTreeCursor::new(&deletes),
        );
        let mut actual = Vec::new();
        while cursor.key() != TERMINATED {
            actual.push(cursor.key().to_vec());
            cursor.advance();
        }
        prop_assert_eq!(actual, expected);
    }
}
