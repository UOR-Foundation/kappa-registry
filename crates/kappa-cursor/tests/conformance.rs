//! Cursor algebra conformance tests.
//!
//! C-9:  Difference strategies produce identical output.
//! C-13: Cursor invariants hold under proptest.
//!
//! These tests are the forcing functions expressed as code.
//! They fail on an empty or incorrect implementation.
//! They run in CI from the first commit.

use kappa_cursor::{Difference, Intersection, KappaCursor, SliceCursor, TERMINATED, Union};
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn keys_from(raw: &[&[u8]]) -> Vec<Vec<u8>> {
    raw.iter().map(|k| k.to_vec()).collect()
}

#[test]
fn intersection_seek_aligns_without_skipping_a_common_key() {
    let mut cursor = Intersection::new(vec![
        cursor_from(&[b"aa", b"cc", b"ee"]),
        cursor_from(&[b"aa", b"bb", b"cc", b"ee"]),
    ]);
    assert_eq!(cursor.seek(b"bb"), b"cc");
    assert_eq!(cursor.advance(), b"ee");
}

#[test]
fn filtered_size_hint_bounds_actual_remaining_results() {
    let inner = cursor_from(&[b"aa", b"bb", b"cc"]);
    let cursor = kappa_cursor::FilteredCursor::new(inner, std::sync::Arc::new(|_| true), 0.01);
    let bound = cursor.size_hint();
    assert!(bound >= collect_cursor(cursor).len() as u64);
}

fn cursor_from(raw: &[&[u8]]) -> SliceCursor {
    let items: Vec<&[u8]> = raw.to_vec();
    SliceCursor::new(items)
}

fn collect_cursor(mut c: impl KappaCursor) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    while c.key() != TERMINATED {
        out.push(c.key().to_vec());
        c.advance();
    }
    out
}

struct CostCursor {
    inner: SliceCursor,
    estimate: u64,
}

impl KappaCursor for CostCursor {
    fn key(&self) -> &[u8] {
        self.inner.key()
    }
    fn advance(&mut self) -> &[u8] {
        self.inner.advance()
    }
    fn seek(&mut self, target: &[u8]) -> &[u8] {
        self.inner.seek(target)
    }
    fn size_hint(&self) -> u64 {
        self.inner.size_hint()
    }
    fn cost(&self) -> u64 {
        self.estimate
    }
}

// ---------------------------------------------------------------------------
// C-9: Difference strategies produce identical output
// ---------------------------------------------------------------------------

#[test]
fn c9_difference_merge_and_seek_produce_identical_output() {
    // Large A, small B (merge path)
    let a_keys: Vec<Vec<u8>> = (0u32..100_000).map(|i| i.to_be_bytes().to_vec()).collect();
    let b_keys: Vec<Vec<u8>> = (0u32..10_000)
        .step_by(10)
        .map(|i| i.to_be_bytes().to_vec())
        .collect();

    let a_refs: Vec<&[u8]> = a_keys.iter().map(Vec::as_slice).collect();
    let b_refs: Vec<&[u8]> = b_keys.iter().map(Vec::as_slice).collect();

    let merge_result = collect_cursor(Difference::new(
        SliceCursor::new(a_refs.clone()),
        SliceCursor::new(b_refs.clone()),
    ));

    // A cost of one makes B's cost exceed A.cost() * log2(B.cost()),
    // selecting the seek strategy over exactly the same key sets.
    let seek_result = collect_cursor(Difference::new(
        CostCursor {
            inner: SliceCursor::new(a_refs),
            estimate: 1,
        },
        SliceCursor::new(b_refs),
    ));
    let expected = {
        let mut expected = Vec::new();
        let b_set: std::collections::BTreeSet<Vec<u8>> = b_keys.iter().cloned().collect();
        for k in &a_keys {
            if !b_set.contains(k) {
                expected.push(k.clone());
            }
        }
        expected
    };

    assert_eq!(
        merge_result, seek_result,
        "C-9: Difference strategies MUST produce identical output. \
         The merge path and the reference BTreeSet path disagree."
    );
    assert_eq!(
        merge_result, expected,
        "both strategies must match the independent oracle"
    );
}

#[test]
fn c9_difference_small_a_large_b() {
    // Small A, large B (seek path should win on cost)
    let a_keys: Vec<Vec<u8>> = (0u32..100).map(|i| i.to_be_bytes().to_vec()).collect();
    let b_keys: Vec<Vec<u8>> = (0u32..1_000_000)
        .map(|i| i.to_be_bytes().to_vec())
        .collect();

    let a_refs: Vec<&[u8]> = a_keys.iter().map(Vec::as_slice).collect();
    let b_refs: Vec<&[u8]> = b_keys.iter().map(Vec::as_slice).collect();

    let diff_result = collect_cursor(Difference::new(
        SliceCursor::new(a_refs),
        SliceCursor::new(b_refs),
    ));

    let b_set: std::collections::BTreeSet<Vec<u8>> = b_keys.iter().cloned().collect();
    let expected: Vec<Vec<u8>> = a_keys.into_iter().filter(|k| !b_set.contains(k)).collect();

    assert_eq!(
        diff_result, expected,
        "C-9: Difference with small A / large B MUST match reference."
    );
}

#[test]
fn c9_difference_disjoint_sets() {
    let a = cursor_from(&[b"aa", b"cc", b"ee"]);
    let b = cursor_from(&[b"bb", b"dd", b"ff"]);
    let result = collect_cursor(Difference::new(a, b));
    assert_eq!(
        result,
        keys_from(&[b"aa", b"cc", b"ee"]),
        "C-9: Disjoint sets — all A elements survive."
    );
}

#[test]
fn c9_difference_identical_sets() {
    let a = cursor_from(&[b"aa", b"bb", b"cc"]);
    let b = cursor_from(&[b"aa", b"bb", b"cc"]);
    let result = collect_cursor(Difference::new(a, b));
    assert!(
        result.is_empty(),
        "C-9: Identical sets — no elements survive."
    );
}

#[test]
fn c9_difference_empty_b() {
    let a = cursor_from(&[b"aa", b"bb", b"cc"]);
    let b = SliceCursor::new(Vec::<&[u8]>::new());
    let result = collect_cursor(Difference::new(a, b));
    assert_eq!(
        result,
        keys_from(&[b"aa", b"bb", b"cc"]),
        "C-9: Empty B — all A elements survive."
    );
}

#[test]
fn c9_difference_empty_a() {
    let a = SliceCursor::new(Vec::<&[u8]>::new());
    let b = cursor_from(&[b"aa", b"bb", b"cc"]);
    let result = collect_cursor(Difference::new(a, b));
    assert!(result.is_empty(), "C-9: Empty A — no elements.");
}

// ---------------------------------------------------------------------------
// C-13: Cursor invariants hold under proptest
// ---------------------------------------------------------------------------

fn arbitrary_key() -> impl Strategy<Value = Vec<u8>> {
    (0u8..=5, proptest::collection::vec(any::<u8>(), 32..=32)).prop_map(|(axis, digest)| {
        let mut key = Vec::with_capacity(33);
        key.push(axis);
        key.extend(digest);
        key
    })
}

proptest! {
    #[test]
    fn c13_cursor_keys_strictly_ascending(
        keys in proptest::collection::vec(arbitrary_key(), 1..10_000)
    ) {
        let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
        let mut c = SliceCursor::new(refs);
        let mut prev = Vec::new();
        while c.key() != TERMINATED {
            let k = c.key().to_vec();
            prop_assert!(k > prev,
                "C-13: keys MUST be strictly ascending. \
                 prev={:?} current={:?}", prev, k);
            prev = k;
            c.advance();
        }
    }

    #[test]
    fn c13_seek_never_moves_backward(
        keys in proptest::collection::vec(arbitrary_key(), 1..5_000),
        targets in proptest::collection::vec(arbitrary_key(), 1..1_000)
    ) {
        let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
        let mut c = SliceCursor::new(refs);
        let mut last_pos = Vec::new();
        for t in &targets {
            let k = c.seek(t);
            if k != TERMINATED {
                prop_assert!(k.to_vec() >= last_pos,
                    "C-13: seek MUST NOT move backward. \
                     target={:?} result={:?} last={:?}", t, k, last_pos);
                last_pos = k.to_vec();
            }
        }
    }

    #[test]
    fn c13_seek_result_gte_target(
        keys in proptest::collection::vec(arbitrary_key(), 1..5_000),
        targets in proptest::collection::vec(arbitrary_key(), 1..1_000)
    ) {
        let refs: Vec<&[u8]> = keys.iter().map(Vec::as_slice).collect();
        let mut c = SliceCursor::new(refs);
        for t in &targets {
            let k = c.seek(t);
            if k != TERMINATED {
                prop_assert!(k >= t.as_slice(),
                    "C-13: seek result MUST be >= target. \
                     target={:?} result={:?}", t, k);
            }
        }
    }

    #[test]
    fn c13_intersection_is_subset_of_both(
        a_keys in proptest::collection::vec(arbitrary_key(), 0..5_000),
        b_keys in proptest::collection::vec(arbitrary_key(), 0..5_000)
    ) {
        let a_refs: Vec<&[u8]> = a_keys.iter().map(Vec::as_slice).collect();
        let b_refs: Vec<&[u8]> = b_keys.iter().map(Vec::as_slice).collect();
        let a_set: std::collections::BTreeSet<Vec<u8>> = a_keys.iter().cloned().collect();
        let b_set: std::collections::BTreeSet<Vec<u8>> = b_keys.iter().cloned().collect();

        let result = collect_cursor(
            Intersection::new(vec![
                Box::new(SliceCursor::new(a_refs)) as Box<dyn KappaCursor>,
                Box::new(SliceCursor::new(b_refs)) as Box<dyn KappaCursor>,
            ])
        );

        for k in &result {
            prop_assert!(a_set.contains(k),
                "C-13: Intersection element {:?} not in A", k);
            prop_assert!(b_set.contains(k),
                "C-13: Intersection element {:?} not in B", k);
        }

        // Verify completeness: every element in both sets is in the result
        let result_set: std::collections::BTreeSet<Vec<u8>> = result.into_iter().collect();
        for k in a_set.intersection(&b_set) {
            prop_assert!(result_set.contains(k),
                "C-13: Element {:?} in both A and B but not in Intersection", k);
        }
    }

    #[test]
    fn c13_union_is_superset_of_both(
        a_keys in proptest::collection::vec(arbitrary_key(), 0..5_000),
        b_keys in proptest::collection::vec(arbitrary_key(), 0..5_000)
    ) {
        let a_refs: Vec<&[u8]> = a_keys.iter().map(Vec::as_slice).collect();
        let b_refs: Vec<&[u8]> = b_keys.iter().map(Vec::as_slice).collect();

        let result = collect_cursor(
            Union::new(
                SliceCursor::new(a_refs),
                SliceCursor::new(b_refs),
            )
        );
        let result_set: std::collections::BTreeSet<Vec<u8>> = result.into_iter().collect();

        for k in &a_keys {
            prop_assert!(result_set.contains(k),
                "C-13: A element {:?} not in Union", k);
        }
        for k in &b_keys {
            prop_assert!(result_set.contains(k),
                "C-13: B element {:?} not in Union", k);
        }
    }

    #[test]
    fn c13_difference_contains_no_b_elements(
        a_keys in proptest::collection::vec(arbitrary_key(), 0..5_000),
        b_keys in proptest::collection::vec(arbitrary_key(), 0..5_000)
    ) {
        let a_refs: Vec<&[u8]> = a_keys.iter().map(Vec::as_slice).collect();
        let b_refs: Vec<&[u8]> = b_keys.iter().map(Vec::as_slice).collect();
        let b_set: std::collections::BTreeSet<Vec<u8>> = b_keys.iter().cloned().collect();

        let result = collect_cursor(
            Difference::new(
                SliceCursor::new(a_refs),
                SliceCursor::new(b_refs),
            )
        );

        for k in &result {
            prop_assert!(!b_set.contains(k),
                "C-13: Difference element {:?} found in B", k);
        }
    }
}

// ---------------------------------------------------------------------------
// Additional cursor contract tests (not proptest, deterministic)
// ---------------------------------------------------------------------------

#[test]
fn cursor_terminated_after_exhaustion() {
    let mut c = cursor_from(&[b"aa", b"bb"]);
    c.advance();
    c.advance();
    assert_eq!(c.key(), TERMINATED);
    assert_eq!(c.advance(), TERMINATED);
    assert_eq!(
        c.seek(b"aa"),
        TERMINATED,
        "Seek after TERMINATED MUST return TERMINATED."
    );
}

#[test]
fn cursor_empty_is_terminated() {
    let c = SliceCursor::new(Vec::<&[u8]>::new());
    assert_eq!(c.key(), TERMINATED);
}

#[test]
fn cursor_seek_to_current_is_noop() {
    let mut c = cursor_from(&[b"aa", b"bb", b"cc", b"dd"]);
    c.seek(b"cc");
    assert_eq!(c.key(), b"cc");
    c.seek(b"aa"); // backward seek: must not move
    assert_eq!(
        c.key(),
        b"cc",
        "Seek to a position at or before current MUST NOT move the cursor."
    );
    c.seek(b"cc"); // seek to current: must not move
    assert_eq!(c.key(), b"cc");
}

#[test]
fn cursor_seek_to_gap_lands_on_next() {
    let mut c = cursor_from(&[b"aa", b"cc", b"ee"]);
    let k = c.seek(b"bb");
    assert_eq!(k, b"cc", "Seek to a gap MUST land on the next element.");
}

#[test]
fn cursor_seek_past_end_terminates() {
    let mut c = cursor_from(&[b"aa", b"bb"]);
    let k = c.seek(b"zz");
    assert_eq!(k, TERMINATED);
}

#[test]
fn cursor_deduplicates_input() {
    let mut c = SliceCursor::new(vec![b"aa" as &[u8], b"aa", b"bb"]);
    assert_eq!(c.key(), b"aa");
    assert_eq!(c.advance(), b"bb");
    assert_eq!(c.advance(), TERMINATED);
}

#[test]
fn cursor_size_hint_decrements() {
    let mut c = cursor_from(&[b"aa", b"bb", b"cc"]);
    assert_eq!(c.size_hint(), 3);
    c.advance();
    assert_eq!(c.size_hint(), 2);
    c.advance();
    assert_eq!(c.size_hint(), 1);
    c.advance();
    assert_eq!(c.size_hint(), 0);
}
