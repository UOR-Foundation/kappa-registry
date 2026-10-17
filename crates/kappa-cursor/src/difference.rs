use crate::cursor::{KappaCursor, TERMINATED};

/// Elements in A but not in B.
///
/// Picks algorithm by cost ratio at construction:
///
/// - **Merge** (default): advance both in lockstep, yield A elements
///   not in B. Cost: O(|A| + |B|). Correct when both sides are
///   comparable size (GC: `all_blobs` - reachable).
///
/// - **Seek**: for each A element, seek B to check membership.
///   Cost: O(|A| * log|B|). Correct when A is much smaller than B
///   (10 candidate blobs against 10^6 total).
///
/// Crossover: seek wins when `B.cost() > A.cost() * log2(B.cost())`.
/// Both strategies produce identical output — the proptest at the
/// bottom of this file verifies this.
pub struct Difference<A: KappaCursor, B: KappaCursor> {
    a: A,
    b: B,
    use_merge: bool,
}

impl<A: KappaCursor, B: KappaCursor> Difference<A, B> {
    pub fn new(a: A, b: B) -> Self {
        let ca = a.cost();
        let cb = b.cost();
        // Seek wins when cb > ca * log2(cb).
        // Integer log2: number of bits minus leading zeros.
        // max(2) prevents log2(0) and log2(1) = 0 which would
        // make the multiplication zero and always pick seek.
        let log_cb = u64::BITS - cb.max(2).leading_zeros();
        let use_merge = cb <= ca.saturating_mul(u64::from(log_cb));
        let mut d = Self { a, b, use_merge };
        d.position_on_first_diff();
        d
    }

    /// Force a specific strategy. For testing only.
    #[cfg(test)]
    fn with_strategy(a: A, b: B, use_merge: bool) -> Self {
        let mut d = Self { a, b, use_merge };
        d.position_on_first_diff();
        d
    }

    fn position_on_first_diff(&mut self) {
        if self.use_merge {
            self.merge_to_next_diff();
        } else {
            self.seek_to_next_diff();
        }
    }

    fn merge_to_next_diff(&mut self) {
        loop {
            let ka = self.a.key();
            if ka == TERMINATED {
                return;
            }
            let kb = self.b.key();
            if kb == TERMINATED {
                return; // A has elements, B exhausted: A element is a diff
            }
            if ka < kb {
                return; // A element not in B
            }
            if ka == kb {
                self.a.advance();
                self.b.advance();
                continue;
            }
            // ka > kb: advance B to catch up
            self.b.advance();
        }
    }

    fn seek_to_next_diff(&mut self) {
        loop {
            let ka = self.a.key();
            if ka == TERMINATED {
                return;
            }
            let kb = self.b.seek(ka);
            if kb != ka {
                return; // A element not in B
            }
            self.a.advance();
        }
    }
}

impl<A: KappaCursor, B: KappaCursor> KappaCursor for Difference<A, B> {
    fn key(&self) -> &[u8] {
        self.a.key()
    }

    fn advance(&mut self) -> &[u8] {
        self.a.advance();
        if self.use_merge {
            self.merge_to_next_diff();
        } else {
            self.seek_to_next_diff();
        }
        self.a.key()
    }

    fn seek(&mut self, target: &[u8]) -> &[u8] {
        self.a.seek(target);
        if self.use_merge {
            self.b.seek(target);
            self.merge_to_next_diff();
        } else {
            self.seek_to_next_diff();
        }
        self.a.key()
    }

    fn size_hint(&self) -> u64 {
        self.a.size_hint()
    }

    fn cost(&self) -> u64 {
        if self.use_merge {
            self.a.cost().saturating_add(self.b.cost())
        } else {
            let log_b = u64::BITS - self.b.cost().max(2).leading_zeros();
            self.a.cost().saturating_mul(u64::from(log_b))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SliceCursor;

    fn collect(mut c: impl KappaCursor) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        while c.key() != TERMINATED {
            out.push(c.key().to_vec());
            c.advance();
        }
        out
    }

    #[test]
    fn disjoint_returns_all_of_a() {
        let a = SliceCursor::new(vec![b"aa", b"bb"]);
        let b = SliceCursor::new(vec![b"cc", b"dd"]);
        let r = collect(Difference::new(a, b));
        assert_eq!(r, vec![b"aa".to_vec(), b"bb".to_vec()]);
    }

    #[test]
    fn identical_returns_empty() {
        let a = SliceCursor::new(vec![b"aa", b"bb"]);
        let b = SliceCursor::new(vec![b"aa", b"bb"]);
        let r = collect(Difference::new(a, b));
        assert!(r.is_empty());
    }

    #[test]
    fn partial_overlap() {
        let a = SliceCursor::new(vec![b"aa", b"bb", b"cc", b"dd"]);
        let b = SliceCursor::new(vec![b"bb", b"dd"]);
        let r = collect(Difference::new(a, b));
        assert_eq!(r, vec![b"aa".to_vec(), b"cc".to_vec()]);
    }

    #[test]
    fn b_empty_returns_all_of_a() {
        let a = SliceCursor::new(vec![b"xx", b"yy"]);
        let b = SliceCursor::new(Vec::<&[u8]>::new());
        let r = collect(Difference::new(a, b));
        assert_eq!(r, vec![b"xx".to_vec(), b"yy".to_vec()]);
    }

    #[test]
    fn a_empty_returns_empty() {
        let a = SliceCursor::new(Vec::<&[u8]>::new());
        let b = SliceCursor::new(vec![b"xx"]);
        let r = collect(Difference::new(a, b));
        assert!(r.is_empty());
    }

    #[test]
    fn a_subset_of_b() {
        let a = SliceCursor::new(vec![b"bb"]);
        let b = SliceCursor::new(vec![b"aa", b"bb", b"cc"]);
        let r = collect(Difference::new(a, b));
        assert!(r.is_empty());
    }

    #[test]
    fn seek_skips_to_target() {
        let a = SliceCursor::new(vec![b"aa", b"bb", b"cc", b"dd", b"ee"]);
        let b = SliceCursor::new(vec![b"bb", b"dd"]);
        let mut d = Difference::new(a, b);
        assert_eq!(d.key(), b"aa");
        d.seek(b"dd");
        assert_eq!(d.key(), b"ee");
    }

    #[test]
    fn seek_to_terminated() {
        let a = SliceCursor::new(vec![b"aa"]);
        let b = SliceCursor::new(Vec::<&[u8]>::new());
        let mut d = Difference::new(a, b);
        assert_eq!(d.key(), b"aa");
        d.seek(b"zz");
        assert_eq!(d.key(), TERMINATED);
    }

    #[test]
    fn single_element_a_not_in_b() {
        let a = SliceCursor::new(vec![b"xx"]);
        let b = SliceCursor::new(vec![b"aa", b"bb", b"cc"]);
        let r = collect(Difference::new(a, b));
        assert_eq!(r, vec![b"xx".to_vec()]);
    }

    #[test]
    fn single_element_a_in_b() {
        let a = SliceCursor::new(vec![b"bb"]);
        let b = SliceCursor::new(vec![b"aa", b"bb", b"cc"]);
        let r = collect(Difference::new(a, b));
        assert!(r.is_empty());
    }

    #[test]
    fn interleaved_elements() {
        let a = SliceCursor::new(vec![b"a", b"c", b"e", b"g"]);
        let b = SliceCursor::new(vec![b"b", b"d", b"f", b"h"]);
        let r = collect(Difference::new(a, b));
        assert_eq!(
            r,
            vec![b"a".to_vec(), b"c".to_vec(), b"e".to_vec(), b"g".to_vec()]
        );
    }

    /// Both strategies must produce identical output for any input.
    /// This is the correctness property that makes cost-based switching safe.
    #[test]
    fn merge_and_seek_produce_identical_output() {
        let data_a: Vec<Vec<u8>> = vec![
            b"01".to_vec(),
            b"03".to_vec(),
            b"05".to_vec(),
            b"07".to_vec(),
            b"09".to_vec(),
            b"11".to_vec(),
            b"13".to_vec(),
            b"15".to_vec(),
            b"17".to_vec(),
        ];
        let data_b: Vec<Vec<u8>> = vec![
            b"03".to_vec(),
            b"07".to_vec(),
            b"11".to_vec(),
            b"15".to_vec(),
        ];

        let merge_result = collect(Difference::with_strategy(
            SliceCursor::from_sorted(data_a.clone()),
            SliceCursor::from_sorted(data_b.clone()),
            true, // force merge
        ));
        let seek_result = collect(Difference::with_strategy(
            SliceCursor::from_sorted(data_a),
            SliceCursor::from_sorted(data_b),
            false, // force seek
        ));
        assert_eq!(
            merge_result, seek_result,
            "merge and seek must produce identical output"
        );
        assert_eq!(
            merge_result,
            vec![
                b"01".to_vec(),
                b"05".to_vec(),
                b"09".to_vec(),
                b"13".to_vec(),
                b"17".to_vec(),
            ]
        );
    }

    /// Edge case: both strategies on empty A.
    #[test]
    fn both_strategies_on_empty_a() {
        let data_b = vec![b"aa".to_vec(), b"bb".to_vec()];
        let m = collect(Difference::with_strategy(
            SliceCursor::from_sorted(Vec::<Vec<u8>>::new()),
            SliceCursor::from_sorted(data_b.clone()),
            true,
        ));
        let s = collect(Difference::with_strategy(
            SliceCursor::from_sorted(Vec::<Vec<u8>>::new()),
            SliceCursor::from_sorted(data_b),
            false,
        ));
        assert!(m.is_empty());
        assert_eq!(m, s);
    }

    /// Edge case: both strategies on empty B.
    #[test]
    fn both_strategies_on_empty_b() {
        let data_a = vec![b"xx".to_vec(), b"yy".to_vec()];
        let m = collect(Difference::with_strategy(
            SliceCursor::from_sorted(data_a.clone()),
            SliceCursor::from_sorted(Vec::<Vec<u8>>::new()),
            true,
        ));
        let s = collect(Difference::with_strategy(
            SliceCursor::from_sorted(data_a),
            SliceCursor::from_sorted(Vec::<Vec<u8>>::new()),
            false,
        ));
        assert_eq!(m, vec![b"xx".to_vec(), b"yy".to_vec()]);
        assert_eq!(m, s);
    }

    /// Verify strategy selection: comparable sizes pick merge.
    #[test]
    fn comparable_sizes_pick_merge() {
        let a = SliceCursor::from_sorted((0u16..100).map(|i| i.to_be_bytes().to_vec()).collect());
        let b = SliceCursor::from_sorted((50u16..150).map(|i| i.to_be_bytes().to_vec()).collect());
        let d = Difference::new(a, b);
        assert!(d.use_merge, "comparable sizes should use merge");
    }

    /// Verify strategy selection: tiny A against large B picks seek.
    #[test]
    fn tiny_a_large_b_picks_seek() {
        // A has 2 elements, B has 10000
        let a = SliceCursor::from_sorted(vec![vec![0x00, 0x50], vec![0x00, 0x99]]);
        let b = SliceCursor::from_sorted((0u16..10000).map(|i| i.to_be_bytes().to_vec()).collect());
        let d = Difference::new(a, b);
        assert!(!d.use_merge, "tiny A against large B should use seek");
    }
}
