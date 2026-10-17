use std::sync::Arc;

use crate::cursor::{KappaCursor, SeekResult, TERMINATED};

/// Shared predicate over encoded cursor keys.
pub type KeyPredicate = Arc<dyn Fn(&[u8]) -> bool + Send + Sync>;

/// A cursor whose entries have been filtered by a predicate.
///
/// The predicate reads raw `key_bytes`. No dereference occurs.
/// Cost is O(1) per entry for the predicate evaluation, plus
/// `O(rejected_run_length)` for `seek` advancing past non-matches.
///
/// `cost()` reflects the selectivity estimate so the Intersection
/// orders correctly. A 99%-rejecting filter is expensive to seek
/// through; the Intersection should put it last, not first.
pub struct FilteredCursor<C: KappaCursor> {
    inner: C,
    predicate: KeyPredicate,
    selectivity: f64,
    lower_bound: Vec<u8>,
}

impl<C: KappaCursor> FilteredCursor<C> {
    /// Create a filtered cursor.
    ///
    /// `selectivity` is the estimated fraction of elements that
    /// pass the predicate (0.0 = reject all, 1.0 = accept all).
    /// Used by `cost()` to inform Intersection ordering.
    pub fn new(inner: C, predicate: KeyPredicate, selectivity: f64) -> Self {
        let mut fc = Self {
            inner,
            predicate,
            selectivity: selectivity.clamp(0.001, 1.0),
            lower_bound: Vec::new(),
        };
        // Position on the first matching element
        if fc.inner.key() != TERMINATED && !(fc.predicate)(fc.inner.key()) {
            fc.advance_to_match();
        }
        fc
    }

    /// Explicitly unfiltered. Audit and reconciliation paths only.
    pub fn unfiltered(inner: C) -> Self {
        Self {
            inner,
            predicate: Arc::new(|_| true),
            selectivity: 1.0,
            lower_bound: Vec::new(),
        }
    }

    fn advance_to_match(&mut self) {
        while self.inner.key() != TERMINATED {
            if (self.predicate)(self.inner.key()) {
                return;
            }
            self.inner.advance();
        }
    }
}

impl<C: KappaCursor> KappaCursor for FilteredCursor<C> {
    fn key(&self) -> &[u8] {
        self.inner.key()
    }

    fn advance(&mut self) -> &[u8] {
        self.inner.advance();
        self.advance_to_match();
        self.inner.key()
    }

    fn seek(&mut self, target: &[u8]) -> &[u8] {
        self.inner.seek(target);
        if self.inner.key() != TERMINATED && !(self.predicate)(self.inner.key()) {
            self.advance_to_match();
        }
        self.inner.key()
    }

    fn seek_danger(&mut self, target: &[u8]) -> SeekResult<'_> {
        let found = match self.inner.seek_danger(target) {
            SeekResult::Found => true,
            SeekResult::LowerBound(bound) => {
                self.lower_bound.clear();
                self.lower_bound.extend_from_slice(bound);
                false
            }
        };
        if !found {
            return SeekResult::LowerBound(&self.lower_bound);
        }
        if (self.predicate)(self.inner.key()) {
            SeekResult::Found
        } else {
            self.advance_to_match();
            SeekResult::LowerBound(self.inner.key())
        }
    }

    fn size_hint(&self) -> u64 {
        self.inner.size_hint()
    }

    // This planning estimate intentionally uses floating-point precision and
    // Rust's saturating float-to-integer conversion for the bounded ratio.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    fn cost(&self) -> u64 {
        // The cost to iterate is the inner cost divided by selectivity.
        // A 1% selectivity filter makes seek 100x more expensive because
        // it advances past 99 non-matching elements per match.
        let effective = self.inner.cost() as f64 / self.selectivity;
        effective as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SliceCursor;

    #[test]
    fn filters_elements() {
        let items: Vec<&[u8]> = vec![b"aa", b"ab", b"ba", b"bb"];
        let cursor = SliceCursor::new(items);
        let filtered = FilteredCursor::new(cursor, Arc::new(|k: &[u8]| k.starts_with(b"a")), 0.5);
        let mut fc = filtered;
        let mut results = Vec::new();
        while fc.key() != TERMINATED {
            results.push(fc.key().to_vec());
            fc.advance();
        }
        assert_eq!(results, vec![b"aa".to_vec(), b"ab".to_vec()]);
    }

    #[test]
    fn unfiltered_passes_all() {
        let items: Vec<&[u8]> = vec![b"aa", b"bb"];
        let cursor = SliceCursor::new(items);
        let mut fc = FilteredCursor::unfiltered(cursor);
        let mut count = 0;
        while fc.key() != TERMINATED {
            count += 1;
            fc.advance();
        }
        assert_eq!(count, 2);
    }

    #[test]
    fn seek_skips_non_matching() {
        let items: Vec<&[u8]> = vec![b"aa", b"ab", b"ba", b"bb", b"bc"];
        let cursor = SliceCursor::new(items);
        let mut fc = FilteredCursor::new(cursor, Arc::new(|k: &[u8]| k.starts_with(b"b")), 0.6);
        assert_eq!(fc.key(), b"ba");
        fc.seek(b"bb");
        assert_eq!(fc.key(), b"bb");
    }

    #[test]
    fn cost_reflects_selectivity() {
        let items: Vec<Vec<u8>> = (0u32..100)
            .map(|value| value.to_be_bytes().to_vec())
            .collect();
        let cursor = SliceCursor::from_sorted(items);
        let baseline = cursor.cost();
        let fc = FilteredCursor::new(cursor, Arc::new(|_| true), 0.01);
        assert_eq!(fc.cost(), baseline * 100);
    }
}
