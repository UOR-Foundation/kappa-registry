use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kappa_cursor::{KappaCursor, TERMINATED};

/// Counts each nonempty `key()` consultation, including repeated consultations.
/// Navigation itself is not counted; the consuming set algebra consults keys.
/// Counter updates are relaxed because this is scheduling telemetry, not state
/// publication. Each base publication owns a counter that saturates and is
/// sampled by `should_rebuild`. Retained old views cannot charge a newer base.
pub struct CountedCursor<C> {
    cursor: C,
    counter: Arc<AtomicU64>,
}

impl<C: KappaCursor> CountedCursor<C> {
    pub const fn new(cursor: C, counter: Arc<AtomicU64>) -> Self {
        Self { cursor, counter }
    }
}

impl<C: KappaCursor> KappaCursor for CountedCursor<C> {
    fn key(&self) -> &[u8] {
        let key = self.cursor.key();
        if key != TERMINATED {
            let _ = self
                .counter
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                    Some(value.saturating_add(1))
                });
        }
        key
    }
    fn advance(&mut self) -> &[u8] {
        self.cursor.advance()
    }
    fn seek(&mut self, target: &[u8]) -> &[u8] {
        self.cursor.seek(target)
    }
    fn size_hint(&self) -> u64 {
        self.cursor.size_hint()
    }
    fn cost(&self) -> u64 {
        self.cursor.cost()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_only_nonempty_consultations_and_saturates() {
        let counter = Arc::new(AtomicU64::new(u64::MAX - 1));
        let mut cursor = CountedCursor::new(
            kappa_cursor::SliceCursor::new(vec![b"a", b"b"]),
            counter.clone(),
        );
        assert_eq!(cursor.key(), b"a");
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        assert_eq!(cursor.key(), b"a");
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
        cursor.advance();
        cursor.advance();
        assert_eq!(cursor.key(), TERMINATED);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn navigation_and_estimates_do_not_increment_counter() {
        let counter = Arc::new(AtomicU64::new(0));
        let mut cursor = CountedCursor::new(
            kappa_cursor::SliceCursor::new(vec![b"a", b"b", b"c"]),
            counter.clone(),
        );
        cursor.advance();
        cursor.seek(b"c");
        assert_eq!(cursor.size_hint(), 1);
        assert_eq!(cursor.cost(), 1);
        assert_eq!(counter.load(Ordering::Relaxed), 0);
        assert_eq!(cursor.key(), b"c");
        assert_eq!(counter.load(Ordering::Relaxed), 1);
        cursor.advance();
        assert_eq!(cursor.key(), TERMINATED);
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }
}
