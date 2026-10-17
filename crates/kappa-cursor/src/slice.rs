use crate::cursor::{KappaCursor, TERMINATED};

/// Cursor over a sorted slice of owned byte sequences.
///
/// `seek` uses binary search: O(log n). `advance` increments
/// the position: O(1).
///
/// This is the reference implementation and permanent testing
/// oracle. Every trie cursor, every redb cursor, every distributed
/// cursor is tested against `SliceCursor` on the same data. If a
/// specialized cursor produces a different sequence, the
/// specialized cursor has a bug. `SliceCursor` is simple, correct,
/// and slow. It is never retired.
pub struct SliceCursor {
    elements: Vec<Vec<u8>>,
    pos: usize,
}

impl SliceCursor {
    /// Construct from a list of byte sequences.
    /// The input is sorted and deduplicated at construction.
    pub fn new(items: Vec<&[u8]>) -> Self {
        Self::from_owned(items.into_iter().map(<[u8]>::to_vec).collect())
    }

    /// Transfer owned keys into the cursor without copying their bytes.
    /// Establish ordering and uniqueness before exposing traversal.
    pub fn from_owned(mut elements: Vec<Vec<u8>>) -> Self {
        elements.sort();
        elements.dedup();
        Self { elements, pos: 0 }
    }

    /// Construct from already-sorted owned byte vectors.
    /// Caller asserts the input is sorted and deduplicated.
    /// Violation produces wrong results, not UB.
    pub const fn from_sorted(elements: Vec<Vec<u8>>) -> Self {
        Self { elements, pos: 0 }
    }
}

/// Cursor over a sorted key table held in an Arc.
///
/// The Arc clone in the cursor factory closure is O(1). The cursor
/// holds the Arc for its lifetime, preventing deallocation. At 10B
/// keys x 33 bytes = 330 GB, the Arc avoids cloning the entire key
/// table per cursor creation.
///
/// Clean general-purpose type. No rebuild trigger coupling. No
/// counter fields. Rebuild scheduling telemetry belongs to the index owner,
/// not in this type.
pub struct ArcSliceCursor {
    elements: std::sync::Arc<Vec<Vec<u8>>>,
    pos: usize,
}

impl ArcSliceCursor {
    pub const fn from_arc(elements: std::sync::Arc<Vec<Vec<u8>>>) -> Self {
        Self { elements, pos: 0 }
    }
}

impl KappaCursor for ArcSliceCursor {
    fn key(&self) -> &[u8] {
        if self.pos >= self.elements.len() {
            TERMINATED
        } else {
            &self.elements[self.pos]
        }
    }

    fn advance(&mut self) -> &[u8] {
        if self.pos < self.elements.len() {
            self.pos += 1;
        }
        self.key()
    }

    fn seek(&mut self, target: &[u8]) -> &[u8] {
        if self.pos < self.elements.len() && target <= self.elements[self.pos].as_slice() {
            return self.key();
        }
        if self.pos >= self.elements.len() {
            return TERMINATED;
        }
        let remaining = &self.elements[self.pos..];
        match remaining.binary_search_by(|e| e.as_slice().cmp(target)) {
            Ok(i) | Err(i) => self.pos += i,
        }
        self.key()
    }

    fn size_hint(&self) -> u64 {
        self.elements.len().saturating_sub(self.pos) as u64
    }
}

impl KappaCursor for SliceCursor {
    fn key(&self) -> &[u8] {
        if self.pos >= self.elements.len() {
            TERMINATED
        } else {
            &self.elements[self.pos]
        }
    }

    fn advance(&mut self) -> &[u8] {
        if self.pos < self.elements.len() {
            self.pos += 1;
        }
        self.key()
    }

    fn seek(&mut self, target: &[u8]) -> &[u8] {
        // Invariant 3: seek to a position at or before current is a no-op.
        if self.pos < self.elements.len() && target <= self.elements[self.pos].as_slice() {
            return self.key();
        }
        if self.pos >= self.elements.len() {
            return TERMINATED;
        }
        // Binary search from current position forward.
        let remaining = &self.elements[self.pos..];
        match remaining.binary_search_by(|e| e.as_slice().cmp(target)) {
            Ok(i) | Err(i) => self.pos += i,
        }
        self.key()
    }

    fn size_hint(&self) -> u64 {
        self.elements.len().saturating_sub(self.pos) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorted_iteration() {
        let mut c = SliceCursor::new(vec![b"cc", b"aa", b"bb"]);
        assert_eq!(c.key(), b"aa");
        assert_eq!(c.advance(), b"bb");
        assert_eq!(c.advance(), b"cc");
        assert_eq!(c.advance(), TERMINATED);
    }

    #[test]
    fn deduplicates() {
        let mut c = SliceCursor::new(vec![b"aa", b"aa", b"bb"]);
        assert_eq!(c.key(), b"aa");
        assert_eq!(c.advance(), b"bb");
        assert_eq!(c.advance(), TERMINATED);
    }

    #[test]
    fn seek_to_existing() {
        let mut c = SliceCursor::new(vec![b"aa", b"bb", b"cc", b"dd"]);
        assert_eq!(c.seek(b"cc"), b"cc");
    }

    #[test]
    fn seek_to_gap() {
        let mut c = SliceCursor::new(vec![b"aa", b"cc", b"ee"]);
        assert_eq!(c.seek(b"bb"), b"cc");
    }

    #[test]
    fn seek_past_end() {
        let mut c = SliceCursor::new(vec![b"aa", b"bb"]);
        assert_eq!(c.seek(b"zz"), TERMINATED);
    }

    #[test]
    fn empty() {
        let c = SliceCursor::new(Vec::<&[u8]>::new());
        assert_eq!(c.key(), TERMINATED);
    }

    #[test]
    fn size_hint_decrements() {
        let mut c = SliceCursor::new(vec![b"aa", b"bb", b"cc"]);
        assert_eq!(c.size_hint(), 3);
        c.advance();
        assert_eq!(c.size_hint(), 2);
        c.advance();
        assert_eq!(c.size_hint(), 1);
        c.advance();
        assert_eq!(c.size_hint(), 0);
    }

    #[test]
    fn seek_does_not_move_backward() {
        let mut c = SliceCursor::new(vec![b"aa", b"bb", b"cc", b"dd"]);
        c.seek(b"cc");
        assert_eq!(c.key(), b"cc");
        // Invariant 3: seeking to a position at or before current
        // does not move the cursor.
        c.seek(b"aa");
        assert_eq!(c.key(), b"cc");
        // Seeking to current position is also a no-op.
        c.seek(b"cc");
        assert_eq!(c.key(), b"cc");
    }

    #[test]
    fn seek_forward_from_middle() {
        let mut c = SliceCursor::new(vec![b"aa", b"bb", b"cc", b"dd", b"ee"]);
        c.seek(b"bb");
        assert_eq!(c.key(), b"bb");
        c.seek(b"dd");
        assert_eq!(c.key(), b"dd");
    }

    #[test]
    fn seek_after_terminated_stays_terminated() {
        let mut c = SliceCursor::new(vec![b"aa"]);
        c.advance(); // TERMINATED
        assert_eq!(c.key(), TERMINATED);
        assert_eq!(c.seek(b"aa"), TERMINATED);
    }
}
