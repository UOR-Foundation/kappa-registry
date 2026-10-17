use std::collections::{BTreeSet, btree_set};

use crate::{KappaCursor, TERMINATED};

/// Borrowed ordered-set traversal without copying keys or materializing a table.
///
/// Construction and forward seek use native tree ranges; advance consumes the
/// range iterator. The borrow prevents mutation for the cursor's lifetime.
pub struct BTreeCursor<'a> {
    source: &'a BTreeSet<Vec<u8>>,
    range: btree_set::Range<'a, Vec<u8>>,
    current: Option<&'a Vec<u8>>,
    remaining_bound: u64,
}

impl<'a> BTreeCursor<'a> {
    pub fn new(source: &'a BTreeSet<Vec<u8>>) -> Self {
        let mut range = source.range::<[u8], _>(..);
        let current = range.next();
        Self {
            source,
            range,
            current,
            remaining_bound: source.len() as u64,
        }
    }
}

impl KappaCursor for BTreeCursor<'_> {
    fn key(&self) -> &[u8] {
        self.current.map_or(TERMINATED, Vec::as_slice)
    }

    fn advance(&mut self) -> &[u8] {
        if self.current.is_some() {
            self.current = self.range.next();
            self.remaining_bound = self.remaining_bound.saturating_sub(1);
        }
        self.key()
    }

    fn seek(&mut self, target: &[u8]) -> &[u8] {
        if self.current.is_none() || target <= self.key() {
            return self.key();
        }
        self.range = self.source.range::<[u8], _>((
            std::ops::Bound::Included(target),
            std::ops::Bound::Unbounded,
        ));
        self.current = self.range.next();
        self.key()
    }

    fn size_hint(&self) -> u64 {
        if self.current.is_none() {
            0
        } else {
            self.remaining_bound
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_seek_borrows_keys_and_exhaustion_is_permanent() -> Result<(), &'static str> {
        let source: BTreeSet<_> = [b"aa", b"cc", b"ee"].map(|key| key.to_vec()).into();
        let mut cursor = BTreeCursor::new(&source);
        let first = source.first().ok_or("nonempty fixture has no first key")?;
        assert_eq!(cursor.key().as_ptr(), first.as_ptr());
        assert_eq!(cursor.seek(b"bb"), b"cc");
        assert_eq!(cursor.seek(b"aa"), b"cc");
        assert_eq!(cursor.advance(), b"ee");
        assert_eq!(cursor.advance(), TERMINATED);
        assert_eq!(cursor.size_hint(), 0);
        assert_eq!(cursor.seek(b"aa"), TERMINATED);
        assert_eq!(cursor.advance(), TERMINATED);
        Ok(())
    }

    #[test]
    fn empty_source_is_exhausted_at_construction() {
        let source = BTreeSet::new();
        let mut cursor = BTreeCursor::new(&source);
        assert_eq!(cursor.key(), TERMINATED);
        assert_eq!(cursor.seek(b"a"), TERMINATED);
        assert_eq!(cursor.size_hint(), 0);
    }
}
