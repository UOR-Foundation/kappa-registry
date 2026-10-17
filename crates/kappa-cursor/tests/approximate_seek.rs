use kappa_cursor::{Intersection, KappaCursor, SeekResult, SliceCursor, TERMINATED};

// A miss deliberately invalidates position access, even when the underlying
// oracle happened to land on a real key. Only approximate seeking may recover.
struct InvalidatingCursor {
    inner: SliceCursor,
    valid: bool,
}

impl InvalidatingCursor {
    fn new(keys: Vec<&[u8]>) -> Self {
        Self {
            inner: SliceCursor::new(keys),
            valid: true,
        }
    }
}

impl KappaCursor for InvalidatingCursor {
    fn key(&self) -> &[u8] {
        assert!(self.valid, "position accessed after approximate miss");
        self.inner.key()
    }

    fn advance(&mut self) -> &[u8] {
        assert!(self.valid, "advance after approximate miss");
        self.inner.advance()
    }

    fn seek(&mut self, target: &[u8]) -> &[u8] {
        assert!(self.valid, "exact seek after approximate miss");
        self.inner.seek(target)
    }

    fn seek_danger(&mut self, target: &[u8]) -> SeekResult<'_> {
        let key = self.inner.seek(target);
        self.valid = key == target && key != TERMINATED;
        if self.valid {
            SeekResult::Found
        } else {
            SeekResult::LowerBound(key)
        }
    }

    fn size_hint(&self) -> u64 {
        assert!(self.valid, "size hint after approximate miss");
        self.inner.size_hint()
    }
}

#[test]
fn exhausted_intersection_never_queries_invalid_children() {
    let cursor = Intersection::new(vec![
        InvalidatingCursor::new(vec![b"aa", b"cc"]),
        InvalidatingCursor::new(vec![b"bb", b"dd"]),
    ]);
    assert_eq!(cursor.key(), TERMINATED);
    assert_eq!(cursor.size_hint(), 0);
}

#[test]
fn leapfrog_recovers_invalid_driver_before_emitting() {
    let mut cursor = Intersection::new(vec![
        InvalidatingCursor::new(vec![b"aa", b"dd", b"gg"]),
        InvalidatingCursor::new(vec![b"bb", b"dd", b"ff", b"gg"]),
    ]);
    assert_eq!(cursor.key(), b"dd");
    assert_eq!(cursor.advance(), b"gg");
    assert_eq!(cursor.advance(), TERMINATED);
}
