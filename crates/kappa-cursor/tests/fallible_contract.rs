use kappa_cursor::{Difference, FallibleCursor, InfallibleCursor, SliceCursor, Union};

#[test]
fn lifted_algebra_preserves_navigation_estimates_and_exhaustion() {
    let algebra = Difference::new(
        Union::new(
            SliceCursor::new(vec![b"aa", b"cc"]),
            SliceCursor::new(vec![b"bb", b"cc", b"dd"]),
        ),
        SliceCursor::new(vec![b"bb"]),
    );
    let mut cursor: Box<dyn FallibleCursor<Error = std::convert::Infallible>> =
        Box::new(InfallibleCursor::new(algebra));
    assert_eq!(cursor.key().unwrap(), Some(b"aa".as_slice()));
    assert!(cursor.size_hint() >= 3);
    assert!(cursor.cost() > 0);
    assert_eq!(cursor.seek(b"ab").unwrap(), Some(b"cc".as_slice()));
    assert_eq!(cursor.seek(b"aa").unwrap(), Some(b"cc".as_slice()));
    assert_eq!(cursor.advance().unwrap(), Some(b"dd".as_slice()));
    assert_eq!(cursor.advance().unwrap(), None);
    assert_eq!(cursor.key().unwrap(), None);
    assert_eq!(cursor.seek(b"aa").unwrap(), None);
    assert_eq!(cursor.advance().unwrap(), None);
    assert_eq!(cursor.size_hint(), 0);
}
