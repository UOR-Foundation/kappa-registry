#![cfg(feature = "bitmap")]

use kappa_cursor::{KappaCursor, TERMINATED};
use kappa_succinct::BitmapCursor;
use roaring::RoaringBitmap;

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn remaining_count_tracks_sparse_seek_advance_and_exhaustion() -> TestResult {
    let keys: Vec<Vec<u8>> = (0..8).map(|position| vec![position]).collect();
    let bitmap = [0, 3, 7].into_iter().collect();
    let mut cursor = BitmapCursor::try_new(bitmap, &keys)?;
    assert_eq!(cursor.size_hint(), 3);
    assert_eq!(cursor.seek(&[2]), &[3]);
    assert_eq!(cursor.size_hint(), 2);
    assert_eq!(cursor.cost(), 2);
    assert_eq!(cursor.seek(&[1]), &[3]);
    assert_eq!(cursor.size_hint(), 2);
    assert_eq!(cursor.advance(), &[7]);
    assert_eq!(cursor.size_hint(), 1);
    assert_eq!(cursor.advance(), TERMINATED);
    assert_eq!(cursor.size_hint(), 0);
    assert_eq!(cursor.cost(), 0);
    assert_eq!(cursor.advance(), TERMINATED);
    Ok(())
}

#[test]
fn rejects_out_of_range_positions_including_after_valid_prefix() {
    let keys = vec![b"a".to_vec()];
    let bitmap: RoaringBitmap = [0, 1].into_iter().collect();
    assert!(BitmapCursor::try_new(bitmap, &keys).is_err());
}

#[test]
fn rejects_unsorted_and_duplicate_mapping() {
    for keys in [
        vec![b"b".to_vec(), b"a".to_vec()],
        vec![b"a".to_vec(), b"a".to_vec()],
    ] {
        assert!(BitmapCursor::try_new(RoaringBitmap::new(), &keys).is_err());
    }
}
