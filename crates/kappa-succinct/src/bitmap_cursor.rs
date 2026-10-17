#[cfg(feature = "bitmap")]
mod inner {
    use kappa_cursor::KappaCursor;
    use roaring::RoaringBitmap;

    /// Cursor over a Roaring bitmap with an external key lookup table.
    ///
    /// Each set bit at position `i` in the bitmap corresponds to
    /// `keys[i]` in the sorted key table. The cursor yields keys
    /// in sorted order by iterating set bits in ascending order.
    ///
    /// seek is O(log n) via binary search on the key table plus
    /// bitmap rank to find the next set bit. Not linear.
    pub struct BitmapCursor<'a> {
        bitmap: RoaringBitmap,
        keys: &'a [Vec<u8>],
        current_pos: u32,
        current_key: Vec<u8>,
        exhausted: bool,
    }

    impl<'a> BitmapCursor<'a> {
        pub fn try_new(bitmap: RoaringBitmap, keys: &'a [Vec<u8>]) -> Result<Self, &'static str> {
            if keys.windows(2).any(|pair| pair[0] >= pair[1]) {
                return Err("bitmap key mapping must be strictly ordered");
            }
            if bitmap
                .max()
                .is_some_and(|position| position as usize >= keys.len())
            {
                return Err("bitmap position exceeds key mapping");
            }
            Ok(Self::new(bitmap, keys))
        }
        /// Create a cursor from a bitmap and the key table it indexes.
        ///
        /// The key table must be sorted. Each set bit `i` in the bitmap
        /// must satisfy `i < keys.len()`.
        pub fn new(bitmap: RoaringBitmap, keys: &'a [Vec<u8>]) -> Self {
            let first_pos = bitmap.min();
            match first_pos {
                Some(pos) if (pos as usize) < keys.len() => Self {
                    current_key: keys[pos as usize].clone(),
                    current_pos: pos,
                    bitmap,
                    keys,
                    exhausted: false,
                },
                _ => Self {
                    bitmap,
                    keys,
                    current_pos: u32::MAX,
                    current_key: Vec::new(),
                    exhausted: true,
                },
            }
        }

        /// Advance to the next set bit strictly after the current position.
        fn advance_past(&mut self, pos: u32) {
            // rank(pos) gives count of set bits in [0, pos].
            // The next set bit is at select(rank(pos)).
            // But roaring provides range iteration more directly:
            // we want the smallest set bit > pos.
            let next = self.bitmap.range_cardinality(0..=pos);
            // next is the count of set bits in [0, pos]. The next
            // set bit is the (next+1)-th set bit (0-indexed: select(next)).
            match u32::try_from(next)
                .ok()
                .and_then(|rank| self.bitmap.select(rank))
            {
                Some(next_pos) if (next_pos as usize) < self.keys.len() => {
                    self.current_pos = next_pos;
                    self.current_key.clear();
                    self.current_key
                        .extend_from_slice(&self.keys[next_pos as usize]);
                }
                _ => {
                    self.exhausted = true;
                }
            }
        }
    }

    impl KappaCursor for BitmapCursor<'_> {
        fn key(&self) -> &[u8] {
            if self.exhausted {
                kappa_cursor::TERMINATED
            } else {
                &self.current_key
            }
        }

        fn advance(&mut self) -> &[u8] {
            if self.exhausted {
                return kappa_cursor::TERMINATED;
            }
            self.advance_past(self.current_pos);
            self.key()
        }

        fn seek(&mut self, target: &[u8]) -> &[u8] {
            if self.exhausted {
                return kappa_cursor::TERMINATED;
            }
            // Invariant 3: backward seek is a no-op.
            if target <= self.current_key.as_slice() {
                return &self.current_key;
            }

            // Binary search on the key table to find the first
            // position >= target. O(log n) in the key table size.
            let position = match self.keys.binary_search_by(|k| k.as_slice().cmp(target)) {
                Ok(exact) => exact,
                Err(insert) => insert,
            };
            let Ok(start_pos) = u32::try_from(position) else {
                self.exhausted = true;
                return kappa_cursor::TERMINATED;
            };

            if start_pos as usize >= self.keys.len() {
                self.exhausted = true;
                return kappa_cursor::TERMINATED;
            }

            // Find the first set bit at or after start_pos.
            // rank(start_pos - 1) gives bits set before start_pos.
            // select(rank) gives the position of the next set bit.
            let bits_before = if start_pos == 0 {
                0
            } else {
                // rank counts set bits in [0, start_pos - 1]. A count past
                // u32::MAX names no selectable bit, so the cursor is exhausted.
                let Ok(rank) = u32::try_from(self.bitmap.rank(start_pos - 1)) else {
                    self.exhausted = true;
                    return kappa_cursor::TERMINATED;
                };
                rank
            };

            match self.bitmap.select(bits_before) {
                Some(found_pos)
                    if (found_pos as usize) < self.keys.len() && found_pos >= start_pos =>
                {
                    self.current_pos = found_pos;
                    self.current_key.clear();
                    self.current_key
                        .extend_from_slice(&self.keys[found_pos as usize]);
                    &self.current_key
                }
                _ => {
                    self.exhausted = true;
                    kappa_cursor::TERMINATED
                }
            }
        }

        fn size_hint(&self) -> u64 {
            if self.exhausted {
                return 0;
            }
            self.bitmap.range_cardinality(self.current_pos..)
        }

        fn cost(&self) -> u64 {
            self.size_hint()
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn empty_bitmap() {
            let bitmap = RoaringBitmap::new();
            let keys: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec()];
            let cursor = BitmapCursor::new(bitmap, &keys);
            assert_eq!(cursor.key(), kappa_cursor::TERMINATED);
        }

        #[test]
        fn full_bitmap() {
            let mut bitmap = RoaringBitmap::new();
            bitmap.insert(0);
            bitmap.insert(1);
            bitmap.insert(2);
            let keys = vec![b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec()];
            let mut cursor = BitmapCursor::new(bitmap, &keys);
            assert_eq!(cursor.key(), b"aa".as_slice());
            assert_eq!(cursor.advance(), b"bb".as_slice());
            assert_eq!(cursor.advance(), b"cc".as_slice());
            assert_eq!(cursor.advance(), kappa_cursor::TERMINATED);
        }

        #[test]
        fn sparse_bitmap() {
            let mut bitmap = RoaringBitmap::new();
            bitmap.insert(0);
            bitmap.insert(2);
            bitmap.insert(4);
            let keys = vec![
                b"aa".to_vec(),
                b"bb".to_vec(),
                b"cc".to_vec(),
                b"dd".to_vec(),
                b"ee".to_vec(),
            ];
            let mut cursor = BitmapCursor::new(bitmap, &keys);
            assert_eq!(cursor.key(), b"aa".as_slice());
            assert_eq!(cursor.advance(), b"cc".as_slice());
            assert_eq!(cursor.advance(), b"ee".as_slice());
            assert_eq!(cursor.advance(), kappa_cursor::TERMINATED);
        }

        #[test]
        fn seek_to_existing() {
            let mut bitmap = RoaringBitmap::new();
            bitmap.insert(0);
            bitmap.insert(1);
            bitmap.insert(2);
            let keys = vec![b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec()];
            let mut cursor = BitmapCursor::new(bitmap, &keys);
            assert_eq!(cursor.seek(b"bb"), b"bb".as_slice());
        }

        #[test]
        fn seek_between_skips_unset() {
            let mut bitmap = RoaringBitmap::new();
            bitmap.insert(0);
            bitmap.insert(2);
            let keys = vec![b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec()];
            let mut cursor = BitmapCursor::new(bitmap, &keys);
            // Seek to "ab" — between "aa" (set) and "bb" (unset).
            // Next set bit at position >= 1 is position 2 ("cc").
            assert_eq!(cursor.seek(b"ab"), b"cc".as_slice());
        }

        #[test]
        fn seek_backward_noop() {
            let mut bitmap = RoaringBitmap::new();
            bitmap.insert(0);
            bitmap.insert(1);
            bitmap.insert(2);
            let keys = vec![b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec()];
            let mut cursor = BitmapCursor::new(bitmap, &keys);
            cursor.seek(b"bb");
            assert_eq!(cursor.seek(b"aa"), b"bb".as_slice());
        }

        #[test]
        fn seek_past_end() {
            let mut bitmap = RoaringBitmap::new();
            bitmap.insert(0);
            let keys = vec![b"aa".to_vec()];
            let mut cursor = BitmapCursor::new(bitmap, &keys);
            assert_eq!(cursor.seek(b"zz"), kappa_cursor::TERMINATED);
        }

        #[test]
        fn seek_is_log_n_not_linear() {
            // Construct a large bitmap and verify seek does not
            // iterate all elements.
            let n = 100_000u32;
            let mut bitmap = RoaringBitmap::new();
            let mut keys = Vec::with_capacity(n as usize);
            for i in 0..n {
                bitmap.insert(i);
                keys.push(format!("{i:010}").into_bytes());
            }
            let mut cursor = BitmapCursor::new(bitmap, &keys);
            // Seek to near the end. If linear, this takes 100K iterations.
            // If O(log n), it takes ~17 comparisons.
            let target = format!("{:010}", n - 10).into_bytes();
            let result = cursor.seek(&target);
            assert_eq!(result, target.as_slice());
        }

        #[test]
        fn advance_after_seek() {
            let mut bitmap = RoaringBitmap::new();
            bitmap.insert(0);
            bitmap.insert(3);
            bitmap.insert(7);
            let keys: Vec<Vec<u8>> = (0..10).map(|i| format!("{i:02}").into_bytes()).collect();
            let mut cursor = BitmapCursor::new(bitmap, &keys);
            assert_eq!(cursor.key(), b"00".as_slice());
            assert_eq!(cursor.seek(b"02"), b"03".as_slice());
            assert_eq!(cursor.advance(), b"07".as_slice());
            assert_eq!(cursor.advance(), kappa_cursor::TERMINATED);
        }
    }
}

#[cfg(feature = "bitmap")]
pub use inner::BitmapCursor;
