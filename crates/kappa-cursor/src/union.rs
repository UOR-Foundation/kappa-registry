use crate::cursor::{KappaCursor, TERMINATED};

/// Merge of two ordered cursors yielding all elements from either.
///
/// When both cursors point to the same element, yields once and
/// advances both (deduplication). Cost is O(|A| + |B|).
pub struct Union<A: KappaCursor, B: KappaCursor> {
    a: A,
    b: B,
}

impl<A: KappaCursor, B: KappaCursor> Union<A, B> {
    pub const fn new(a: A, b: B) -> Self {
        Self { a, b }
    }
}

impl<A: KappaCursor, B: KappaCursor> KappaCursor for Union<A, B> {
    fn key(&self) -> &[u8] {
        let ka = self.a.key();
        let kb = self.b.key();
        if ka == TERMINATED {
            return kb;
        }
        if kb == TERMINATED {
            return ka;
        }
        if ka <= kb { ka } else { kb }
    }

    fn advance(&mut self) -> &[u8] {
        let ka = self.a.key();
        let kb = self.b.key();
        match (ka == TERMINATED, kb == TERMINATED) {
            (true, true) => TERMINATED,
            (true, false) => self.b.advance(),
            (false, true) => self.a.advance(),
            (false, false) => {
                match ka.cmp(kb) {
                    std::cmp::Ordering::Less => self.a.advance(),
                    std::cmp::Ordering::Greater => self.b.advance(),
                    std::cmp::Ordering::Equal => {
                        // Equal: advance both, deduplicate
                        self.a.advance();
                        self.b.advance()
                    }
                }
            }
        };
        self.key()
    }

    fn seek(&mut self, target: &[u8]) -> &[u8] {
        self.a.seek(target);
        self.b.seek(target);
        self.key()
    }

    fn size_hint(&self) -> u64 {
        self.a.size_hint().saturating_add(self.b.size_hint())
    }

    fn cost(&self) -> u64 {
        self.a.cost().saturating_add(self.b.cost())
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
    fn disjoint() {
        let a = SliceCursor::new(vec![b"aa", b"cc"]);
        let b = SliceCursor::new(vec![b"bb", b"dd"]);
        let u = Union::new(a, b);
        let r = collect(u);
        assert_eq!(
            r,
            vec![
                b"aa".to_vec(),
                b"bb".to_vec(),
                b"cc".to_vec(),
                b"dd".to_vec(),
            ]
        );
    }

    #[test]
    fn overlapping_deduplicates() {
        let a = SliceCursor::new(vec![b"aa", b"bb", b"cc"]);
        let b = SliceCursor::new(vec![b"bb", b"cc", b"dd"]);
        let u = Union::new(a, b);
        let r = collect(u);
        assert_eq!(
            r,
            vec![
                b"aa".to_vec(),
                b"bb".to_vec(),
                b"cc".to_vec(),
                b"dd".to_vec(),
            ]
        );
    }

    #[test]
    fn one_empty() {
        let a = SliceCursor::new(vec![b"xx"]);
        let b = SliceCursor::new(Vec::<&[u8]>::new());
        let r = collect(Union::new(a, b));
        assert_eq!(r, vec![b"xx".to_vec()]);
    }

    #[test]
    fn both_empty() {
        let a = SliceCursor::new(Vec::<&[u8]>::new());
        let b = SliceCursor::new(Vec::<&[u8]>::new());
        let r = collect(Union::new(a, b));
        assert!(r.is_empty());
    }

    #[test]
    fn identical() {
        let items: Vec<&[u8]> = vec![b"aa", b"bb"];
        let a = SliceCursor::new(items.clone());
        let b = SliceCursor::new(items);
        let r = collect(Union::new(a, b));
        assert_eq!(r, vec![b"aa".to_vec(), b"bb".to_vec()]);
    }

    #[test]
    fn seek_before_union_head_preserves_both_inputs() {
        let mut union = Union::new(
            SliceCursor::new(vec![b"aa", b"cc", b"ee"]),
            SliceCursor::new(vec![b"bb", b"cc", b"dd"]),
        );
        assert_eq!(union.seek(b"cc"), b"cc");
        assert_eq!(union.seek(b"aa"), b"cc");
        assert_eq!(
            collect(union),
            vec![b"cc".to_vec(), b"dd".to_vec(), b"ee".to_vec()]
        );
    }
}
