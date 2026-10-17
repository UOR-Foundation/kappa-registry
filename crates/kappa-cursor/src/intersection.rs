use crate::cursor::{KappaCursor, SeekResult, TERMINATED};

/// k-way intersection over ordered cursors.
///
/// Sorts inputs by cost ascending at construction. The cheapest
/// cursor drives the candidate; each remaining cursor seeks to
/// the candidate via `seek_danger`. On mismatch, the leapfrog
/// resets to cursor 0 with the new lower bound.
///
/// Construction positions the cursor on the first intersection
/// element or TERMINATED. `key()` is valid immediately — there is
/// no "before first element" state.
///
/// `Intersection` is itself a `KappaCursor`, so intersections nest.
pub struct Intersection<C: KappaCursor> {
    cursors: Vec<C>,
    candidate: Vec<u8>,
    exhausted: bool,
}

impl<C: KappaCursor> Intersection<C> {
    pub fn new(mut cursors: Vec<C>) -> Self {
        cursors.sort_by_key(KappaCursor::cost);
        let exhausted = cursors.is_empty() || cursors.iter().any(|c| c.key() == TERMINATED);
        let mut s = Self {
            cursors,
            candidate: Vec::new(),
            exhausted,
        };
        if !s.exhausted {
            s.align_initial();
        }
        s
    }

    /// Position on the first element present in all cursors.
    /// Called once at construction. After this, `key()` is valid.
    fn align_initial(&mut self) {
        // Start with cursor 0's current position as the candidate.
        self.candidate.clear();
        self.candidate.extend_from_slice(self.cursors[0].key());

        // Run the leapfrog alignment without advancing cursor 0 first.
        // This is the same logic as the inner loop of advance(), but
        // without the initial cursors[0].advance() call.
        'outer: while self.candidate.as_slice() != TERMINATED {
            let mut i = 0;
            while i < self.cursors.len() {
                match self.cursors[i].seek_danger(&self.candidate) {
                    SeekResult::Found => {
                        i += 1;
                    }
                    SeekResult::LowerBound(lb) => {
                        assert!(
                            lb == TERMINATED || lb > self.candidate.as_slice(),
                            "seek_danger lower bound must exceed target"
                        );
                        if lb == TERMINATED {
                            self.exhausted = true;
                            return;
                        }
                        self.candidate.clear();
                        self.candidate.extend_from_slice(lb);
                        continue 'outer;
                    }
                }
            }
            // All cursors aligned on candidate.
            return;
        }
        self.exhausted = true;
    }
}

impl<C: KappaCursor> KappaCursor for Intersection<C> {
    fn key(&self) -> &[u8] {
        if self.exhausted {
            TERMINATED
        } else {
            &self.candidate
        }
    }

    fn advance(&mut self) -> &[u8] {
        if self.exhausted {
            return TERMINATED;
        }

        // Advance cursor 0 past the current candidate, then realign.
        self.candidate.clear();
        self.candidate.extend_from_slice(self.cursors[0].advance());

        self.align_initial();
        self.key()
    }

    fn seek(&mut self, target: &[u8]) -> &[u8] {
        if self.exhausted {
            return TERMINATED;
        }
        // Invariant 3: no backward movement.
        if target <= self.key() {
            return self.key();
        }
        for c in &mut self.cursors {
            if c.seek(target) == TERMINATED {
                self.exhausted = true;
                return TERMINATED;
            }
        }
        self.candidate.clear();
        self.candidate.extend_from_slice(self.cursors[0].key());
        if self
            .cursors
            .iter()
            .all(|c| c.key() == self.candidate.as_slice())
        {
            return &self.candidate;
        }
        self.align_initial();
        self.key()
    }

    fn size_hint(&self) -> u64 {
        if self.exhausted {
            return 0;
        }
        self.cursors
            .iter()
            .map(KappaCursor::size_hint)
            .min()
            .unwrap_or(0)
    }

    fn cost(&self) -> u64 {
        if self.exhausted {
            return 0;
        }
        self.cursors.iter().map(KappaCursor::cost).sum()
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
    fn empty_inputs() {
        let int = Intersection::new(Vec::<SliceCursor>::new());
        assert_eq!(int.key(), TERMINATED);
    }

    #[test]
    fn single_cursor() {
        let items: Vec<&[u8]> = vec![b"aa", b"bb", b"cc"];
        let cursor = SliceCursor::new(items);
        let r = collect(Intersection::new(vec![cursor]));
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn two_cursors_with_overlap() {
        let a = SliceCursor::new(vec![b"aa", b"bb", b"cc", b"dd"]);
        let b = SliceCursor::new(vec![b"bb", b"dd", b"ee"]);
        let int = Intersection::new(vec![a, b]);
        // key() is valid immediately — positioned on first intersection element.
        assert_eq!(int.key(), b"bb");
        let r = collect(int);
        assert_eq!(r, vec![b"bb".to_vec(), b"dd".to_vec()]);
    }

    #[test]
    fn no_overlap() {
        let a = SliceCursor::new(vec![b"aa", b"cc"]);
        let b = SliceCursor::new(vec![b"bb", b"dd"]);
        let int = Intersection::new(vec![a, b]);
        assert_eq!(int.key(), TERMINATED);
    }

    #[test]
    fn three_way() {
        let a = SliceCursor::new(vec![b"aa", b"bb", b"cc", b"dd", b"ee"]);
        let b = SliceCursor::new(vec![b"bb", b"cc", b"dd"]);
        let c = SliceCursor::new(vec![b"cc", b"dd", b"ff"]);
        let int = Intersection::new(vec![a, b, c]);
        assert_eq!(int.key(), b"cc");
        let r = collect(int);
        assert_eq!(r, vec![b"cc".to_vec(), b"dd".to_vec()]);
    }

    #[test]
    fn identical_inputs() {
        let items: Vec<&[u8]> = vec![b"xx", b"yy", b"zz"];
        let a = SliceCursor::new(items.clone());
        let b = SliceCursor::new(items.clone());
        let int = Intersection::new(vec![a, b]);
        assert_eq!(int.key(), b"xx");
        let r = collect(int);
        assert_eq!(r.len(), 3);
    }

    #[test]
    fn key_valid_before_advance() {
        // This test verifies the construction invariant:
        // key() returns the first intersection element, not
        // cursor 0's first unaligned element.
        let a = SliceCursor::new(vec![b"aa", b"bb", b"cc"]);
        let b = SliceCursor::new(vec![b"cc", b"dd"]);
        let int = Intersection::new(vec![a, b]);
        // "cc" is the only common element. key() must return it
        // immediately, not "aa" (cursor 0's first element).
        assert_eq!(int.key(), b"cc");
    }

    #[test]
    fn seek_no_backward_movement() {
        let a = SliceCursor::new(vec![b"aa", b"bb", b"cc", b"dd"]);
        let b = SliceCursor::new(vec![b"aa", b"bb", b"cc", b"dd"]);
        let mut int = Intersection::new(vec![a, b]);
        assert_eq!(int.key(), b"aa");
        int.seek(b"cc");
        assert_eq!(int.key(), b"cc");
        // Seeking backward is a no-op per invariant 3.
        int.seek(b"aa");
        assert_eq!(int.key(), b"cc");
    }
}
