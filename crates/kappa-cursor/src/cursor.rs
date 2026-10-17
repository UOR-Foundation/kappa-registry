/// Sentinel greater than every valid kappa `key_bytes`.
///
/// Kappa `key_bytes` are [`axis_discriminant`, `digest_bytes`...] where
/// the axis discriminant is 0-5 and digest bytes are raw hash output.
/// 0xFF cannot appear as a valid axis discriminant, so a single 0xFF
/// byte compares greater than any valid `key_bytes` sequence.
pub const TERMINATED: &[u8] = &[0xFF];

/// Result of a `seek_danger` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeekResult<'a> {
    /// Target present. Cursor is positioned on it and is valid.
    Found,
    /// Target absent. `lower_bound` is in (target, `next_present`] or
    /// is TERMINATED. The cursor may be in an invalid state and must
    /// receive only further `seek_danger` calls until one returns
    /// `Found`.
    LowerBound(&'a [u8]),
}

/// An ordered cursor over sorted byte sequences.
///
/// Implementations own their iteration state. The cursor holds
/// whatever resources it needs -- a read transaction handle, a trie
/// reference, a sorted buffer -- and releases them on drop. No
/// lifetime parameter. `Box<dyn KappaCursor>` works in trait method
/// returns without infecting the store trait with lifetimes.
///
/// Elements are raw `key_bytes`, not Kappa structs. Consumers that
/// need a Kappa call `Kappa::from_key_bytes(cursor.key())` at the
/// consumption point. Consumers that need only byte comparison
/// (GC, intersection combinators) never construct a Kappa.
///
/// # Contract
///
/// A cursor is either positioned on a valid element or at TERMINATED.
/// There is no "before first element" state. Construction positions
/// the cursor on the first valid element or TERMINATED. `key()` is
/// valid immediately after construction.
///
/// For leaf cursors (`SliceCursor`), construction positions at `elements[0]`.
/// For composed cursors (`Intersection`, `Difference`, `FilteredCursor`),
/// construction runs the alignment/filtering logic and positions on
/// the first output element.
///
/// # Invariants
///
/// Enforced with `assert!`, not `debug_assert!`. A violated
/// invariant here is a false attestation in an audit substrate,
/// not a bad search result. One comparison per iteration is the
/// correct price.
///
/// 1. `key()` is non-decreasing across `advance()` and `seek()`.
/// 2. `seek(t)` returns a key >= t, or TERMINATED.
/// 3. `seek(t)` where t <= `key()` does not move the cursor.
/// 4. After `seek_danger` returns `LowerBound`, only `seek_danger`
///    is legal until one returns `Found`.
/// 5. Consecutive `seek_danger` targets strictly increase.
pub trait KappaCursor: Send {
    /// Current position. TERMINATED when exhausted.
    /// Valid immediately after construction.
    fn key(&self) -> &[u8];

    /// Advance one position. Returns the new key, or TERMINATED.
    fn advance(&mut self) -> &[u8];

    /// Advance to the first key >= target. Never moves backward.
    /// Returns the key landed on, or TERMINATED.
    ///
    /// Implementations that override MUST enforce invariant 3:
    /// if target <= `self.key()`, return `self.key()` without moving.
    /// The default enforces this with an assert. Overrides MUST
    /// include the same assert or equivalent guard.
    ///
    /// Implementations with sublinear seek (B+tree re-range, trie
    /// descent) SHOULD override for performance. The default is
    /// repeated `advance`.
    fn seek(&mut self, target: &[u8]) -> &[u8] {
        // Invariant 3: seek to a position at or before current is a no-op.
        if target <= self.key() {
            return self.key();
        }
        while self.key() < target && self.key() != TERMINATED {
            self.advance();
        }
        self.key()
    }

    /// Approximate seek. May leave the cursor invalid and return a
    /// lower bound rather than positioning exactly.
    ///
    /// On the miss path -- the common path inside an intersection --
    /// exact positioning is wasted work because the caller restarts.
    ///
    /// After `LowerBound`, the cursor must receive only further
    /// `seek_danger` calls until one returns `Found`.
    fn seek_danger(&mut self, target: &[u8]) -> SeekResult<'_> {
        if target == TERMINATED {
            return SeekResult::LowerBound(TERMINATED);
        }
        if self.key() < target {
            self.seek(target);
        }
        if self.key() == target {
            SeekResult::Found
        } else {
            SeekResult::LowerBound(self.key())
        }
    }

    /// Upper bound on remaining elements.
    fn size_hint(&self) -> u64;

    /// Best-effort cost to drive this cursor to exhaustion, relative
    /// to one in-memory index scan of the same cardinality.
    ///
    /// NOT cardinality. An index-only scan and a scan requiring blob
    /// fetch plus dCBOR decode differ by orders of magnitude at equal
    /// cardinality. The intersection orders by cost, never by size.
    ///
    /// The default returns `size_hint()`, which is correct ONLY for
    /// in-memory cursors with O(1) per-element cost (`SliceCursor`,
    /// `EmptyCursor`, `OnceCursor`). Cursors with per-element I/O (redb
    /// blob fetch, network round-trip) MUST override to reflect the
    /// true cost. `FilteredCursor` overrides to inflate cost by the
    /// inverse of selectivity.
    fn cost(&self) -> u64 {
        self.size_hint()
    }
}

impl<C: KappaCursor + ?Sized> KappaCursor for Box<C> {
    fn key(&self) -> &[u8] {
        (**self).key()
    }
    fn advance(&mut self) -> &[u8] {
        (**self).advance()
    }
    fn seek(&mut self, target: &[u8]) -> &[u8] {
        (**self).seek(target)
    }
    fn seek_danger(&mut self, target: &[u8]) -> SeekResult<'_> {
        (**self).seek_danger(target)
    }
    fn size_hint(&self) -> u64 {
        (**self).size_hint()
    }
    fn cost(&self) -> u64 {
        (**self).cost()
    }
}

/// A cursor that can bound its current block, permitting the
/// intersection to skip the block without decoding it.
///
/// This trait is an optimization and MUST NOT be load-bearing for
/// any security property. `Intersection` is generic over
/// `KappaCursor` and cannot name `BlockCursor`. No correctness
/// path can rest on skipping.
pub trait BlockCursor: KappaCursor {
    /// Highest key in the current block.
    fn block_max_key(&self) -> &[u8];

    /// True if any element in the current block satisfies the
    /// predicate. False permits skipping the block untouched.
    fn block_may_match(&self, pred: &dyn Fn(&[u8]) -> bool) -> bool;

    /// Advance past the current block. Returns the new key.
    fn skip_block(&mut self) -> &[u8];
}

impl<C: BlockCursor + ?Sized> BlockCursor for Box<C> {
    fn block_max_key(&self) -> &[u8] {
        (**self).block_max_key()
    }
    fn block_may_match(&self, pred: &dyn Fn(&[u8]) -> bool) -> bool {
        (**self).block_may_match(pred)
    }
    fn skip_block(&mut self) -> &[u8] {
        (**self).skip_block()
    }
}
