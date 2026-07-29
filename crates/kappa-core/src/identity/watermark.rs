//! O(1) bulk invalidation via watermarks.
//!
//! A watermark invalidates all assertions from an asserter before a
//! given timestamp without enumerating them. Used when a signing key
//! is compromised: set watermark to the compromise time, and all
//! prior assertions are invalid regardless of count.

use dcbor::prelude::*;

/// CBOR key assignments (PERMANENT):
///   0: asserter (text)
///   1: invalidate_before_ms (unsigned)
///   2: reason (text)
///   3: set_at_ms (unsigned)
#[derive(Debug, Clone, CBORCodable)]
pub struct Watermark {
    #[cbor(n = 0)]
    pub asserter: String,
    #[cbor(n = 1)]
    pub invalidate_before_ms: u64,
    #[cbor(n = 2)]
    pub reason: String,
    #[cbor(n = 3)]
    pub set_at_ms: u64,
}

impl Watermark {
    /// Check whether an assertion's valid_from_ms is before this watermark.
    pub fn invalidates(&self, valid_from_ms: u64) -> bool {
        valid_from_ms < self.invalidate_before_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    #[test]
    fn watermark_roundtrip() {
        let w = Watermark {
            asserter: "anchor-1".into(),
            invalidate_before_ms: 5000,
            reason: "key compromise".into(),
            set_at_ms: 6000,
        };
        let bytes = canonical_bytes(&w);
        let decoded: Watermark = from_canonical(&bytes).unwrap();
        assert_eq!(decoded.asserter, w.asserter);
        assert_eq!(decoded.invalidate_before_ms, w.invalidate_before_ms);
    }

    #[test]
    fn invalidates_before_threshold() {
        let w = Watermark {
            asserter: "a".into(),
            invalidate_before_ms: 1000,
            reason: "test".into(),
            set_at_ms: 1001,
        };
        assert!(w.invalidates(999));
        assert!(w.invalidates(0));
        assert!(!w.invalidates(1000));
        assert!(!w.invalidates(1001));
    }
}
