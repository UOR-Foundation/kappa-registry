//! Epoch watermark -- O(1) bulk invalidation.
//!
//! One monotonic integer per anchor: everything asserted before
//! watermark N is void. The Kerberos not-before pattern applied to
//! identity assertions.
//!
//! The watermark is stored in the asserter's namespace as a sequence
//! counter named "watermark". It is checked at read time by
//! resolve_at/resolve_all.

use serde::{Deserialize, Serialize};

/// A watermark record for an anchor.
///
/// Any assertion with `valid_from < watermark_epoch` is treated as
/// invalidated, regardless of whether an individual revocation exists.
/// This provides O(1) bulk revocation without enumerating assertions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct Watermark {
    /// The anchor this watermark applies to.
    /// (Carried for serialization; in practice the namespace implies the anchor.)
    pub epoch: u64,
}

impl Watermark {
    /// A watermark that invalidates nothing (epoch 0).
    pub fn none() -> Self {
        Self { epoch: 0 }
    }

    /// Create a watermark at the given epoch.
    pub fn at(epoch: u64) -> Self {
        Self { epoch }
    }

    /// Check if an assertion's valid_from is before this watermark.
    pub fn invalidates(&self, valid_from: u64) -> bool {
        self.epoch > 0 && valid_from < self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_invalidates_nothing() {
        let w = Watermark::none();
        assert!(!w.invalidates(0));
        assert!(!w.invalidates(1));
        assert!(!w.invalidates(u64::MAX));
    }

    #[test]
    fn watermark_invalidates_prior() {
        let w = Watermark::at(5);
        assert!(w.invalidates(0));
        assert!(w.invalidates(1));
        assert!(w.invalidates(4));
        assert!(!w.invalidates(5));
        assert!(!w.invalidates(6));
    }

    #[test]
    fn watermark_at_1_invalidates_epoch_0() {
        let w = Watermark::at(1);
        assert!(w.invalidates(0));
        assert!(!w.invalidates(1));
    }
}
