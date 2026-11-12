//! Ordered byte intervals: the one definition of a prefix's key range, of
//! resuming a traversal strictly after a position, and of seeking to a
//! position.
//!
//! Keys compare as byte strings, lexicographically. An [`Interval`] holds a
//! contiguous set of keys: from an inclusive or exclusive lower bound to an
//! exclusive upper bound, or unbounded above. Its representation is
//! private and every constructor and transformation normalizes an interval
//! holding no key to the exhausted interval, so an exhausted interval is
//! one state, never a reversed or empty range, and never a sentinel key:
//! general storage keys may begin with or consist of `0xFF`, unlike kappa
//! `key_bytes` (`TERMINATED`).
//!
//! This module decides interval membership and the bytes an interval owns,
//! and nothing else. Which traversal a resume position belongs to, whether a
//! stale position is refused or restarted, and what constructing an
//! interval or examining a key is admitted at are decided by the operation
//! that owns the traversal, from the costs this module states
//! ([`Interval::prefix_cost`], [`Interval::position_cost`],
//! [`Interval::bound_bytes`]).

use std::ops::Bound;

/// The lower bound of a non-exhausted interval.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum Lower {
    /// Keys at or after this one.
    Included(Vec<u8>),
    /// Keys strictly after this one.
    Excluded(Vec<u8>),
}

impl Lower {
    fn key(&self) -> &[u8] {
        match self {
            Self::Included(key) | Self::Excluded(key) => key,
        }
    }
}

/// A non-empty range of keys.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct Range {
    lower: Lower,
    upper: Option<Vec<u8>>,
}

/// A set of byte keys contiguous in lexicographic order.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Interval {
    /// `None`: no key.
    range: Option<Range>,
}

/// The least byte string greater than every key starting with `prefix`:
/// the prefix with its last byte below `0xFF` incremented and every byte
/// after it removed. `None` when no finite bound exists: the empty prefix
/// and prefixes of `0xFF` bytes only, whose keys extend to the end of the
/// key space.
pub fn prefix_upper(prefix: &[u8]) -> Option<Vec<u8>> {
    let last = prefix.iter().rposition(|byte| *byte < 0xFF)?;
    let mut upper = prefix[..=last].to_vec();
    upper[last] += 1;
    Some(upper)
}

/// Bytes [`prefix_upper`] of `prefix` occupies.
fn prefix_upper_len(prefix: &[u8]) -> u64 {
    prefix
        .iter()
        .rposition(|byte| *byte < 0xFF)
        .map_or(0, |last| last as u64 + 1)
}

impl Interval {
    /// The interval holding no key.
    pub const fn exhausted() -> Self {
        Self { range: None }
    }

    /// Every key.
    pub const fn all() -> Self {
        Self {
            range: Some(Range {
                lower: Lower::Included(Vec::new()),
                upper: None,
            }),
        }
    }

    /// Every key starting with `prefix`. Owns [`Self::prefix_cost`] bytes.
    pub fn prefix(prefix: &[u8]) -> Self {
        Self::normalized(Lower::Included(prefix.to_vec()), prefix_upper(prefix))
    }

    /// Bytes [`Self::prefix`] of `prefix` allocates: the prefix and its
    /// upper bound, computed without allocating either. `None` when the sum
    /// does not fit in `u64`: a cost is a bound to admit, never clamped.
    pub fn prefix_cost(prefix: &[u8]) -> Option<u64> {
        (prefix.len() as u64).checked_add(prefix_upper_len(prefix))
    }

    /// Bytes [`Self::after`] or [`Self::at_or_after`] at `position` may
    /// allocate: a copy of the position as the new lower bound.
    pub fn position_cost(position: &[u8]) -> u64 {
        position.len() as u64
    }

    /// The interval from `lower` to `upper`, or exhausted when that holds
    /// no key: an included lower bound at or past the upper bound, or an
    /// excluded lower bound whose immediate successor (itself followed by a
    /// zero byte) is at or past it.
    fn normalized(lower: Lower, upper: Option<Vec<u8>>) -> Self {
        let empty = upper.as_deref().is_some_and(|end| match &lower {
            Lower::Included(start) => start.as_slice() >= end,
            Lower::Excluded(start) => {
                start.as_slice() >= end
                    || (end.len() == start.len() + 1
                        && end.starts_with(start)
                        && end[start.len()] == 0)
            }
        });
        if empty {
            return Self::exhausted();
        }
        Self {
            range: Some(Range { lower, upper }),
        }
    }

    /// Whether the interval holds no key.
    pub const fn is_exhausted(&self) -> bool {
        self.range.is_none()
    }

    /// Whether `key` belongs to the interval.
    pub fn contains(&self, key: &[u8]) -> bool {
        let Some(range) = &self.range else {
            return false;
        };
        let above = match &range.lower {
            Lower::Included(start) => key >= start.as_slice(),
            Lower::Excluded(start) => key > start.as_slice(),
        };
        above && range.upper.as_deref().is_none_or(|end| key < end)
    }

    /// The keys of this interval strictly after `position` (an exclusive
    /// resume), by the one ordered rule: a position before the interval
    /// leaves it unchanged, a position inside it excludes everything up to
    /// and including the position, and a position at or beyond a finite
    /// upper bound exhausts it.
    #[must_use]
    pub fn after(self, position: &[u8]) -> Self {
        let Some(Range { lower, upper }) = self.range else {
            return Self::exhausted();
        };
        let before = match &lower {
            Lower::Included(start) => position < start.as_slice(),
            Lower::Excluded(start) => position <= start.as_slice(),
        };
        if before {
            return Self {
                range: Some(Range { lower, upper }),
            };
        }
        Self::normalized(Lower::Excluded(position.to_vec()), upper)
    }

    /// The keys of this interval at or after `position` (an inclusive
    /// seek): a position at or before the interval's lower bound leaves it
    /// unchanged, a position inside it starts it at the position, and a
    /// position at or beyond a finite upper bound exhausts it.
    #[must_use]
    pub fn at_or_after(self, position: &[u8]) -> Self {
        let Some(Range { lower, upper }) = self.range else {
            return Self::exhausted();
        };
        // A position at an excluded lower bound adds nothing: that key is
        // outside the interval either way.
        if position <= lower.key() {
            return Self {
                range: Some(Range { lower, upper }),
            };
        }
        Self::normalized(Lower::Included(position.to_vec()), upper)
    }

    /// The interval's bounds, borrowed, for a native range; `None` when it
    /// is exhausted, so no native range is built for an interval that holds
    /// no key.
    pub fn bounds(&self) -> Option<(Bound<&[u8]>, Bound<&[u8]>)> {
        let range = self.range.as_ref()?;
        let lower = match &range.lower {
            Lower::Included(start) => Bound::Included(start.as_slice()),
            Lower::Excluded(start) => Bound::Excluded(start.as_slice()),
        };
        let upper = range
            .upper
            .as_deref()
            .map_or(Bound::Unbounded, Bound::Excluded);
        Some((lower, upper))
    }

    /// Bytes the interval's bounds occupy: what a native range copies to
    /// encode them. An unbounded end and an empty bound copy nothing. `None`
    /// when the sum does not fit in `u64`.
    pub fn bound_bytes(&self) -> Option<u64> {
        self.range.as_ref().map_or(Some(0), |range| {
            (range.lower.key().len() as u64)
                .checked_add(range.upper.as_ref().map_or(0, Vec::len) as u64)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Interval, prefix_upper};

    /// Every byte string of length at most three over an alphabet holding
    /// the bytes the bound arithmetic distinguishes.
    fn keys() -> Vec<Vec<u8>> {
        const ALPHABET: [u8; 7] = [0x00, 0x01, 0x12, 0x34, 0x35, 0xFE, 0xFF];
        let mut keys = vec![Vec::new()];
        let mut frontier = vec![Vec::new()];
        for _ in 0..3 {
            let mut next = Vec::new();
            for key in &frontier {
                for byte in ALPHABET {
                    let mut longer = key.clone();
                    longer.push(byte);
                    next.push(longer);
                }
            }
            keys.extend(next.iter().cloned());
            frontier = next;
        }
        keys
    }

    /// Whether some key of the sampled space lies in `interval`: an
    /// exhausted interval must hold none, and a non-exhausted one at least
    /// one key of the full key space (checked where the sample can show it).
    fn holds_any(interval: &Interval, keys: &[Vec<u8>]) -> bool {
        keys.iter().any(|key| interval.contains(key))
    }

    #[test]
    fn prefix_bounds_carry_and_truncate() {
        assert_eq!(prefix_upper(&[0x12, 0x34]), Some(vec![0x12, 0x35]));
        assert_eq!(prefix_upper(&[0x12, 0xFF]), Some(vec![0x13]));
        assert_eq!(prefix_upper(&[0x12, 0xFF, 0xFF]), Some(vec![0x13]));
        assert_eq!(prefix_upper(&[0xFF, 0xFF]), None);
        assert_eq!(prefix_upper(&[]), None);
        assert_eq!(Interval::prefix(&[]), Interval::all());
        for prefix in keys() {
            let upper = prefix_upper(&prefix).map_or(0, |upper| upper.len() as u64);
            assert_eq!(
                Interval::prefix_cost(&prefix),
                Some(prefix.len() as u64 + upper)
            );
            assert_eq!(
                Interval::prefix(&prefix).bound_bytes(),
                Interval::prefix_cost(&prefix).filter(|_| !prefix.is_empty()),
                "a prefix's native bounds copy what the interval owns, except the empty prefix's"
            );
        }
    }

    /// The defining property: a key is in a prefix's interval exactly when
    /// it starts with the prefix.
    #[test]
    fn a_prefix_interval_holds_exactly_its_keys() {
        let keys = keys();
        for prefix in &keys {
            let interval = Interval::prefix(prefix);
            for key in &keys {
                assert_eq!(
                    interval.contains(key),
                    key.starts_with(prefix),
                    "prefix {prefix:02x?} key {key:02x?}"
                );
            }
        }
    }

    /// Resuming, seeking and their compositions (excluded lower bounds
    /// resumed or sought again) keep exactly the keys their rules name, and
    /// an interval holding none is exhausted.
    #[test]
    fn compositions_keep_exactly_their_keys() {
        let keys = keys();
        let positions: Vec<&Vec<u8>> = keys.iter().filter(|key| key.len() <= 2).collect();
        for prefix in keys.iter().filter(|key| key.len() <= 1) {
            for first in &positions {
                let resumed = Interval::prefix(prefix).after(first);
                for second in &positions {
                    let twice = resumed.clone().after(second);
                    let sought = resumed.clone().at_or_after(second);
                    for key in &keys {
                        let base = key.starts_with(prefix) && key > *first;
                        assert_eq!(twice.contains(key), base && key > *second);
                        assert_eq!(sought.contains(key), base && key >= *second);
                    }
                    for interval in [&twice, &sought] {
                        if interval.is_exhausted() {
                            assert!(!holds_any(interval, &keys));
                            assert!(interval.bounds().is_none());
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn the_resume_and_seek_cases() {
        let prefix = Interval::prefix(&[0x10]);
        assert_eq!(prefix.clone().after(&[0x0F]), prefix, "before: unchanged");
        let inside = prefix.clone().after(&[0x10, 0x05]);
        assert!(!inside.contains(&[0x10, 0x05]) && inside.contains(&[0x10, 0x06]));
        assert!(prefix.clone().after(&[0x11]).is_exhausted(), "at the bound");
        assert!(prefix.clone().after(&[0x20]).is_exhausted(), "beyond it");
        assert!(prefix.clone().at_or_after(&[0x11]).is_exhausted());
        assert!(
            prefix
                .clone()
                .at_or_after(&[0x10, 0x05])
                .contains(&[0x10, 0x05])
        );
        assert!(Interval::exhausted().after(&[]).is_exhausted());
        // An excluded bound whose only successor below the upper bound is
        // itself followed by a zero byte still holds that key.
        let tight = Interval::prefix(&[0x10]).after(&[0x10]);
        assert!(tight.contains(&[0x10, 0x00]) && !tight.is_exhausted());
    }

    #[test]
    fn an_exhausted_interval_has_no_native_bounds() {
        assert!(Interval::exhausted().bounds().is_none());
        assert_eq!(Interval::exhausted().bound_bytes(), Some(0));
        assert_eq!(Interval::prefix(&[0x12, 0x34]).bound_bytes(), Some(4));
        assert_eq!(Interval::all().bound_bytes(), Some(0), "nothing to copy");
        assert!(Interval::all().bounds().is_some());
    }

    /// A prefix interval's construction and the native copy of its bounds
    /// together fit four prefix lengths: the upper bound is never longer
    /// than the prefix, so a length bound is conservative whatever the
    /// prefix's contents. This proves the interval-plus-bound-copy component
    /// only, not any other allocation of a database adapter.
    #[test]
    fn prefix_construction_and_bound_copy_fit_four_prefix_lengths() {
        for prefix in keys() {
            let Some(construction) = Interval::prefix_cost(&prefix) else {
                panic!("sampled prefixes have at most three bytes");
            };
            let Some(copied_bounds) = Interval::prefix(&prefix).bound_bytes() else {
                panic!("sampled interval bounds have at most six bytes");
            };
            let Some(measured) = construction.checked_add(copied_bounds) else {
                panic!("sampled construction and copy fit in u64");
            };
            let Some(conservative) = (prefix.len() as u64).checked_mul(4) else {
                panic!("sampled prefix length times four fits in u64");
            };
            assert!(
                measured <= conservative,
                "prefix {prefix:02x?}: construction {construction}, \
                 bound copy {copied_bounds}, bound {conservative}"
            );
        }
    }

    /// Equal-length prefixes can differ in exact cost: the upper bound
    /// truncates trailing `0xFF` bytes.
    #[test]
    fn equal_length_prefixes_can_have_different_exact_costs() {
        assert_eq!(Interval::prefix_cost(&[0x12, 0x34]), Some(4));
        assert_eq!(Interval::prefix_cost(&[0x12, 0xff]), Some(3));
        assert_eq!(Interval::prefix_cost(&[0xff, 0xff]), Some(2));
    }
}
