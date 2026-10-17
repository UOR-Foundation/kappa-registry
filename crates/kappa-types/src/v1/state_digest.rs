//! Federation-stable additive fingerprints over domain-separated SHA-256 leaves.
//!
//! The accumulator is a little-endian integer modulo 2^256. Unlike XOR,
//! repeated leaves retain their multiplicity. Names and values are framed with
//! unsigned 64-bit big-endian lengths so separators cannot alias fields.

use sha2::{Digest, Sha256};

use crate::Kappa;

pub const STATE_DIGEST_ALGORITHM: &str = "sha256-add256-v1";
const DOMAIN: &[u8] = b"kappa:state-digest:sha256-add256:v1\0";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StateDigest([u8; 32]);

impl StateDigest {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    pub fn insert(&mut self, name: &str, kappa: &Kappa) {
        self.insert_raw(name.as_bytes(), &kappa.key_bytes());
    }

    pub fn remove(&mut self, name: &str, kappa: &Kappa) {
        self.subtract(Self::leaf(name.as_bytes(), &kappa.key_bytes()));
    }

    pub fn insert_raw(&mut self, name: &[u8], value: &[u8]) {
        self.merge(Self::leaf(name, value));
    }

    pub fn remove_raw(&mut self, name: &[u8], value: &[u8]) {
        self.subtract(Self::leaf(name, value));
    }

    pub fn merge(&mut self, other: Self) {
        let mut carry = 0u16;
        for (left, right) in self.0.iter_mut().zip(other.0) {
            let sum = u16::from(*left) + u16::from(right) + carry;
            *left = sum.to_le_bytes()[0];
            carry = sum >> 8;
        }
    }

    pub fn subtract(&mut self, other: Self) {
        let mut borrow = 0u16;
        for (left, right) in self.0.iter_mut().zip(other.0) {
            let subtrahend = u16::from(right) + borrow;
            let original = u16::from(*left);
            *left = original.wrapping_sub(subtrahend).to_le_bytes()[0];
            borrow = u16::from(original < subtrahend);
        }
    }

    fn leaf(name: &[u8], value: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update((name.len() as u64).to_be_bytes());
        hash.update(name);
        hash.update((value.len() as u64).to_be_bytes());
        hash.update(value);
        Self(hash.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn partition_merge_and_removal_match_full_accumulation() {
        let a = Kappa::sha256(b"a");
        let b = Kappa::sha256(b"b");
        let mut full = StateDigest::default();
        full.insert("first", &a);
        full.insert("second", &b);
        let mut left = StateDigest::default();
        left.insert("first", &a);
        let mut right = StateDigest::default();
        right.insert("second", &b);
        left.merge(right);
        assert_eq!(full, left);
        left.remove("first", &a);
        assert_eq!(left, right);
        left.remove("second", &b);
        assert_eq!(left, StateDigest::default());
    }

    #[test]
    fn multiplicity_framing_and_order_are_preserved() {
        let mut duplicate = StateDigest::default();
        duplicate.insert_raw(b"a", b"b");
        duplicate.insert_raw(b"a", b"b");
        assert_ne!(duplicate, StateDigest::default());
        assert_ne!(
            StateDigest::leaf(b"a=b", b"c"),
            StateDigest::leaf(b"a", b"b=c")
        );
        let mut first = StateDigest::default();
        first.insert_raw(b"a", b"b");
        first.insert_raw(b"c", b"d");
        let mut second = StateDigest::default();
        second.insert_raw(b"c", b"d");
        second.insert_raw(b"a", b"b");
        assert_eq!(first, second);
    }

    #[test]
    fn carries_and_borrows_cross_all_bytes() {
        let mut value = StateDigest::from_bytes([255; 32]);
        let mut one = [0; 32];
        one[0] = 1;
        value.merge(StateDigest::from_bytes(one));
        assert_eq!(value, StateDigest::default());
        value.subtract(StateDigest::from_bytes(one));
        assert_eq!(value.into_bytes(), [255; 32]);
    }
}
