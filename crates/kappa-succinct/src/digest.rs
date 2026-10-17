use kappa_types::StateDigest;

/// Additive, order-independent digest of a key multiset. The index enforces
/// set membership before calling insert or remove.
#[derive(Debug, Clone, Default)]
pub struct IncrementalDigest {
    state: StateDigest,
}

impl IncrementalDigest {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, key: &[u8]) {
        self.state.insert_raw(key, &[]);
    }

    pub fn remove(&mut self, key: &[u8]) {
        self.state.remove_raw(key, &[]);
    }

    pub fn insert_tag(&mut self, name: &str, kappa: &kappa_types::Kappa) {
        self.state.insert(name, kappa);
    }

    pub fn remove_tag(&mut self, name: &str, kappa: &kappa_types::Kappa) {
        self.state.remove(name, kappa);
    }

    pub const fn from_state(state: [u8; 32]) -> Self {
        Self {
            state: StateDigest::from_bytes(state),
        }
    }

    pub const fn value(&self) -> &[u8; 32] {
        self.state.as_bytes()
    }

    pub fn merge(&mut self, other: &Self) {
        self.state.merge(other.state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_removal_inverts_insertion_but_duplicates_do_not_cancel() {
        let mut digest = IncrementalDigest::new();
        digest.insert(b"key");
        let first = *digest.value();
        digest.insert(b"key");
        assert_ne!(*digest.value(), [0; 32]);
        digest.remove(b"key");
        assert_eq!(*digest.value(), first);
        digest.remove(b"key");
        assert_eq!(*digest.value(), [0; 32]);
    }

    #[test]
    fn partition_merge_matches_whole_digest() {
        let mut left = IncrementalDigest::new();
        left.insert(b"a");
        let mut right = IncrementalDigest::new();
        right.insert(b"b");
        left.merge(&right);
        let mut whole = IncrementalDigest::new();
        whole.insert(b"b");
        whole.insert(b"a");
        assert_eq!(left.value(), whole.value());
        assert_eq!(
            IncrementalDigest::from_state(*whole.value()).value(),
            whole.value()
        );
    }
}
