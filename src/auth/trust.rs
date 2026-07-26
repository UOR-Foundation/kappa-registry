//! Trust policy -- reader-local, non-propagating assertion filter.
//!
//! The trust policy determines which asserters a reader believes and
//! how grouped assertions are presented. It is applied at read time
//! by the caller of `resolve_all`. It is NOT stored, NOT propagated,
//! and NOT part of the Merkle commitment.
//!
//! `fuse` returns grouped-and-unmerged results. The return type
//! `Vec<(String, Vec<IdentityAssertion>)>` is the type-level expression
//! of non-coalescence: there is no signature by which it can collapse
//! two asserters into one value.
//!
//! This is the seam where WASM policy modules will substitute later.
//! The initial implementation is a simple allowlist.

use std::collections::BTreeSet;

use crate::identity::assertion::IdentityAssertion;

/// Trust policy applied to assertion resolution.
///
/// Registered in `app_context`. `resolve_all`'s caller applies it
/// to filter and fuse assertions from multiple asserters.
pub trait TrustPolicy: Send + Sync {
    /// Whether this reader trusts assertions from `asserter` on `facet`.
    fn believes(&self, asserter: &str, facet: &str) -> bool;

    /// Filter and reorder grouped assertions. MUST NOT merge across
    /// asserter groups. MAY remove entire groups. MAY reorder within
    /// or across groups. MUST NOT collapse two asserter groups into one.
    ///
    /// The input is grouped by asserter (each tuple is one asserter's
    /// assertions). The output must maintain this grouping.
    fn fuse(
        &self,
        grouped: Vec<(String, Vec<IdentityAssertion>)>,
    ) -> Vec<(String, Vec<IdentityAssertion>)> {
        // Default: filter by believes(), keep all assertions from trusted asserters.
        grouped
            .into_iter()
            .filter(|(asserter, assertions)| {
                assertions
                    .first()
                    .map(|a| self.believes(asserter, &a.facet))
                    .unwrap_or(false)
            })
            .collect()
    }
}

/// Simple allowlist trust policy.
///
/// Trusts only asserters whose anchor kappas are in the `trusted` set.
/// If the set is empty, trusts all asserters (permissive default for
/// bootstrapping).
pub struct AllowList {
    trusted: BTreeSet<String>,
}

impl AllowList {
    /// Create an allowlist that trusts all asserters.
    pub fn allow_all() -> Self {
        Self {
            trusted: BTreeSet::new(),
        }
    }

    /// Create an allowlist that trusts only the specified asserters.
    pub fn from_set(trusted: BTreeSet<String>) -> Self {
        Self { trusted }
    }
}

impl TrustPolicy for AllowList {
    fn believes(&self, asserter: &str, _facet: &str) -> bool {
        if self.trusted.is_empty() {
            return true;
        }
        self.trusted.contains(asserter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_all_trusts_everything() {
        let policy = AllowList::allow_all();
        assert!(policy.believes("sha256:abc", "key/signing"));
        assert!(policy.believes("sha256:def", "name/display"));
    }

    #[test]
    fn explicit_set_filters() {
        let mut trusted = BTreeSet::new();
        trusted.insert("sha256:abc".to_owned());
        let policy = AllowList::from_set(trusted);
        assert!(policy.believes("sha256:abc", "key/signing"));
        assert!(!policy.believes("sha256:def", "key/signing"));
    }

    #[test]
    fn fuse_filters_untrusted() {
        let mut trusted = BTreeSet::new();
        trusted.insert("sha256:alice".to_owned());
        let policy = AllowList::from_set(trusted);

        let assertion = |asserter: &str| IdentityAssertion {
            asserter: asserter.to_owned(),
            subject: "sha256:bob".to_owned(),
            facet: "key/signing".to_owned(),
            value: b"key-bytes".to_vec(),
            valid_from: 1,
            valid_to: None,
            basis: None,
            audience: None,
            matching_rule: None,
            signature: vec![0u8; 64],
        };

        let grouped = vec![
            ("sha256:alice".to_owned(), vec![assertion("sha256:alice")]),
            ("sha256:eve".to_owned(), vec![assertion("sha256:eve")]),
        ];

        let fused = policy.fuse(grouped);
        assert_eq!(fused.len(), 1);
        assert_eq!(fused[0].0, "sha256:alice");
    }

    #[test]
    fn fuse_preserves_grouping() {
        let policy = AllowList::allow_all();

        let assertion = |asserter: &str, val: &[u8]| IdentityAssertion {
            asserter: asserter.to_owned(),
            subject: "sha256:bob".to_owned(),
            facet: "key/signing".to_owned(),
            value: val.to_vec(),
            valid_from: 1,
            valid_to: None,
            basis: None,
            audience: None,
            matching_rule: None,
            signature: vec![0u8; 64],
        };

        let grouped = vec![
            (
                "sha256:alice".to_owned(),
                vec![assertion("sha256:alice", b"key-a")],
            ),
            (
                "sha256:carol".to_owned(),
                vec![assertion("sha256:carol", b"key-c")],
            ),
        ];

        let fused = policy.fuse(grouped);
        // Both kept, still grouped separately
        assert_eq!(fused.len(), 2);
        assert_ne!(fused[0].0, fused[1].0);
    }
}
