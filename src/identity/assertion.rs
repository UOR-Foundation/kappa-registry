//! Identity assertion -- the atom of the identity model.
//!
//! An assertion is a signed claim by an asserter about a subject on a
//! facet. It is stored in the asserter's namespace, never the subject's.
//! Multiple assertions about the same (subject, facet) from different
//! asserters are NOT conflicts -- they are distinguishable facts.
//! resolve_at returns Vec, not Option. No merge operation exists.

use serde::{Deserialize, Serialize};

use crate::kappa::KappaLabel;

/// A signed identity assertion.
///
/// Content-addressed: identical assertions from the same asserter dedupe.
/// Stored in asserter's namespace via edge store.
/// Natural key: asserter + subject + facet + valid_from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IdentityAssertion {
    /// Who says this (anchor kappa of the asserter).
    pub asserter: String,
    /// About whom (anchor kappa of the subject).
    pub subject: String,
    /// What aspect (hierarchical facet path, e.g., "key/signing").
    pub facet: String,
    /// The claim (opaque bytes -- interpretation depends on facet).
    pub value: Vec<u8>,
    /// Asserted start of validity (asserter's epoch counter).
    pub valid_from: u64,
    /// Asserted end of validity (None = unbounded).
    pub valid_to: Option<u64>,
    /// Prior assertion this extends (kappa of superseded assertion).
    pub basis: Option<String>,
    /// Audience scope (anchor kappa of audience, None = public).
    pub audience: Option<String>,
    /// Pinned schema for equality semantics (kappa of schema blob).
    pub matching_rule: Option<String>,
    /// Asserter's signature over canonical form of all other fields.
    pub signature: Vec<u8>,
}

impl IdentityAssertion {
    /// Compute the canonical bytes for signing/verification.
    ///
    /// Excludes the signature field. All other fields are serialized
    /// in a fixed order with length prefixes. This format MUST be
    /// frozen before any assertion is created in production.
    ///
    /// Format:
    ///   u16(asserter.len) + asserter
    ///   u16(subject.len) + subject
    ///   u16(facet.len) + facet
    ///   u32(value.len) + value
    ///   u64(valid_from)
    ///   u8(has_valid_to) + [u64(valid_to)]
    ///   u8(has_basis) + [u16(basis.len) + basis]
    ///   u8(has_audience) + [u16(audience.len) + audience]
    ///   u8(has_matching_rule) + [u16(matching_rule.len) + matching_rule]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);

        // asserter
        buf.extend_from_slice(&(self.asserter.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.asserter.as_bytes());

        // subject
        buf.extend_from_slice(&(self.subject.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.subject.as_bytes());

        // facet
        buf.extend_from_slice(&(self.facet.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.facet.as_bytes());

        // value
        buf.extend_from_slice(&(self.value.len() as u32).to_be_bytes());
        buf.extend_from_slice(&self.value);

        // valid_from
        buf.extend_from_slice(&self.valid_from.to_be_bytes());

        // valid_to
        match self.valid_to {
            Some(vt) => {
                buf.push(0x01);
                buf.extend_from_slice(&vt.to_be_bytes());
            }
            None => buf.push(0x00),
        }

        // basis
        Self::encode_optional_string(&mut buf, self.basis.as_deref());

        // audience
        Self::encode_optional_string(&mut buf, self.audience.as_deref());

        // matching_rule
        Self::encode_optional_string(&mut buf, self.matching_rule.as_deref());

        buf
    }

    fn encode_optional_string(buf: &mut Vec<u8>, opt: Option<&str>) {
        match opt {
            Some(s) => {
                buf.push(0x01);
                buf.extend_from_slice(&(s.len() as u16).to_be_bytes());
                buf.extend_from_slice(s.as_bytes());
            }
            None => buf.push(0x00),
        }
    }

    /// Compute the kappa-label for this assertion.
    ///
    /// The kappa is SHA-256 of the full serialized assertion including
    /// the signature. This is the content address used for storage
    /// and reference.
    pub fn kappa(&self) -> String {
        // Full serialization includes signature for content addressing.
        let mut buf = self.canonical_bytes();
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        KappaLabel::sha256(&buf).as_str().to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_assertion(asserter: &str, subject: &str, facet: &str) -> IdentityAssertion {
        IdentityAssertion {
            asserter: asserter.to_owned(),
            subject: subject.to_owned(),
            facet: facet.to_owned(),
            value: b"test-value".to_vec(),
            valid_from: 1,
            valid_to: None,
            basis: None,
            audience: None,
            matching_rule: None,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn canonical_bytes_deterministic() {
        let a = test_assertion("sha256:aaa", "sha256:bbb", "key/signing");
        let b1 = a.canonical_bytes();
        let b2 = a.canonical_bytes();
        assert_eq!(b1, b2);
    }

    #[test]
    fn canonical_bytes_excludes_signature() {
        let mut a = test_assertion("sha256:aaa", "sha256:bbb", "key/signing");
        let b1 = a.canonical_bytes();
        a.signature = vec![0xFF; 64];
        let b2 = a.canonical_bytes();
        assert_eq!(b1, b2);
    }

    #[test]
    fn kappa_deterministic() {
        let a = test_assertion("sha256:aaa", "sha256:bbb", "key/signing");
        let k1 = a.kappa();
        let k2 = a.kappa();
        assert_eq!(k1, k2);
        assert!(k1.starts_with("sha256:"));
    }

    #[test]
    fn different_values_different_kappas() {
        let a1 = test_assertion("sha256:aaa", "sha256:bbb", "key/signing");
        let mut a2 = a1.clone();
        a2.value = b"different-value".to_vec();
        assert_ne!(a1.kappa(), a2.kappa());
    }

    #[test]
    fn kappa_includes_signature() {
        let mut a1 = test_assertion("sha256:aaa", "sha256:bbb", "key/signing");
        let k1 = a1.kappa();
        a1.signature = vec![0xFF; 64];
        let k2 = a1.kappa();
        assert_ne!(k1, k2);
    }

    #[test]
    fn optional_fields_change_canonical() {
        let mut a = test_assertion("sha256:aaa", "sha256:bbb", "key/signing");
        let b1 = a.canonical_bytes();
        a.audience = Some("sha256:audience".to_owned());
        let b2 = a.canonical_bytes();
        assert_ne!(b1, b2);
    }
}
