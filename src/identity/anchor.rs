//! Identity anchors -- immutable origin records and typed anchor newtypes.
//!
//! Three anchor newtypes enforce role separation at compile time:
//! - `NodeAnchor`: this process's own identity, derived from its signing key
//! - `AsserterAnchor`: verified signer of an assertion (no public constructor)
//! - `SubjectAnchor`: the party an assertion is about (freely constructible)
//!
//! `AsserterAnchor` having no public constructor is load-bearing: it makes
//! "forgot to verify the signature" a compile error. The only path to one
//! is `crypto::anchor::asserter_from_signature`.

use serde::{Deserialize, Serialize};

use crate::kappa::KappaLabel;

// ── Typed anchor newtypes ───────────────────────────────────────────

/// This process's own identity. Derived from the signing key.
/// Constructible only via `crypto::anchor::anchor_from_key`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeAnchor(String);

impl NodeAnchor {
    /// Create from a raw anchor string. Only called by `crypto::anchor`.
    pub(crate) fn from_raw(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Derive the namespace name for this node's own assertions.
    pub fn as_namespace(&self) -> String {
        self.0.clone()
    }
}

impl std::fmt::Display for NodeAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The party that signed an assertion. Constructible ONLY by successful
/// signature verification -- there is no `from_str`, no `From<String>`,
/// and no public constructor.
///
/// If you find yourself wanting another constructor, you are about to
/// skip verification.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AsserterAnchor(String);

impl AsserterAnchor {
    /// Create from a raw anchor string after signature verification.
    /// Only called by `crypto::anchor::asserter_from_signature`.
    pub(crate) fn from_verified(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Test-only constructor. Do not use outside of #[cfg(test)].
    #[cfg(test)]
    pub fn test_only(s: &str) -> Self {
        Self(s.to_owned())
    }
}

impl std::fmt::Display for AsserterAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The party an assertion is about. Freely constructible: you may
/// legitimately refer to a subject whose key you have never seen.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubjectAnchor(String);

impl SubjectAnchor {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for SubjectAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ── AnchorSpec (origin record) ──────────────────────────────────────

/// Specification for creating a new identity anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorSpec {
    /// CSPRNG entropy at origin (32 bytes).
    pub entropy: [u8; 32],
    /// SHA-256 of initial rotation key set (commitment, not the keys).
    /// The keys themselves arrive as assertion #1.
    pub key_commitment: Option<[u8; 32]>,
}

/// Canonical serialization of an anchor for kappa computation.
///
/// The anchor kappa is `sha256(canonical(axis, entropy, key_commitment))`.
/// This is deterministic: the same spec always produces the same anchor.
pub fn anchor_canonical_bytes(spec: &AnchorSpec) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(b"sha256:");
    buf.extend_from_slice(&spec.entropy);
    match &spec.key_commitment {
        Some(kc) => {
            buf.push(0x01);
            buf.extend_from_slice(kc);
        }
        None => {
            buf.push(0x00);
        }
    }
    buf
}

/// Compute the anchor kappa from a spec.
pub fn compute_anchor_kappa(spec: &AnchorSpec) -> String {
    let canonical = anchor_canonical_bytes(spec);
    KappaLabel::sha256(&canonical).as_str().to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn anchor_kappa_deterministic() {
        let spec = AnchorSpec {
            entropy: [42u8; 32],
            key_commitment: None,
        };
        let k1 = compute_anchor_kappa(&spec);
        let k2 = compute_anchor_kappa(&spec);
        assert_eq!(k1, k2);
        assert!(k1.starts_with("sha256:"));
    }

    #[test]
    fn different_entropy_different_kappa() {
        let s1 = AnchorSpec {
            entropy: [1u8; 32],
            key_commitment: None,
        };
        let s2 = AnchorSpec {
            entropy: [2u8; 32],
            key_commitment: None,
        };
        assert_ne!(compute_anchor_kappa(&s1), compute_anchor_kappa(&s2));
    }

    #[test]
    fn key_commitment_changes_kappa() {
        let without = AnchorSpec {
            entropy: [1u8; 32],
            key_commitment: None,
        };
        let with = AnchorSpec {
            entropy: [1u8; 32],
            key_commitment: Some([0xAA; 32]),
        };
        assert_ne!(compute_anchor_kappa(&without), compute_anchor_kappa(&with));
    }

    #[test]
    fn canonical_bytes_stable() {
        let spec = AnchorSpec {
            entropy: [0u8; 32],
            key_commitment: Some([0xFF; 32]),
        };
        let b1 = anchor_canonical_bytes(&spec);
        let b2 = anchor_canonical_bytes(&spec);
        assert_eq!(b1, b2);
    }

    #[test]
    fn node_anchor_as_namespace() {
        let a = NodeAnchor::from_raw("sha256:abc".to_owned());
        assert_eq!(a.as_namespace(), "sha256:abc");
        assert_eq!(a.as_str(), "sha256:abc");
    }

    #[test]
    fn subject_anchor_freely_constructible() {
        let s = SubjectAnchor::new("sha256:unknown_subject");
        assert_eq!(s.as_str(), "sha256:unknown_subject");
    }

    #[test]
    fn asserter_anchor_test_only_available_in_tests() {
        let a = AsserterAnchor::test_only("sha256:verified");
        assert_eq!(a.as_str(), "sha256:verified");
    }
}
