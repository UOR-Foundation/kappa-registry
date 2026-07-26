//! Identity anchor -- immutable genesis record.
//!
//! The anchor IS the identity. It is minimal, immutable, and permanent.
//! Nothing about a subject lives here. It has no attributes. Kind is a
//! query result over the assertion graph, not a stored field.

use serde::{Deserialize, Serialize};

use crate::kappa::KappaLabel;

/// Specification for creating a new identity anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorSpec {
    /// CSPRNG entropy at genesis (32 bytes).
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
    // Canonical form: CBOR-like deterministic encoding.
    // For now, use a simple concatenation with length prefixes.
    // This MUST be frozen before any anchor is created in production.
    let mut buf = Vec::with_capacity(128);
    // axis = sha256 (always, for anchors)
    buf.extend_from_slice(b"sha256:");
    // entropy
    buf.extend_from_slice(&spec.entropy);
    // key_commitment (32 bytes or absent)
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
}
