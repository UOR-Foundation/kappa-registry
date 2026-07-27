//! Asserter resolution from cryptographic signatures.
//!
//! D-1: asserter identity is derived from the signature, not from auth.
//! Authentication is "which key signed this." Authorization is "may this
//! key write here." This module handles the first; auth/policy.rs handles
//! the second.
//!
//! `asserter_from_signature` returns `AsserterAnchor` -- the ONLY
//! constructor for that type. If you find yourself wanting another
//! path to an `AsserterAnchor`, you are about to skip verification.

use super::{verifier_for, CryptoError};
use crate::identity::anchor::{AsserterAnchor, NodeAnchor};
use crate::kappa::KappaLabel;

/// Length-prefixed so ("ed25519", key) and ("ed2551", [0x39] + key)
/// cannot collide. Do not change without a format version bump.
///
/// Format: u16(algorithm.len) BE + algorithm + u16(public_key.len) BE + public_key
pub fn canonical_anchor_from_key(algorithm: &str, public_key: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + algorithm.len() + public_key.len());
    buf.extend_from_slice(&(algorithm.len() as u16).to_be_bytes());
    buf.extend_from_slice(algorithm.as_bytes());
    buf.extend_from_slice(&(public_key.len() as u16).to_be_bytes());
    buf.extend_from_slice(public_key);
    buf
}

fn compute_anchor_string(algorithm: &str, public_key: &[u8]) -> String {
    let canonical = canonical_anchor_from_key(algorithm, public_key);
    KappaLabel::sha256(&canonical).as_str().to_owned()
}

/// Verify a signature and derive the asserter anchor from the signing
/// public key. This is the ONLY constructor for `AsserterAnchor`.
///
/// # Errors
///
/// Returns `CryptoError::InvalidSignature` if the signature does not
/// verify against the provided public key.
/// Returns `CryptoError::UnsupportedAlgorithm` if the algorithm is
/// not recognized.
#[must_use = "discarding a verification result is a security bug"]
pub fn asserter_from_signature(
    algorithm: &str,
    public_key: &[u8],
    message: &[u8],
    sig: &[u8],
) -> Result<AsserterAnchor, CryptoError> {
    let v = verifier_for(algorithm)?;
    if !v.verify(message, sig, public_key)? {
        return Err(CryptoError::InvalidSignature);
    }
    Ok(AsserterAnchor::from_verified(compute_anchor_string(
        algorithm, public_key,
    )))
}

/// Derive the anchor from a public key without signature verification.
/// Used when the key is already trusted (loaded from the local keystore).
///
/// Returns `NodeAnchor` -- this process's own identity.
pub fn anchor_from_key(algorithm: &str, public_key: &[u8]) -> NodeAnchor {
    NodeAnchor::from_raw(compute_anchor_string(algorithm, public_key))
}

/// Derive an anchor string from a public key. Returns a raw String
/// for use in contexts where the caller manages its own type safety
/// (e.g., `registry_anchor` in handlers, which passes the result as
/// `&str` to `authorize`).
pub fn anchor_from_key_str(algorithm: &str, public_key: &[u8]) -> String {
    compute_anchor_string(algorithm, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::Ed25519Signer;
    use crate::crypto::RegistrySigner;

    #[test]
    fn anchor_from_key_deterministic() {
        let signer = Ed25519Signer::generate();
        let pk = signer.public_key_bytes();
        let a1 = anchor_from_key("ed25519", &pk);
        let a2 = anchor_from_key("ed25519", &pk);
        assert_eq!(a1, a2);
        assert!(a1.as_str().starts_with("sha256:"));
        assert_eq!(a1.as_str().len(), 71);
    }

    #[test]
    fn asserter_from_valid_signature() {
        let signer = Ed25519Signer::generate();
        let pk = signer.public_key_bytes();
        let msg = b"test message";
        let sig = signer.sign(msg).unwrap();
        let asserter = asserter_from_signature("ed25519", &pk, msg, &sig).unwrap();
        let expected = anchor_from_key("ed25519", &pk);
        assert_eq!(asserter.as_str(), expected.as_str());
    }

    #[test]
    fn asserter_from_invalid_signature() {
        let signer = Ed25519Signer::generate();
        let pk = signer.public_key_bytes();
        let msg = b"test message";
        let bad_sig = vec![0u8; 64];
        let result = asserter_from_signature("ed25519", &pk, msg, &bad_sig);
        assert!(result.is_err());
    }

    #[test]
    fn different_keys_different_anchors() {
        let s1 = Ed25519Signer::generate();
        let s2 = Ed25519Signer::generate();
        let a1 = anchor_from_key("ed25519", &s1.public_key_bytes());
        let a2 = anchor_from_key("ed25519", &s2.public_key_bytes());
        assert_ne!(a1, a2);
    }

    #[test]
    fn length_prefix_prevents_injection() {
        let key = [0xAA; 32];
        let c1 = canonical_anchor_from_key("ed25519", &key);
        let mut injected_key = vec![0x39u8];
        injected_key.extend_from_slice(&key);
        let c2 = canonical_anchor_from_key("ed2551", &injected_key);
        assert_ne!(c1, c2);
    }

    #[test]
    fn anchor_from_key_str_matches_typed() {
        let signer = Ed25519Signer::generate();
        let pk = signer.public_key_bytes();
        let typed = anchor_from_key("ed25519", &pk);
        let raw = anchor_from_key_str("ed25519", &pk);
        assert_eq!(typed.as_str(), raw.as_str());
    }
}
