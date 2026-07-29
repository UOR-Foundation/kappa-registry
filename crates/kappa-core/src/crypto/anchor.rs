//! Identity anchors -- typed newtypes with construction control.
//!
//! NodeAnchor: this process's identity, derived from its signing key.
//! AsserterAnchor: ONLY from signature verification (closed constructor).
//! SubjectAnchor: freely constructible, identifies assertion subjects.

use dcbor::prelude::*;

use crate::kappa::kappa_from_value;

/// dCBOR-encoded input to anchor derivation.
/// CBOR key assignments (PERMANENT):
///   0: algorithm, 1: public_key
#[derive(Clone, CBORCodable)]
struct AnchorInput {
    #[cbor(n = 0)]
    algorithm: String,
    #[cbor(n = 1)]
    public_key: Vec<u8>,
}

fn compute_anchor(algorithm: &str, public_key: &[u8]) -> String {
    let input = AnchorInput {
        algorithm: algorithm.to_string(),
        public_key: public_key.to_vec(),
    };
    kappa_from_value(&input)
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeAnchor(String);

impl NodeAnchor {
    pub fn from_key(algorithm: &str, public_key: &[u8]) -> Self {
        Self(compute_anchor(algorithm, public_key))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn as_namespace(&self) -> String {
        self.0.clone()
    }
}

impl std::fmt::Display for NodeAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Closed constructor. Only obtainable through asserter_from_signature().
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AsserterAnchor(String);

impl AsserterAnchor {
    pub(crate) fn from_verified(algorithm: &str, public_key: &[u8]) -> Self {
        Self(compute_anchor(algorithm, public_key))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AsserterAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectAnchor(String);

impl SubjectAnchor {
    pub fn new(value: String) -> Self {
        Self(value)
    }

    pub fn from_key(algorithm: &str, public_key: &[u8]) -> Self {
        Self(compute_anchor(algorithm, public_key))
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

/// Verify a signature and return the asserter anchor if valid.
pub fn asserter_from_signature(
    algorithm: &'static str,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<AsserterAnchor, super::CryptoError> {
    let verifier = super::verifier_for(algorithm)?;
    if verifier.verify(public_key, message, signature)? {
        Ok(AsserterAnchor::from_verified(algorithm, public_key))
    } else {
        Err(super::CryptoError::InvalidSignature)
    }
}

/// Compute an anchor string from algorithm and public key bytes.
pub fn anchor_from_key_str(algorithm: &str, public_key: &[u8]) -> String {
    compute_anchor(algorithm, public_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::Ed25519Signer;
    use crate::crypto::Signer;

    #[test]
    fn node_anchor_deterministic() {
        let a1 = NodeAnchor::from_key("ed25519", &[1u8; 32]);
        let a2 = NodeAnchor::from_key("ed25519", &[1u8; 32]);
        assert_eq!(a1, a2);
    }

    #[test]
    fn different_keys_different_anchors() {
        let a1 = NodeAnchor::from_key("ed25519", &[1u8; 32]);
        let a2 = NodeAnchor::from_key("ed25519", &[2u8; 32]);
        assert_ne!(a1, a2);
    }

    #[test]
    fn different_algorithms_different_anchors() {
        let a1 = NodeAnchor::from_key("ed25519", &[1u8; 32]);
        let a2 = NodeAnchor::from_key("p256", &[1u8; 32]);
        assert_ne!(a1, a2);
    }

    #[test]
    fn anchor_uses_kappa_label_format() {
        let a = NodeAnchor::from_key("ed25519", &[1u8; 32]);
        assert!(a.as_str().starts_with("sha256:"));
    }

    #[test]
    fn asserter_from_valid_signature() {
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let signer = Ed25519Signer::generate(&mut rng);
        let msg = b"prove identity";
        let sig = signer.sign(msg).unwrap();
        let asserter = asserter_from_signature(
            "ed25519", signer.public_key(), msg, &sig,
        ).unwrap();
        let expected = NodeAnchor::from_key("ed25519", signer.public_key());
        assert_eq!(asserter.as_str(), expected.as_str());
    }

    #[test]
    fn asserter_from_invalid_signature_fails() {
        let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
        let signer = Ed25519Signer::generate(&mut rng);
        let result = asserter_from_signature(
            "ed25519", signer.public_key(), b"msg", &[0u8; 64],
        );
        assert!(result.is_err());
    }

    #[test]
    fn subject_anchor_freely_constructible() {
        let s = SubjectAnchor::new("user:alice".into());
        assert_eq!(s.as_str(), "user:alice");
    }

    #[test]
    fn anchor_from_key_str_matches_node_anchor() {
        let s = anchor_from_key_str("ed25519", &[1u8; 32]);
        let n = NodeAnchor::from_key("ed25519", &[1u8; 32]);
        assert_eq!(s, n.as_str());
    }
}
