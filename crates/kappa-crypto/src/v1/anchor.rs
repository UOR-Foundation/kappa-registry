use kappa_types::kappa::Kappa;

// -- Typed anchor newtypes with construction control --------------------------

/// This node's identity, derived from its signing key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NodeAnchor(Kappa);

impl NodeAnchor {
    pub fn from_key(algorithm: &str, public_key: &[u8]) -> Result<Self, super::CryptoError> {
        Ok(Self(Kappa::from_key(algorithm, public_key)?))
    }

    pub fn kappa(&self) -> &Kappa {
        &self.0
    }

    pub fn as_str(&self) -> String {
        self.0.format().as_str().to_string()
    }

    pub fn as_namespace(&self) -> String {
        self.as_str()
    }
}

impl std::fmt::Display for NodeAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Closed constructor. Only obtainable through `asserter_from_signature`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AsserterAnchor(Kappa);

impl AsserterAnchor {
    pub(crate) fn from_verified(
        algorithm: &str,
        public_key: &[u8],
    ) -> Result<Self, super::CryptoError> {
        Ok(Self(Kappa::from_key(algorithm, public_key)?))
    }

    pub fn kappa(&self) -> &Kappa {
        &self.0
    }

    pub fn as_str(&self) -> String {
        self.0.format().as_str().to_string()
    }
}

impl std::fmt::Display for AsserterAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Subject of an identity assertion. Freely constructible.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectAnchor(Kappa);

impl SubjectAnchor {
    pub fn new(kappa: Kappa) -> Self {
        Self(kappa)
    }

    pub fn from_key(algorithm: &str, public_key: &[u8]) -> Result<Self, super::CryptoError> {
        Ok(Self(Kappa::from_key(algorithm, public_key)?))
    }

    pub fn kappa(&self) -> &Kappa {
        &self.0
    }

    pub fn as_str(&self) -> String {
        self.0.format().as_str().to_string()
    }
}

impl std::fmt::Display for SubjectAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Compute an anchor string from algorithm and public key bytes.
///
/// Uses the authoritative `Kappa::from_key` derivation. Returns the
/// formatted kappa-label string.
pub fn anchor_from_key_str(
    algorithm: &str,
    public_key: &[u8],
) -> Result<String, super::CryptoError> {
    Ok(Kappa::from_key(algorithm, public_key)?
        .format()
        .as_str()
        .to_string())
}

/// Verify a signature against a public key, then return the signer's
/// identity kappa computed from (algorithm, public_key).
///
/// This is the ONLY path from "I have a signature" to "I know who
/// signed it." The verification MUST succeed before the identity
/// kappa is computed. There is no function that returns an identity
/// kappa from an unverified signature.
///
/// # Errors
///
/// Returns `CryptoError::UnsupportedAlgorithm` if the algorithm
/// string does not map to a known verifier.
///
/// Returns `CryptoError::InvalidSignature` if the signature does
/// not verify against the public key and message.
///
/// Returns `CryptoError::InvalidKey` if the public key bytes are
/// malformed for the algorithm.
/// Verify a signature and return typed evidence of the signer's
/// identity. The `AsserterAnchor` can only be obtained through this
/// path -- failed verification cannot produce it.
pub fn asserter_from_signature(
    algorithm: &str,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<AsserterAnchor, super::CryptoError> {
    let verifier = super::verifier_for(algorithm)?;
    match verifier.verify(public_key, message, signature)? {
        true => AsserterAnchor::from_verified(algorithm, public_key),
        false => Err(super::CryptoError::InvalidSignature),
    }
}

/// Verify a signature and return the raw `Kappa` content address of
/// the signer's identity. Use `asserter_from_signature` when typed
/// evidence is needed.
pub fn asserter_kappa_from_signature(
    algorithm: &str,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<Kappa, super::CryptoError> {
    let verifier = super::verifier_for(algorithm)?;
    match verifier.verify(public_key, message, signature)? {
        true => Ok(Kappa::from_key(algorithm, public_key)?),
        false => Err(super::CryptoError::InvalidSignature),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Signer;

    #[test]
    fn asserter_from_valid_signature() -> Result<(), crate::CryptoError> {
        let signer =
            crate::ed25519::Ed25519Signer::generate(&mut rand_core::UnwrapErr(getrandom::SysRng))?;
        let message = b"test message";
        let signature = signer.sign(message)?;
        let anchor = asserter_from_signature("ed25519", signer.public_key(), message, &signature)?;

        let expected = Kappa::from_key("ed25519", signer.public_key())?;
        assert_eq!(*anchor.kappa(), expected);
        Ok(())
    }

    #[test]
    fn asserter_from_invalid_signature_fails() -> Result<(), crate::CryptoError> {
        let signer =
            crate::ed25519::Ed25519Signer::generate(&mut rand_core::UnwrapErr(getrandom::SysRng))?;
        let result =
            asserter_from_signature("ed25519", signer.public_key(), b"message", &[0u8; 64]);
        assert!(matches!(result, Err(crate::CryptoError::InvalidSignature)));
        Ok(())
    }

    #[test]
    fn asserter_kappa_matches_typed_anchor() -> Result<(), crate::CryptoError> {
        let signer =
            crate::ed25519::Ed25519Signer::generate(&mut rand_core::UnwrapErr(getrandom::SysRng))?;
        let message = b"both paths agree";
        let signature = signer.sign(message)?;
        let anchor = asserter_from_signature("ed25519", signer.public_key(), message, &signature)?;
        let kappa =
            asserter_kappa_from_signature("ed25519", signer.public_key(), message, &signature)?;
        assert_eq!(*anchor.kappa(), kappa);
        Ok(())
    }

    #[test]
    fn asserter_from_wrong_algorithm_fails() {
        let result = asserter_from_signature("rsa-4096", &[0u8; 32], b"message", &[0u8; 64]);
        assert!(matches!(
            result,
            Err(crate::CryptoError::UnsupportedAlgorithm { .. })
        ));
    }

    #[test]
    fn kappa_from_key_is_deterministic() -> Result<(), crate::CryptoError> {
        let key = [42u8; 32];
        let a = Kappa::from_key("ed25519", &key)?;
        let b = Kappa::from_key("ed25519", &key)?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn kappa_from_key_differs_by_algorithm() -> Result<(), crate::CryptoError> {
        let key = [42u8; 32];
        let ed = Kappa::from_key("ed25519", &key)?;
        let p2 = Kappa::from_key("p256", &key)?;
        assert_ne!(ed, p2);
        Ok(())
    }

    #[test]
    fn kappa_from_key_differs_by_key() -> Result<(), crate::CryptoError> {
        let a = Kappa::from_key("ed25519", &[1u8; 32])?;
        let b = Kappa::from_key("ed25519", &[2u8; 32])?;
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn node_anchor_deterministic() -> Result<(), crate::CryptoError> {
        let a = NodeAnchor::from_key("ed25519", &[1u8; 32])?;
        let b = NodeAnchor::from_key("ed25519", &[1u8; 32])?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn different_keys_different_anchors() -> Result<(), crate::CryptoError> {
        let a = NodeAnchor::from_key("ed25519", &[1u8; 32])?;
        let b = NodeAnchor::from_key("ed25519", &[2u8; 32])?;
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn anchor_from_key_str_matches_node_anchor() -> Result<(), crate::CryptoError> {
        let s = anchor_from_key_str("ed25519", &[1u8; 32])?;
        let n = NodeAnchor::from_key("ed25519", &[1u8; 32])?;
        assert_eq!(s, n.as_str());
        Ok(())
    }

    #[test]
    fn subject_anchor_freely_constructible() {
        let s = SubjectAnchor::new(Kappa::sha256(b"user:alice"));
        assert!(s.as_str().starts_with("sha256:"));
    }
}
