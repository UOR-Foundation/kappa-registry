//! Cryptographic signing, verification, and threshold co-signing.

pub mod anchor;
pub mod ecdsa;
pub mod ed25519;
pub mod frost;
pub mod keystore;
pub mod kms;
pub mod prf;
pub mod vrf_trait;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("invalid key")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("deserialization failed: {0}")]
    Deserialization(String),
    #[error("key generation failed: {0}")]
    KeyGeneration(String),
    #[error("integrity check failed: {0}")]
    IntegrityFailure(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

/// Single-key signer. Implementations store their public key bytes
/// at construction time so public_key() is a zero-allocation borrow.
pub trait Signer: Send + Sync {
    fn algorithm(&self) -> &'static str;
    fn public_key(&self) -> &[u8];
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
}

/// Opaque FROST Round 1 precomputation state.
///
/// Holds serialized nonces (secret) and commitments (public).
/// Consumed by sign_share() -- each Round1State is used exactly
/// once, then destroyed (RFC 9591 section 4.1).
pub struct Round1State {
    pub nonces: Vec<u8>,
    pub commitments: Vec<u8>,
}

/// A participant's commitment from FROST Round 1.
pub struct Commitment {
    pub signer_id: Vec<u8>,
    pub data: Vec<u8>,
}

/// A participant's signature share from FROST Round 2.
pub struct SignatureShare {
    pub signer_id: Vec<u8>,
    pub data: Vec<u8>,
}

/// Per-signer threshold signing operations (FROST t-of-n).
/// Aggregation is performed by FrostEd25519Coordinator.
pub trait ThresholdSigner: Send + Sync {
    fn algorithm(&self) -> &'static str;
    fn group_public_key(&self) -> &[u8];
    fn precompute_round1(&mut self) -> Result<Round1State, CryptoError>;
    fn sign_share(
        &mut self,
        round1: Round1State,
        message: &[u8],
        commitments: &[Commitment],
    ) -> Result<SignatureShare, CryptoError>;
}

/// Signature verifier. Algorithm-dispatched via verifier_for().
pub trait Verifier: Send + Sync {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError>;
}

/// Get a verifier for the given algorithm.
pub fn verifier_for(algorithm: &str) -> Result<Box<dyn Verifier>, CryptoError> {
    match algorithm {
        "ed25519" | "frost-ed25519" => Ok(Box::new(ed25519::Ed25519Verifier)),
        "p256" => Ok(Box::new(ecdsa::P256EcdsaVerifier)),
        "k256" => Ok(Box::new(ecdsa::K256EcdsaVerifier)),
        "frost-p256" => Ok(Box::new(ecdsa::P256SchnorrVerifier)),
        "frost-secp256k1" => Ok(Box::new(ecdsa::K256SchnorrVerifier)),
        _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_dispatch_ed25519() {
        assert!(verifier_for("ed25519").is_ok());
    }

    #[test]
    fn verifier_dispatch_frost_ed25519() {
        assert!(verifier_for("frost-ed25519").is_ok());
    }

    #[test]
    fn verifier_dispatch_p256() {
        assert!(verifier_for("p256").is_ok());
    }

    #[test]
    fn verifier_dispatch_k256() {
        assert!(verifier_for("k256").is_ok());
    }

    #[test]
    fn verifier_dispatch_frost_p256() {
        assert!(verifier_for("frost-p256").is_ok());
    }

    #[test]
    fn verifier_dispatch_frost_secp256k1() {
        assert!(verifier_for("frost-secp256k1").is_ok());
    }

    #[test]
    fn verifier_dispatch_unknown_fails() {
        assert!(verifier_for("rsa-4096").is_err());
    }
}
