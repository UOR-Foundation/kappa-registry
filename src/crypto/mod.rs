//! Cryptographic signing and verification primitives.
//!
//! Provides trait-based signing (Ed25519, P-256, K-256) for namespace
//! root attestation, witness receipt signing, and future protocol
//! layer signature verification (Git GPG, atproto DID).
//!
//! No HTTP surface. Protocol layers decide what gets signed.

pub mod ecdsa;
pub mod ed25519;

use sha2::{Digest, Sha256};

pub const ALG_ED25519: &str = "ed25519";
pub const ALG_P256: &str = "p256";
pub const ALG_K256: &str = "k256";

#[derive(Debug)]
pub enum CryptoError {
    InvalidKey,
    InvalidSignature,
    UnsupportedAlgorithm(String),
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoError::InvalidKey => write!(f, "invalid key"),
            CryptoError::InvalidSignature => write!(f, "invalid signature"),
            CryptoError::UnsupportedAlgorithm(a) => {
                write!(f, "unsupported algorithm: {a}")
            }
        }
    }
}

impl std::error::Error for CryptoError {}

pub trait RegistrySigner: Send + Sync {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;
    fn public_key_bytes(&self) -> Vec<u8>;
    fn algorithm(&self) -> &str;
    fn key_id(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.algorithm().as_bytes());
        hasher.update(b":");
        hasher.update(self.public_key_bytes());
        let hash = hasher.finalize();
        hex::encode(&hash[..8])
    }
}

pub trait RegistryVerifier: Send + Sync {
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, CryptoError>;
    fn algorithm(&self) -> &str;
}

pub fn verifier_for(algorithm: &str) -> Result<Box<dyn RegistryVerifier>, CryptoError> {
    match algorithm {
        ALG_ED25519 => Ok(Box::new(ed25519::Ed25519Verifier)),
        ALG_P256 => Ok(Box::new(ecdsa::P256Verifier)),
        ALG_K256 => Ok(Box::new(ecdsa::K256Verifier)),
        _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

pub fn signer_from_bytes(
    algorithm: &str,
    private_key: &[u8],
) -> Result<Box<dyn RegistrySigner>, CryptoError> {
    match algorithm {
        ALG_ED25519 => Ok(Box::new(ed25519::Ed25519Signer::from_bytes(private_key)?)),
        ALG_P256 => Ok(Box::new(ecdsa::P256Signer::from_bytes(private_key)?)),
        ALG_K256 => Ok(Box::new(ecdsa::K256Signer::from_bytes(private_key)?)),
        _ => Err(CryptoError::UnsupportedAlgorithm(algorithm.to_string())),
    }
}

/// Signed namespace root statement. Produced by P10 + P11 together.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SignedRoot {
    pub namespace: String,
    pub root: String,
    pub timestamp: String,
    pub algorithm: String,
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "hex_bytes")]
    pub signature: Vec<u8>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "option_hex_bytes"
    )]
    pub attestation: Option<Vec<u8>>,
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

mod option_hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match bytes {
            Some(b) => s.serialize_str(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        let opt: Option<String> = Option::deserialize(d)?;
        match opt {
            Some(s) => hex::decode(&s).map(Some).map_err(serde::de::Error::custom),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_for_ed25519() {
        assert!(verifier_for(ALG_ED25519).is_ok());
    }

    #[test]
    fn verifier_for_p256() {
        assert!(verifier_for(ALG_P256).is_ok());
    }

    #[test]
    fn verifier_for_k256() {
        assert!(verifier_for(ALG_K256).is_ok());
    }

    #[test]
    fn verifier_for_unknown() {
        assert!(matches!(
            verifier_for("rsa"),
            Err(CryptoError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn key_id_is_deterministic() {
        let signer = ed25519::Ed25519Signer::generate();
        let id1 = signer.key_id();
        let id2 = signer.key_id();
        assert_eq!(id1, id2);
        assert_eq!(id1.len(), 16);
    }

    #[test]
    fn signer_from_bytes_dispatch() {
        // Ed25519 accepts any 32 bytes as a private key
        assert!(signer_from_bytes(ALG_ED25519, &[0u8; 32]).is_ok());
        // Wrong length rejected
        assert!(signer_from_bytes(ALG_ED25519, &[0u8; 16]).is_err());
        // Unknown algorithm rejected
        assert!(signer_from_bytes("rsa", &[0u8; 32]).is_err());
    }
}
