//! Cryptographic signing and verification primitives.
//!
//! Provides trait-based signing (Ed25519, P-256, K-256) for namespace
//! root attestation, witness receipt signing, and future protocol
//! layer signature verification (Git GPG, atproto DID).
//!
//! No HTTP surface. Protocol layers decide what gets signed.

pub mod ecdsa;
pub mod ed25519;
pub mod keystore;

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

/// Generate a raw keypair for the given algorithm. Returns (private_key_bytes,
/// public_key_bytes). The private bytes are wrapped in Zeroizing to ensure
/// they are cleared from memory after use. The caller persists these bytes
/// to disk, then constructs a signer via `signer_from_bytes()`. The raw
/// bytes are never exposed through the signer type.
pub fn generate_raw_keypair(
    algorithm: &str,
) -> Result<(zeroize::Zeroizing<Vec<u8>>, Vec<u8>), CryptoError> {
    match algorithm {
        ALG_ED25519 => {
            use getrandom::rand_core::UnwrapErr;
            use getrandom::SysRng;
            let sk = ed25519_dalek::SigningKey::generate(&mut UnwrapErr(SysRng));
            let pk = sk.verifying_key().to_bytes().to_vec();
            let private = zeroize::Zeroizing::new(sk.to_bytes().to_vec());
            Ok((private, pk))
        }
        ALG_P256 => {
            use p256::elliptic_curve::Generate;
            let sk = p256::ecdsa::SigningKey::generate();
            let pk = sk.verifying_key().to_sec1_point(true).as_ref().to_vec();
            let private = zeroize::Zeroizing::new(sk.to_bytes().to_vec());
            Ok((private, pk))
        }
        ALG_K256 => {
            use p256::elliptic_curve::Generate;
            let sk = k256::ecdsa::SigningKey::generate();
            let pk = sk.verifying_key().to_sec1_point(true).as_ref().to_vec();
            let private = zeroize::Zeroizing::new(sk.to_bytes().to_vec());
            Ok((private, pk))
        }
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

    #[test]
    fn signed_root_serialization_roundtrip() {
        let sr = SignedRoot {
            namespace: "test/ns".to_string(),
            root: "sha256:abc123".to_string(),
            timestamp: "2026-07-23T00:00:00Z".to_string(),
            algorithm: ALG_ED25519.to_string(),
            public_key: vec![1, 2, 3],
            signature: vec![4, 5, 6],
            attestation: None,
        };
        let json = serde_json::to_string(&sr).unwrap();
        let parsed: SignedRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.namespace, sr.namespace);
        assert_eq!(parsed.root, sr.root);
        assert_eq!(parsed.timestamp, sr.timestamp);
        assert_eq!(parsed.algorithm, sr.algorithm);
        assert_eq!(parsed.public_key, sr.public_key);
        assert_eq!(parsed.signature, sr.signature);
        assert!(parsed.attestation.is_none());
    }

    #[test]
    fn signed_root_with_attestation_roundtrip() {
        let sr = SignedRoot {
            namespace: "test".to_string(),
            root: "sha256:def".to_string(),
            timestamp: "2026-07-23T12:00:00Z".to_string(),
            algorithm: ALG_P256.to_string(),
            public_key: vec![2, 3, 4],
            signature: vec![5, 6, 7],
            attestation: Some(vec![8, 9, 10]),
        };
        let json = serde_json::to_string(&sr).unwrap();
        let parsed: SignedRoot = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.attestation, Some(vec![8, 9, 10]));
    }

    #[test]
    fn p256_generate_persist_restore_roundtrip() {
        let (private, public) = generate_raw_keypair(ALG_P256).unwrap();
        let signer = signer_from_bytes(ALG_P256, &private).unwrap();
        let msg = b"p256 roundtrip test";
        let sig = signer.sign(msg).unwrap();
        assert_eq!(signer.public_key_bytes(), public);
        let verifier = ecdsa::P256Verifier;
        assert!(verifier.verify(msg, &sig, &public).unwrap());
    }

    #[test]
    fn k256_generate_persist_restore_roundtrip() {
        let (private, public) = generate_raw_keypair(ALG_K256).unwrap();
        let signer = signer_from_bytes(ALG_K256, &private).unwrap();
        let msg = b"k256 roundtrip test";
        let sig = signer.sign(msg).unwrap();
        assert_eq!(signer.public_key_bytes(), public);
        let verifier = ecdsa::K256Verifier;
        assert!(verifier.verify(msg, &sig, &public).unwrap());
    }

    #[test]
    fn ed25519_generate_persist_restore_roundtrip() {
        let (private, public) = generate_raw_keypair(ALG_ED25519).unwrap();
        let signer = signer_from_bytes(ALG_ED25519, &private).unwrap();
        let msg = b"ed25519 roundtrip test";
        let sig = signer.sign(msg).unwrap();
        assert_eq!(signer.public_key_bytes(), public);
        let verifier = ed25519::Ed25519Verifier;
        assert!(verifier.verify(msg, &sig, &public).unwrap());
    }
}
