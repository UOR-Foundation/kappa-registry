//! Ed25519 signing and verification.
//!
//! Signing: x86-64 and aarch64 use aws-lc (precomputed-table
//! scalar-basepoint multiply). Other targets use ed25519-dalek.
//! Both produce deterministic signatures per RFC 8032.
//!
//! Verification: ed25519-dalek `verify_strict` on all targets.
//! aws-lc's `ED25519_verify` does not reject small-order public keys
//! or small-order R components; Dalek's `verify_strict` does.

use super::{CryptoError, Signer, Verifier};

/// Backend-specific error for Ed25519 operations.
enum Ed25519Error {
    InvalidKeyLength { got: usize, expected: usize },
    KeyDecodeFailed { reason: String },
    MalformedSignature { got: usize },
}

impl From<Ed25519Error> for CryptoError {
    fn from(e: Ed25519Error) -> Self {
        match e {
            Ed25519Error::InvalidKeyLength { got, expected } => CryptoError::InvalidKey {
                reason: format!("ed25519 key must be {expected} bytes, got {got}"),
            },
            Ed25519Error::KeyDecodeFailed { reason } => CryptoError::InvalidKey {
                reason: format!("ed25519 key decode: {reason}"),
            },
            Ed25519Error::MalformedSignature { got } => CryptoError::InvalidKey {
                reason: format!("ed25519 signature must be 64 bytes, got {got}"),
            },
        }
    }
}

// -- Signing backend (cfg-gated) ----------------------------------------------

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod sign_backend {
    use super::{CryptoError, Ed25519Error};

    pub struct SigningState {
        key_pair: aws_lc_rs::signature::Ed25519KeyPair,
        seed: zeroize::Zeroizing<[u8; 32]>,
        public_key_bytes: [u8; 32],
    }

    impl SigningState {
        pub fn from_seed(secret: &[u8; 32]) -> Result<Self, CryptoError> {
            let key_pair = aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(secret)
                .map_err(|e| Ed25519Error::KeyDecodeFailed {
                    reason: e.to_string(),
                })?;
            let mut public_key_bytes = [0u8; 32];
            public_key_bytes
                .copy_from_slice(aws_lc_rs::signature::KeyPair::public_key(&key_pair).as_ref());
            Ok(Self {
                key_pair,
                seed: zeroize::Zeroizing::new(*secret),
                public_key_bytes,
            })
        }

        pub fn public_key_bytes(&self) -> &[u8; 32] {
            &self.public_key_bytes
        }

        pub fn secret_key_bytes(&self) -> [u8; 32] {
            *self.seed
        }

        pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let sig = self
                .key_pair
                .try_sign(message)
                .map_err(|_| CryptoError::SigningFailed {
                    algorithm: "ed25519".into(),
                    reason: "aws-lc ed25519 signing failed".into(),
                })?;
            Ok(sig.as_ref().to_vec())
        }
    }
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
mod sign_backend {
    use ed25519_dalek::{Signer as DalekSigner, SigningKey};

    use super::{CryptoError, Ed25519Error};

    pub struct SigningState {
        signing_key: SigningKey,
        public_key_bytes: [u8; 32],
    }

    impl SigningState {
        pub fn from_seed(secret: &[u8; 32]) -> Result<Self, CryptoError> {
            let signing_key = SigningKey::from_bytes(secret);
            let public_key_bytes = signing_key.verifying_key().to_bytes();
            Ok(Self {
                signing_key,
                public_key_bytes,
            })
        }

        pub fn public_key_bytes(&self) -> &[u8; 32] {
            &self.public_key_bytes
        }

        pub fn secret_key_bytes(&self) -> [u8; 32] {
            self.signing_key.to_bytes()
        }

        pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
            let sig = self.signing_key.sign(message);
            Ok(sig.to_bytes().to_vec())
        }
    }
}

// -- Public signer ------------------------------------------------------------

pub struct Ed25519Signer {
    state: sign_backend::SigningState,
}

impl Ed25519Signer {
    /// Construct from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if the seed is rejected by the
    /// backend (e.g. all-zero seeds on some implementations).
    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self, CryptoError> {
        Ok(Self {
            state: sign_backend::SigningState::from_seed(secret)?,
        })
    }

    /// Generate a new key pair from the provided RNG.
    ///
    /// `fill_bytes` on a `CryptoRng` is infallible. The only failure
    /// mode is native key construction from the generated seed.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::KeyGeneration` if native key construction
    /// rejects the generated seed.
    pub fn generate(rng: &mut impl rand_core::CryptoRng) -> Result<Self, CryptoError> {
        let mut secret = zeroize::Zeroizing::new([0u8; 32]);
        rng.fill_bytes(secret.as_mut());
        Self::from_bytes(&secret).map_err(|e| CryptoError::KeyGeneration {
            algorithm: "ed25519".into(),
            reason: e.to_string(),
        })
    }

    /// The raw 32-byte seed. Caller is responsible for zeroizing.
    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.state.secret_key_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn algorithm(&self) -> &'static str {
        "ed25519"
    }

    fn public_key(&self) -> &[u8] {
        self.state.public_key_bytes()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.state.sign(message)
    }
}

// -- Verification (Dalek verify_strict on all targets) ------------------------

pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let pk_bytes: [u8; 32] =
            public_key
                .try_into()
                .map_err(|_| Ed25519Error::InvalidKeyLength {
                    got: public_key.len(),
                    expected: 32,
                })?;
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_bytes).map_err(|_| {
            Ed25519Error::KeyDecodeFailed {
                reason: "public key bytes do not encode a valid point".into(),
            }
        })?;
        let sig = ed25519_dalek::Signature::from_slice(signature).map_err(|_| {
            Ed25519Error::MalformedSignature {
                got: signature.len(),
            }
        })?;
        Ok(vk.verify_strict(message, &sig).is_ok())
    }
}

/// Dispatch provenance: which signing backend compiled this module.
pub const SIGNING_BACKEND: &str = if cfg!(any(target_arch = "x86_64", target_arch = "aarch64")) {
    "aws_lc"
} else {
    "ed25519_dalek"
};

#[cfg(test)]
mod tests {
    use super::*;

    fn rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
        rand_core::UnwrapErr(getrandom::SysRng)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let signer = Ed25519Signer::generate(&mut rng()).expect("generate");
        let message = b"test message";
        let signature = signer.sign(message).expect("sign must succeed");
        let verifier = Ed25519Verifier;
        let valid = verifier
            .verify(signer.public_key(), message, &signature)
            .expect("verify must succeed");
        assert!(valid);
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let signer = Ed25519Signer::generate(&mut rng()).expect("generate");
        let signature = signer.sign(b"original").expect("sign");
        let verifier = Ed25519Verifier;
        let valid = verifier
            .verify(signer.public_key(), b"tampered", &signature)
            .expect("verify must not error");
        assert!(!valid);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer_a = Ed25519Signer::generate(&mut rng()).expect("generate");
        let signer_b = Ed25519Signer::generate(&mut rng()).expect("generate");
        let signature = signer_a.sign(b"message").expect("sign");
        let verifier = Ed25519Verifier;
        let valid = verifier
            .verify(signer_b.public_key(), b"message", &signature)
            .expect("verify must not error");
        assert!(!valid);
    }

    #[test]
    fn verify_rejects_short_key() {
        let verifier = Ed25519Verifier;
        let result = verifier.verify(&[0u8; 16], b"msg", &[0u8; 64]);
        match result {
            Err(CryptoError::InvalidKey { reason }) => {
                assert!(reason.contains("32 bytes"), "reason: {reason}");
                assert!(reason.contains("16"), "reason: {reason}");
            }
            other => panic!("expected InvalidKey, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_short_signature() {
        let signer = Ed25519Signer::generate(&mut rng()).expect("generate");
        let verifier = Ed25519Verifier;
        let result = verifier.verify(signer.public_key(), b"msg", &[0u8; 32]);
        match result {
            Err(CryptoError::InvalidKey { reason }) => {
                assert!(reason.contains("64 bytes"), "reason: {reason}");
            }
            other => panic!("expected InvalidKey, got {other:?}"),
        }
    }

    #[test]
    fn from_bytes_roundtrip() {
        let signer = Ed25519Signer::generate(&mut rng()).expect("generate");
        let secret = signer.secret_key_bytes();
        let restored = Ed25519Signer::from_bytes(&secret).expect("from_bytes");
        assert_eq!(signer.public_key(), restored.public_key());
    }

    #[test]
    fn algorithm_is_ed25519() {
        let signer = Ed25519Signer::generate(&mut rng()).expect("generate");
        assert_eq!(signer.algorithm(), "ed25519");
    }

    /// Deterministic: same seed + same message = same signature.
    #[test]
    fn deterministic_signing() {
        let signer = Ed25519Signer::from_bytes(&[42; 32]).expect("from_bytes");
        let sig1 = signer.sign(b"deterministic").expect("sign");
        let sig2 = signer.sign(b"deterministic").expect("sign");
        assert_eq!(
            sig1, sig2,
            "Ed25519 signing must be deterministic per RFC 8032"
        );
    }
}
