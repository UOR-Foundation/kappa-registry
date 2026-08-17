//! Ed25519 signing and verification (RFC 8032).
//!
//! FROST Ed25519 produces standard Ed25519 signatures, so
//! Ed25519Verifier handles both single-signer and threshold cases.

use ed25519_dalek::{Signer as DalekSigner, SigningKey, VerifyingKey};

use super::{CryptoError, Signer, Verifier};

pub struct Ed25519Signer {
    signing_key: SigningKey,
    public_key_bytes: [u8; 32],
}

impl Ed25519Signer {
    pub fn new(signing_key: SigningKey) -> Self {
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        Self {
            signing_key,
            public_key_bytes,
        }
    }

    pub fn from_bytes(secret: &[u8; 32]) -> Self {
        Self::new(SigningKey::from_bytes(secret))
    }

    pub fn generate(rng: &mut impl rand_core::CryptoRng) -> Self {
        Self::new(SigningKey::generate(rng))
    }

    pub fn secret_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

impl Signer for Ed25519Signer {
    fn algorithm(&self) -> &'static str {
        "ed25519"
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig = self.signing_key.sign(message);
        Ok(sig.to_bytes().to_vec())
    }
}

pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let pk_bytes: [u8; 32] = public_key.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let vk = VerifyingKey::from_bytes(&pk_bytes).map_err(|_| CryptoError::InvalidKey)?;
        let sig = ed25519_dalek::Signature::from_slice(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(vk.verify_strict(message, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
        rand_core::UnwrapErr(getrandom::SysRng)
    }

    #[test]
    fn sign_verify_roundtrip() {
        let signer = Ed25519Signer::generate(&mut test_rng());
        let msg = b"test message";
        let sig = signer.sign(msg).unwrap();
        let verifier = Ed25519Verifier;
        assert!(verifier.verify(signer.public_key(), msg, &sig).unwrap());
    }

    #[test]
    fn rejects_wrong_message() {
        let signer = Ed25519Signer::generate(&mut test_rng());
        let sig = signer.sign(b"correct").unwrap();
        let verifier = Ed25519Verifier;
        assert!(!verifier
            .verify(signer.public_key(), b"wrong", &sig)
            .unwrap());
    }

    #[test]
    fn rejects_wrong_key() {
        let s1 = Ed25519Signer::generate(&mut test_rng());
        let s2 = Ed25519Signer::generate(&mut test_rng());
        let sig = s1.sign(b"msg").unwrap();
        let verifier = Ed25519Verifier;
        assert!(!verifier.verify(s2.public_key(), b"msg", &sig).unwrap());
    }

    #[test]
    fn from_bytes_roundtrip() {
        let signer = Ed25519Signer::generate(&mut test_rng());
        let secret = signer.secret_key_bytes();
        let restored = Ed25519Signer::from_bytes(&secret);
        assert_eq!(signer.public_key(), restored.public_key());
    }

    #[test]
    fn deterministic_signatures() {
        let signer = Ed25519Signer::from_bytes(&[42u8; 32]);
        let s1 = signer.sign(b"determinism").unwrap();
        let s2 = signer.sign(b"determinism").unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn public_key_is_32_bytes() {
        let signer = Ed25519Signer::generate(&mut test_rng());
        assert_eq!(signer.public_key().len(), 32);
    }

    #[test]
    fn signature_is_64_bytes() {
        let signer = Ed25519Signer::generate(&mut test_rng());
        assert_eq!(signer.sign(b"x").unwrap().len(), 64);
    }

    #[test]
    fn rejects_short_key() {
        let v = Ed25519Verifier;
        assert!(matches!(
            v.verify(&[0u8; 16], b"m", &[0u8; 64]),
            Err(CryptoError::InvalidKey)
        ));
    }

    #[test]
    fn rejects_short_signature() {
        let signer = Ed25519Signer::generate(&mut test_rng());
        let v = Ed25519Verifier;
        assert!(matches!(
            v.verify(signer.public_key(), b"m", &[0u8; 32]),
            Err(CryptoError::InvalidSignature)
        ));
    }
}
