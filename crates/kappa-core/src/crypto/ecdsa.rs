//! ECDSA (P-256, K-256) signing and verification.
//! Schnorr verifiers for FROST P-256 and K-256 threshold signatures.

use super::{CryptoError, Signer, Verifier};

// -- P-256 ECDSA -----------------------------------------------------------

pub struct P256Signer {
    signing_key: p256::ecdsa::SigningKey,
    public_key_bytes: Vec<u8>,
}

impl P256Signer {
    pub fn new(signing_key: p256::ecdsa::SigningKey) -> Self {
        let public_key_bytes = signing_key.verifying_key().to_sec1_bytes().to_vec();
        Self {
            signing_key,
            public_key_bytes,
        }
    }

    pub fn generate(rng: &mut (impl rand_core::CryptoRng + ?Sized)) -> Self {
        use p256::elliptic_curve::Generate;
        Self::new(
            p256::ecdsa::SigningKey::try_generate_from_rng(rng)
                .expect("ECDSA key generation from CryptoRng is infallible"),
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let key =
            p256::ecdsa::SigningKey::from_slice(bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self::new(key))
    }
}

impl Signer for P256Signer {
    fn algorithm(&self) -> &'static str {
        "p256"
    }
    fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use p256::ecdsa::signature::Signer as _;
        let sig: p256::ecdsa::Signature = self.signing_key.sign(message);
        let normalized = sig.normalize_s();
        Ok(normalized.to_der().as_bytes().to_vec())
    }
}

pub struct P256EcdsaVerifier;

impl Verifier for P256EcdsaVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        use p256::ecdsa::signature::Verifier as _;
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|_| CryptoError::InvalidKey)?;
        let sig = p256::ecdsa::Signature::from_der(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(vk.verify(message, &sig).is_ok())
    }
}

// -- K-256 (secp256k1) ECDSA -----------------------------------------------

pub struct K256Signer {
    signing_key: k256::ecdsa::SigningKey,
    public_key_bytes: Vec<u8>,
}

impl K256Signer {
    pub fn new(signing_key: k256::ecdsa::SigningKey) -> Self {
        let public_key_bytes = signing_key.verifying_key().to_sec1_bytes().to_vec();
        Self {
            signing_key,
            public_key_bytes,
        }
    }

    pub fn generate(rng: &mut (impl rand_core::CryptoRng + ?Sized)) -> Self {
        use k256::elliptic_curve::Generate;
        Self::new(
            k256::ecdsa::SigningKey::try_generate_from_rng(rng)
                .expect("ECDSA key generation from CryptoRng is infallible"),
        )
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let key =
            k256::ecdsa::SigningKey::from_slice(bytes).map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self::new(key))
    }
}

impl Signer for K256Signer {
    fn algorithm(&self) -> &'static str {
        "k256"
    }
    fn public_key(&self) -> &[u8] {
        &self.public_key_bytes
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use k256::ecdsa::signature::Signer as _;
        let sig: k256::ecdsa::Signature = self.signing_key.sign(message);
        let normalized = sig.normalize_s();
        Ok(normalized.to_der().as_bytes().to_vec())
    }
}

pub struct K256EcdsaVerifier;

impl Verifier for K256EcdsaVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        use k256::ecdsa::signature::Verifier as _;
        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|_| CryptoError::InvalidKey)?;
        let sig = k256::ecdsa::Signature::from_der(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(vk.verify(message, &sig).is_ok())
    }
}

// -- Schnorr verifiers for FROST -------------------------------------------

pub struct P256SchnorrVerifier;

impl Verifier for P256SchnorrVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let vk = frost_p256::VerifyingKey::deserialize(public_key)
            .map_err(|_| CryptoError::InvalidKey)?;
        let sig = frost_p256::Signature::deserialize(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(vk.verify(message, &sig).is_ok())
    }
}

pub struct K256SchnorrVerifier;

impl Verifier for K256SchnorrVerifier {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let vk = frost_secp256k1::VerifyingKey::deserialize(public_key)
            .map_err(|_| CryptoError::InvalidKey)?;
        let sig = frost_secp256k1::Signature::deserialize(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(vk.verify(message, &sig).is_ok())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
        rand_core::UnwrapErr(getrandom::SysRng)
    }

    #[test]
    fn p256_sign_verify() {
        let signer = P256Signer::generate(&mut test_rng());
        let sig = signer.sign(b"p256 test").unwrap();
        let v = P256EcdsaVerifier;
        assert!(v.verify(signer.public_key(), b"p256 test", &sig).unwrap());
    }

    #[test]
    fn p256_rejects_wrong_message() {
        let signer = P256Signer::generate(&mut test_rng());
        let sig = signer.sign(b"right").unwrap();
        let v = P256EcdsaVerifier;
        assert!(!v.verify(signer.public_key(), b"wrong", &sig).unwrap());
    }

    #[test]
    fn k256_sign_verify() {
        let signer = K256Signer::generate(&mut test_rng());
        let sig = signer.sign(b"k256 test").unwrap();
        let v = K256EcdsaVerifier;
        assert!(v.verify(signer.public_key(), b"k256 test", &sig).unwrap());
    }

    #[test]
    fn k256_rejects_wrong_message() {
        let signer = K256Signer::generate(&mut test_rng());
        let sig = signer.sign(b"right").unwrap();
        let v = K256EcdsaVerifier;
        assert!(!v.verify(signer.public_key(), b"wrong", &sig).unwrap());
    }

    #[test]
    fn p256_algorithm() {
        let s = P256Signer::generate(&mut test_rng());
        assert_eq!(s.algorithm(), "p256");
    }

    #[test]
    fn k256_algorithm() {
        let s = K256Signer::generate(&mut test_rng());
        assert_eq!(s.algorithm(), "k256");
    }

    #[test]
    fn p256_from_bytes_roundtrip() {
        let signer = P256Signer::generate(&mut test_rng());
        let pk = signer.public_key().to_vec();
        let sig = signer.sign(b"test").unwrap();
        let v = P256EcdsaVerifier;
        assert!(v.verify(&pk, b"test", &sig).unwrap());
    }

    #[test]
    fn k256_from_bytes_roundtrip() {
        let signer = K256Signer::generate(&mut test_rng());
        let pk = signer.public_key().to_vec();
        let sig = signer.sign(b"test").unwrap();
        let v = K256EcdsaVerifier;
        assert!(v.verify(&pk, b"test", &sig).unwrap());
    }
}
