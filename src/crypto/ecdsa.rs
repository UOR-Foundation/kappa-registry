use p256::elliptic_curve::Generate;

use super::{CryptoError, RegistrySigner, RegistryVerifier, ALG_K256, ALG_P256};

// -- P-256 (secp256r1 / prime256v1) --

pub struct P256Signer {
    key: p256::ecdsa::SigningKey,
}

impl P256Signer {
    pub fn from_bytes(private_key: &[u8]) -> Result<Self, CryptoError> {
        let key = p256::ecdsa::SigningKey::from_slice(private_key)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { key })
    }

    pub fn generate() -> Self {
        Self {
            key: p256::ecdsa::SigningKey::generate(),
        }
    }
}

impl RegistrySigner for P256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use p256::ecdsa::signature::Signer;
        let sig: p256::ecdsa::Signature = self.key.sign(message);
        let normalized = sig.normalize_s();
        Ok(normalized.to_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_sec1_point(true)
            .as_ref()
            .to_vec()
    }

    fn algorithm(&self) -> &str {
        ALG_P256
    }
}

pub struct P256Verifier;

impl RegistryVerifier for P256Verifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, CryptoError> {
        use p256::ecdsa::signature::Verifier;
        let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|_| CryptoError::InvalidKey)?;
        let sig = p256::ecdsa::Signature::from_slice(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(vk.verify(message, &sig).is_ok())
    }

    fn algorithm(&self) -> &str {
        ALG_P256
    }
}

// -- K-256 (secp256k1) --

pub struct K256Signer {
    key: k256::ecdsa::SigningKey,
}

impl K256Signer {
    pub fn from_bytes(private_key: &[u8]) -> Result<Self, CryptoError> {
        let key = k256::ecdsa::SigningKey::from_slice(private_key)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self { key })
    }

    pub fn generate() -> Self {
        Self {
            key: k256::ecdsa::SigningKey::generate(),
        }
    }
}

impl RegistrySigner for K256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        use k256::ecdsa::signature::Signer;
        let sig: k256::ecdsa::Signature = self.key.sign(message);
        let normalized = sig.normalize_s();
        Ok(normalized.to_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_sec1_point(true)
            .as_ref()
            .to_vec()
    }

    fn algorithm(&self) -> &str {
        ALG_K256
    }
}

pub struct K256Verifier;

impl RegistryVerifier for K256Verifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, CryptoError> {
        use k256::ecdsa::signature::Verifier;
        let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
            .map_err(|_| CryptoError::InvalidKey)?;
        let sig = k256::ecdsa::Signature::from_slice(signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(vk.verify(message, &sig).is_ok())
    }

    fn algorithm(&self) -> &str {
        ALG_K256
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{RegistrySigner, RegistryVerifier};

    #[test]
    fn p256_sign_verify_roundtrip() {
        let signer = P256Signer::generate();
        let msg = b"p256 test";
        let sig = signer.sign(msg).unwrap();
        let pubkey = signer.public_key_bytes();
        let verifier = P256Verifier;
        assert!(verifier.verify(msg, &sig, &pubkey).unwrap());
    }

    #[test]
    fn p256_verify_rejects_wrong_message() {
        let signer = P256Signer::generate();
        let sig = signer.sign(b"correct").unwrap();
        let pubkey = signer.public_key_bytes();
        assert!(!P256Verifier.verify(b"wrong", &sig, &pubkey).unwrap());
    }

    #[test]
    fn k256_sign_verify_roundtrip() {
        let signer = K256Signer::generate();
        let msg = b"k256 test";
        let sig = signer.sign(msg).unwrap();
        let pubkey = signer.public_key_bytes();
        let verifier = K256Verifier;
        assert!(verifier.verify(msg, &sig, &pubkey).unwrap());
    }

    #[test]
    fn k256_verify_rejects_wrong_key() {
        let s1 = K256Signer::generate();
        let s2 = K256Signer::generate();
        let msg = b"test";
        let sig = s1.sign(msg).unwrap();
        assert!(!K256Verifier
            .verify(msg, &sig, &s2.public_key_bytes())
            .unwrap());
    }

    #[test]
    fn cross_algorithm_verify_fails() {
        let ed_signer = crate::crypto::ed25519::Ed25519Signer::generate();
        let msg = b"cross-alg";
        let sig = ed_signer.sign(msg).unwrap();
        let pubkey = ed_signer.public_key_bytes();
        assert!(P256Verifier.verify(msg, &sig, &pubkey).is_err());
    }
}
