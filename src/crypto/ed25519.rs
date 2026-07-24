use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use getrandom::rand_core::UnwrapErr;
use getrandom::SysRng;

use super::{CryptoError, RegistrySigner, RegistryVerifier, ALG_ED25519};

pub struct Ed25519Signer {
    key: SigningKey,
}

impl Ed25519Signer {
    pub fn from_bytes(private_key: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; 32] = private_key
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            key: SigningKey::from_bytes(&bytes),
        })
    }

    pub fn generate() -> Self {
        let mut csprng = UnwrapErr(SysRng);
        Self {
            key: SigningKey::generate(&mut csprng),
        }
    }
}

impl RegistrySigner for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        Ok(self.key.sign(message).to_bytes().to_vec())
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.key.verifying_key().to_bytes().to_vec()
    }

    fn algorithm(&self) -> &str {
        ALG_ED25519
    }
}

pub struct Ed25519Verifier;

impl RegistryVerifier for Ed25519Verifier {
    fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> Result<bool, CryptoError> {
        let vk_bytes: [u8; 32] = public_key.try_into().map_err(|_| CryptoError::InvalidKey)?;
        let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| CryptoError::InvalidKey)?;
        let sig_bytes: [u8; 64] = signature
            .try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let sig = Signature::from_bytes(&sig_bytes);
        Ok(vk.verify(message, &sig).is_ok())
    }

    fn algorithm(&self) -> &str {
        ALG_ED25519
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip() {
        let signer = Ed25519Signer::generate();
        let msg = b"test message";
        let sig = signer.sign(msg).unwrap();
        let pubkey = signer.public_key_bytes();
        let verifier = Ed25519Verifier;
        assert!(verifier.verify(msg, &sig, &pubkey).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let signer = Ed25519Signer::generate();
        let sig = signer.sign(b"correct").unwrap();
        let pubkey = signer.public_key_bytes();
        let verifier = Ed25519Verifier;
        assert!(!verifier.verify(b"wrong", &sig, &pubkey).unwrap());
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signer1 = Ed25519Signer::generate();
        let signer2 = Ed25519Signer::generate();
        let msg = b"test";
        let sig = signer1.sign(msg).unwrap();
        let wrong_pubkey = signer2.public_key_bytes();
        let verifier = Ed25519Verifier;
        assert!(!verifier.verify(msg, &sig, &wrong_pubkey).unwrap());
    }

    #[test]
    fn from_bytes_roundtrip() {
        let signer = Ed25519Signer::generate();
        let key_bytes = signer.key.to_bytes();
        let restored = Ed25519Signer::from_bytes(&key_bytes).unwrap();
        assert_eq!(signer.public_key_bytes(), restored.public_key_bytes());
    }

    #[test]
    fn from_bytes_invalid_length() {
        assert!(Ed25519Signer::from_bytes(&[0u8; 16]).is_err());
    }
}
