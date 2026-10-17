//! FIPS 204 ML-DSA-65 with seed-derived, zeroizing secret keys.

use ml_dsa::{EncodedVerifyingKey, Keypair, MlDsa65, Signature, SigningKey, VerifyingKey};

use crate::{CryptoError, Signer, Verifier};

pub struct MlDsa65Signer {
    key: SigningKey<MlDsa65>,
    public_key: Vec<u8>,
}

impl MlDsa65Signer {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let key = SigningKey::<MlDsa65>::from_seed(&(*seed).into());
        let public_key = key.verifying_key().encode().to_vec();
        Self { key, public_key }
    }
}

impl Signer for MlDsa65Signer {
    fn algorithm(&self) -> &'static str {
        "ml-dsa-65"
    }

    fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature: Signature<MlDsa65> = ::ml_dsa::Signer::try_sign(&self.key, message)
            .map_err(|error| CryptoError::SigningFailed {
                algorithm: self.algorithm().into(),
                reason: error.to_string(),
            })?;
        Ok(signature.encode().to_vec())
    }
}

pub struct MlDsa65Verifier;

impl Verifier for MlDsa65Verifier {
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<bool, CryptoError> {
        let encoded = EncodedVerifyingKey::<MlDsa65>::try_from(public_key).map_err(|_| {
            CryptoError::InvalidKey {
                reason: "ML-DSA-65 public key must be 1952 bytes".into(),
            }
        })?;
        let key = VerifyingKey::<MlDsa65>::decode(&encoded);
        let Ok(signature) = Signature::<MlDsa65>::try_from(signature) else {
            return Ok(false);
        };
        Ok(key.verify_with_context(message, &[], &signature))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_bind_message_and_key_and_reject_malformed_inputs() {
        let signer = MlDsa65Signer::from_seed(&[7; 32]);
        let other = MlDsa65Signer::from_seed(&[8; 32]);
        let signature = signer.sign(b"message").expect("ML-DSA signing");
        let verifier = MlDsa65Verifier;
        assert!(
            verifier
                .verify(signer.public_key(), b"message", &signature)
                .expect("valid key")
        );
        assert!(
            !verifier
                .verify(signer.public_key(), b"changed", &signature)
                .expect("valid key")
        );
        assert!(
            !verifier
                .verify(other.public_key(), b"message", &signature)
                .expect("valid key")
        );
        assert!(
            !verifier
                .verify(signer.public_key(), b"message", &[0; 64])
                .expect("valid key")
        );
        assert!(verifier.verify(&[0; 32], b"message", &signature).is_err());
    }
}
