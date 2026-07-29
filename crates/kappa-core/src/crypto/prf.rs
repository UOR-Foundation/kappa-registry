//! BLAKE3 keyed PRF for audience-label derivation.
//!
//! This is a pseudorandom function (keyed hash), not a verifiable
//! random function. It produces deterministic output from (key, input)
//! but cannot produce a proof verifiable by third parties. For
//! verifiable randomness (quorum selection, leader election), see
//! the Vrf trait in vrf_trait.rs.

use std::path::Path;

use super::CryptoError;

/// PRF key material stored on the filesystem with BLAKE3 integrity.
pub struct PrfKeyMaterial {
    secret: Vec<u8>,
    public: Vec<u8>,
}

impl PrfKeyMaterial {
    /// Load existing PRF key material or generate new.
    pub fn load_or_generate(keys_dir: &Path) -> Result<Self, CryptoError> {
        let secret_path = keys_dir.join("prf.key");
        let public_path = keys_dir.join("prf.pub");
        let hash_path = keys_dir.join("prf.blake3");

        if secret_path.exists() {
            let secret = std::fs::read(&secret_path)?;
            let stored_hash = std::fs::read_to_string(&hash_path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    CryptoError::IntegrityFailure("missing PRF integrity hash".into())
                } else {
                    CryptoError::Io(e)
                }
            })?;
            let computed = blake3::hash(&secret);
            if computed.to_hex().as_str() != stored_hash.trim() {
                return Err(CryptoError::IntegrityFailure(
                    "PRF key integrity check failed".into(),
                ));
            }
            let public = std::fs::read(&public_path).map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    CryptoError::InvalidKey
                } else {
                    CryptoError::Io(e)
                }
            })?;
            return Ok(Self { secret, public });
        }

        std::fs::create_dir_all(keys_dir)?;

        let mut secret = vec![0u8; 32];
        getrandom::fill(&mut secret)
            .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;

        let public = blake3::derive_key("kappa-registry prf public", &secret).to_vec();
        let hash = blake3::hash(&secret);

        std::fs::write(&secret_path, &secret)?;
        std::fs::write(&public_path, &public)?;
        std::fs::write(&hash_path, hash.to_hex().as_str())?;

        Ok(Self { secret, public })
    }

    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// Evaluate the PRF: deterministic keyed hash of input.
    pub fn prf_evaluate(&self, input: &[u8]) -> [u8; 32] {
        let key: [u8; 32] = self.secret[..32]
            .try_into()
            .expect("PRF secret is always 32 bytes");
        let mut hasher = blake3::Hasher::new_keyed(&key);
        hasher.update(input);
        *hasher.finalize().as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_or_generate_creates() {
        let dir = tempfile::tempdir().unwrap();
        let prf = PrfKeyMaterial::load_or_generate(dir.path()).unwrap();
        assert_eq!(prf.secret().len(), 32);
        assert_eq!(prf.public().len(), 32);
    }

    #[test]
    fn load_or_generate_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = PrfKeyMaterial::load_or_generate(dir.path()).unwrap();
        let p2 = PrfKeyMaterial::load_or_generate(dir.path()).unwrap();
        assert_eq!(p1.secret(), p2.secret());
        assert_eq!(p1.public(), p2.public());
    }

    #[test]
    fn evaluate_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let prf = PrfKeyMaterial::load_or_generate(dir.path()).unwrap();
        assert_eq!(prf.prf_evaluate(b"test"), prf.prf_evaluate(b"test"));
    }

    #[test]
    fn evaluate_different_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let prf = PrfKeyMaterial::load_or_generate(dir.path()).unwrap();
        assert_ne!(prf.prf_evaluate(b"a"), prf.prf_evaluate(b"b"));
    }

    #[test]
    fn tampered_key_rejected() {
        let dir = tempfile::tempdir().unwrap();
        PrfKeyMaterial::load_or_generate(dir.path()).unwrap();
        std::fs::write(dir.path().join("prf.key"), [0xffu8; 32]).unwrap();
        assert!(matches!(
            PrfKeyMaterial::load_or_generate(dir.path()),
            Err(CryptoError::IntegrityFailure(_))
        ));
    }
}
