use std::fs;
use std::io;
use std::path::Path;

use super::CryptoError;

/// Backend-specific errors for PRF key operations.
enum PrfError {
    IntegrityHashMissing,
    IntegrityMismatch,
    PublicKeyMissing,
    SecretLengthInvalid { got: usize },
    NonceGeneration { reason: String },
}

impl From<PrfError> for CryptoError {
    fn from(e: PrfError) -> Self {
        match e {
            PrfError::IntegrityHashMissing => CryptoError::IntegrityFailure {
                path: "prf.blake3".into(),
                reason: "integrity hash file missing".into(),
            },
            PrfError::IntegrityMismatch => CryptoError::IntegrityFailure {
                path: "prf.key".into(),
                reason: "BLAKE3 hash does not match stored integrity hash".into(),
            },
            PrfError::PublicKeyMissing => CryptoError::InvalidKey {
                reason: "prf.pub file missing".into(),
            },
            PrfError::SecretLengthInvalid { got } => CryptoError::InvalidKey {
                reason: format!("PRF secret must be 32 bytes, got {}", got),
            },
            PrfError::NonceGeneration { reason } => CryptoError::KeyGeneration {
                algorithm: "blake3-prf".into(),
                reason,
            },
        }
    }
}

/// BLAKE3-based pseudorandom function key material.
///
/// Used for audience-derived labels and other deterministic
/// derivations where the output must be unpredictable without
/// the secret but reproducible with it.
pub struct PrfKeyMaterial {
    secret: [u8; 32],
    public: [u8; 32],
}

impl PrfKeyMaterial {
    /// Load existing PRF key material from disk, or generate new
    /// material and persist it. BLAKE3 integrity hash verified on load.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::IntegrityFailure` if the stored key's
    /// BLAKE3 hash does not match the integrity file.
    ///
    /// Returns `CryptoError::InvalidKey` if the key file exists but
    /// has wrong length or the public key file is missing.
    ///
    /// Returns `CryptoError::KeyGeneration` if the CSPRNG fails.
    pub fn load_or_generate(keys_dir: &Path) -> Result<Self, CryptoError> {
        let secret_path = keys_dir.join("prf.key");
        let public_path = keys_dir.join("prf.pub");
        let hash_path = keys_dir.join("prf.blake3");

        if secret_path.exists() {
            let secret_bytes = fs::read(&secret_path)?;
            let stored_hash = fs::read_to_string(&hash_path).map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    CryptoError::from(PrfError::IntegrityHashMissing)
                } else {
                    CryptoError::Io(e)
                }
            })?;
            let computed = blake3::hash(&secret_bytes);
            if computed.to_hex().as_str() != stored_hash.trim() {
                return Err(PrfError::IntegrityMismatch.into());
            }
            let secret: [u8; 32] = secret_bytes
                .try_into()
                .map_err(|v: Vec<u8>| PrfError::SecretLengthInvalid { got: v.len() })?;
            let public_bytes = fs::read(&public_path).map_err(|e| {
                if e.kind() == io::ErrorKind::NotFound {
                    CryptoError::from(PrfError::PublicKeyMissing)
                } else {
                    CryptoError::Io(e)
                }
            })?;
            let public: [u8; 32] = public_bytes
                .try_into()
                .map_err(|v: Vec<u8>| PrfError::SecretLengthInvalid { got: v.len() })?;
            return Ok(Self { secret, public });
        }

        fs::create_dir_all(keys_dir)?;
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|e| PrfError::NonceGeneration {
            reason: e.to_string(),
        })?;
        let public = blake3::derive_key("kappa-registry prf public", &secret);
        let hash = blake3::hash(&secret);
        fs::write(&secret_path, secret)?;
        fs::write(&public_path, public)?;
        fs::write(&hash_path, hash.to_hex().as_str())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))?;
        }

        Ok(Self { secret, public })
    }

    /// The public component. Safe to share. Used for verification
    /// that a PRF output was produced by the holder of this key.
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }

    /// Evaluate the PRF on an input. Deterministic: same input
    /// always produces the same 32-byte output. Unpredictable
    /// without the secret.
    pub fn evaluate(&self, input: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_keyed(&self.secret);
        hasher.update(input);
        *hasher.finalize().as_bytes()
    }
}

impl Drop for PrfKeyMaterial {
    fn drop(&mut self) {
        self.secret = [0u8; 32];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_then_load_produces_same_output() {
        let dir = tempfile::tempdir().expect("tempdir");
        let first = PrfKeyMaterial::load_or_generate(dir.path()).expect("generate");
        let second = PrfKeyMaterial::load_or_generate(dir.path()).expect("load");
        assert_eq!(first.public(), second.public());
        assert_eq!(
            first.evaluate(b"test input"),
            second.evaluate(b"test input"),
        );
    }

    #[test]
    fn evaluate_is_deterministic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prf = PrfKeyMaterial::load_or_generate(dir.path()).expect("generate");
        let a = prf.evaluate(b"same input");
        let b = prf.evaluate(b"same input");
        assert_eq!(a, b);
    }

    #[test]
    fn different_inputs_produce_different_outputs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prf = PrfKeyMaterial::load_or_generate(dir.path()).expect("generate");
        let a = prf.evaluate(b"input one");
        let b = prf.evaluate(b"input two");
        assert_ne!(a, b);
    }

    #[test]
    fn integrity_check_detects_tampering() {
        let dir = tempfile::tempdir().expect("tempdir");
        PrfKeyMaterial::load_or_generate(dir.path()).expect("generate");
        fs::write(dir.path().join("prf.key"), [0u8; 32]).expect("tamper");
        let result = PrfKeyMaterial::load_or_generate(dir.path());
        assert!(matches!(result, Err(CryptoError::IntegrityFailure { .. })));
    }

    #[test]
    fn missing_integrity_hash_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        PrfKeyMaterial::load_or_generate(dir.path()).expect("generate");
        fs::remove_file(dir.path().join("prf.blake3")).expect("remove hash");
        let result = PrfKeyMaterial::load_or_generate(dir.path());
        assert!(matches!(result, Err(CryptoError::IntegrityFailure { .. })));
    }

    #[test]
    fn wrong_length_secret_fails() {
        let dir = tempfile::tempdir().expect("tempdir");
        PrfKeyMaterial::load_or_generate(dir.path()).expect("generate");
        let short = [0u8; 16];
        let hash = blake3::hash(&short);
        fs::write(dir.path().join("prf.key"), short).expect("write short");
        fs::write(dir.path().join("prf.blake3"), hash.to_hex().as_str()).expect("write hash");
        let result = PrfKeyMaterial::load_or_generate(dir.path());
        assert!(matches!(result, Err(CryptoError::InvalidKey { .. })));
    }

    #[cfg(unix)]
    #[test]
    fn secret_file_permissions_restricted() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        PrfKeyMaterial::load_or_generate(dir.path()).expect("generate");
        let mode = fs::metadata(dir.path().join("prf.key"))
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "prf.key should be owner-only: {:o}",
            mode
        );
    }
}
