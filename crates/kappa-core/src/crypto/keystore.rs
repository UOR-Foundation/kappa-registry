//! BLAKE3 integrity-checked key storage on the filesystem.
//!
//! Keys are stored as files alongside their BLAKE3 hashes. On load,
//! the hash is recomputed and compared. A mismatch means the key file
//! was corrupted or tampered with -- the keystore refuses to load it.

use std::path::{Path, PathBuf};

use super::{CryptoError, Signer};

pub struct KeyStore {
    keys_dir: PathBuf,
}

impl KeyStore {
    pub fn new(keys_dir: PathBuf) -> Result<Self, CryptoError> {
        std::fs::create_dir_all(&keys_dir)?;
        Ok(Self { keys_dir })
    }

    pub fn keys_dir(&self) -> &Path {
        &self.keys_dir
    }

    /// Store a key with BLAKE3 integrity hash.
    ///
    /// Writes three files:
    ///   {name}.key     -- the raw key bytes
    ///   {name}.blake3  -- the BLAKE3 hash of the key bytes (hex)
    ///   {name}.pub     -- the public key bytes (if provided)
    pub fn store(
        &self,
        name: &str,
        secret_bytes: &[u8],
        public_bytes: Option<&[u8]>,
        algorithm: &str,
    ) -> Result<(), CryptoError> {
        let key_path = self.keys_dir.join(format!("{}.key", name));
        let hash_path = self.keys_dir.join(format!("{}.blake3", name));
        let algo_path = self.keys_dir.join(format!("{}.algorithm", name));

        let hash = blake3::hash(secret_bytes);

        std::fs::write(&key_path, secret_bytes)?;
        std::fs::write(&hash_path, hash.to_hex().as_str())?;
        std::fs::write(&algo_path, algorithm)?;

        if let Some(pub_bytes) = public_bytes {
            let pub_path = self.keys_dir.join(format!("{}.pub", name));
            std::fs::write(&pub_path, pub_bytes)?;
        }

        Ok(())
    }

    /// Load a key, verifying BLAKE3 integrity.
    ///
    /// Returns (secret_bytes, algorithm). Fails with IntegrityFailure
    /// if the hash does not match.
    pub fn load(&self, name: &str) -> Result<(Vec<u8>, String), CryptoError> {
        let key_path = self.keys_dir.join(format!("{}.key", name));
        let hash_path = self.keys_dir.join(format!("{}.blake3", name));
        let algo_path = self.keys_dir.join(format!("{}.algorithm", name));

        let secret_bytes = std::fs::read(&key_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CryptoError::InvalidKey
            } else {
                CryptoError::Io(e)
            }
        })?;

        let stored_hash = std::fs::read_to_string(&hash_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CryptoError::IntegrityFailure(format!("missing integrity hash for key '{}'", name))
            } else {
                CryptoError::Io(e)
            }
        })?;

        let computed_hash = blake3::hash(&secret_bytes);
        if computed_hash.to_hex().as_str() != stored_hash.trim() {
            return Err(CryptoError::IntegrityFailure(format!(
                "key '{}' integrity check failed: expected {} got {}",
                name,
                stored_hash.trim(),
                computed_hash.to_hex()
            )));
        }

        let algorithm = std::fs::read_to_string(&algo_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CryptoError::InvalidKey
            } else {
                CryptoError::Io(e)
            }
        })?;

        Ok((secret_bytes, algorithm.trim().to_string()))
    }

    /// Load the public key bytes for a named key.
    pub fn load_public(&self, name: &str) -> Result<Vec<u8>, CryptoError> {
        let pub_path = self.keys_dir.join(format!("{}.pub", name));
        std::fs::read(&pub_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CryptoError::InvalidKey
            } else {
                CryptoError::Io(e)
            }
        })
    }

    /// Check whether a named key exists.
    pub fn exists(&self, name: &str) -> bool {
        self.keys_dir.join(format!("{}.key", name)).exists()
    }

    /// Load an existing key or generate a new Ed25519 key.
    pub fn load_or_generate_ed25519(
        &self,
        name: &str,
    ) -> Result<super::ed25519::Ed25519Signer, CryptoError> {
        if self.exists(name) {
            let (secret_bytes, algorithm) = self.load(name)?;
            if algorithm != "ed25519" {
                return Err(CryptoError::InvalidKey);
            }
            let secret: [u8; 32] = secret_bytes
                .try_into()
                .map_err(|_| CryptoError::InvalidKey)?;
            Ok(super::ed25519::Ed25519Signer::from_bytes(&secret))
        } else {
            let mut rng = rand_core::UnwrapErr(getrandom::SysRng);
            let signer = super::ed25519::Ed25519Signer::generate(&mut rng);
            self.store(
                name,
                &signer.secret_key_bytes(),
                Some(signer.public_key()),
                "ed25519",
            )?;
            Ok(signer)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::new(dir.path().to_path_buf()).unwrap();
        let secret = [42u8; 32];
        let public = [99u8; 32];
        ks.store("test", &secret, Some(&public), "ed25519").unwrap();

        let (loaded_secret, algo) = ks.load("test").unwrap();
        assert_eq!(loaded_secret, secret);
        assert_eq!(algo, "ed25519");

        let loaded_pub = ks.load_public("test").unwrap();
        assert_eq!(loaded_pub, public);
    }

    #[test]
    fn integrity_failure_on_tampered_key() {
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::new(dir.path().to_path_buf()).unwrap();
        ks.store("tampered", &[1u8; 32], None, "ed25519").unwrap();

        // Tamper with the key file
        let key_path = dir.path().join("tampered.key");
        std::fs::write(&key_path, [2u8; 32]).unwrap();

        let result = ks.load("tampered");
        assert!(matches!(result, Err(CryptoError::IntegrityFailure(_))));
    }

    #[test]
    fn load_nonexistent_fails() {
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::new(dir.path().to_path_buf()).unwrap();
        assert!(matches!(ks.load("nope"), Err(CryptoError::InvalidKey)));
    }

    #[test]
    fn exists_check() {
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::new(dir.path().to_path_buf()).unwrap();
        assert!(!ks.exists("x"));
        ks.store("x", &[0u8; 16], None, "test").unwrap();
        assert!(ks.exists("x"));
    }

    #[test]
    fn load_or_generate_creates_then_loads() {
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::new(dir.path().to_path_buf()).unwrap();

        let s1 = ks.load_or_generate_ed25519("default").unwrap();
        let s2 = ks.load_or_generate_ed25519("default").unwrap();
        assert_eq!(s1.public_key(), s2.public_key());
    }

    #[test]
    fn load_or_generate_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let ks = KeyStore::new(dir.path().to_path_buf()).unwrap();

        let s1 = ks.load_or_generate_ed25519("idem").unwrap();
        let s2 = ks.load_or_generate_ed25519("idem").unwrap();
        let s3 = ks.load_or_generate_ed25519("idem").unwrap();
        assert_eq!(s1.public_key(), s2.public_key());
        assert_eq!(s2.public_key(), s3.public_key());
    }
}
