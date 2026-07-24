//! Key persistence with BLAKE3 integrity protection.
//!
//! Pattern from rekindle-keys: {name}.key (0o600), {name}.pub (0o644),
//! {name}.blake3 (0o600), {name}.algorithm. Atomic writes via tempfile
//! + rename. BLAKE3(pub || key) integrity checksum verified on load.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use super::{generate_raw_keypair, signer_from_bytes, CryptoError, RegistrySigner};
use crate::store::fs::atomic_write;

pub struct KeyStore {
    keys_dir: PathBuf,
}

impl KeyStore {
    pub fn new(store_root: &Path) -> Result<Self, CryptoError> {
        let keys_dir = store_root.join("keys");
        std::fs::create_dir_all(&keys_dir).map_err(|_| CryptoError::InvalidKey)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&keys_dir, std::fs::Permissions::from_mode(0o700));
        }
        Ok(Self { keys_dir })
    }

    /// Load the default signing key, or generate one if absent.
    pub fn load_or_generate(
        &self,
        algorithm: &str,
    ) -> Result<Box<dyn RegistrySigner>, CryptoError> {
        let key_path = self.keys_dir.join("default.key");
        if key_path.exists() {
            self.load("default")
        } else {
            self.generate("default", algorithm)
        }
    }

    /// Generate a new keypair, persist to disk, return the signer.
    pub fn generate(
        &self,
        name: &str,
        algorithm: &str,
    ) -> Result<Box<dyn RegistrySigner>, CryptoError> {
        let (private, public) = generate_raw_keypair(algorithm)?;

        // Write algorithm
        atomic_write(
            &self.keys_dir.join(format!("{name}.algorithm")),
            algorithm.as_bytes(),
        )
        .map_err(|_| CryptoError::InvalidKey)?;

        // Write public key
        atomic_write(&self.keys_dir.join(format!("{name}.pub")), &public)
            .map_err(|_| CryptoError::InvalidKey)?;

        // Write private key
        let key_path = self.keys_dir.join(format!("{name}.key"));
        atomic_write(&key_path, &private).map_err(|_| CryptoError::InvalidKey)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600));
        }

        // Write BLAKE3 integrity checksum
        let mut hasher = blake3::Hasher::new();
        hasher.update(&public);
        hasher.update(&private);
        let checksum = hasher.finalize();
        let checksum_path = self.keys_dir.join(format!("{name}.blake3"));
        atomic_write(&checksum_path, checksum.as_bytes()).map_err(|_| CryptoError::InvalidKey)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&checksum_path, std::fs::Permissions::from_mode(0o600));
        }

        signer_from_bytes(algorithm, &private)
    }

    /// Load a keypair from disk with BLAKE3 integrity verification.
    pub fn load(&self, name: &str) -> Result<Box<dyn RegistrySigner>, CryptoError> {
        let alg = std::fs::read_to_string(self.keys_dir.join(format!("{name}.algorithm")))
            .map_err(|_| CryptoError::InvalidKey)?;

        let pub_bytes = std::fs::read(self.keys_dir.join(format!("{name}.pub")))
            .map_err(|_| CryptoError::InvalidKey)?;

        let key_bytes = Zeroizing::new(
            std::fs::read(self.keys_dir.join(format!("{name}.key")))
                .map_err(|_| CryptoError::InvalidKey)?,
        );

        // BLAKE3 integrity check
        let checksum_path = self.keys_dir.join(format!("{name}.blake3"));
        if checksum_path.exists() {
            let stored = std::fs::read(&checksum_path).map_err(|_| CryptoError::InvalidKey)?;
            let mut hasher = blake3::Hasher::new();
            hasher.update(&pub_bytes);
            hasher.update(&key_bytes);
            let computed = hasher.finalize();
            if stored.len() != 32 || stored[..] != computed.as_bytes()[..] {
                return Err(CryptoError::InvalidKey);
            }
        }

        signer_from_bytes(alg.trim(), &key_bytes)
    }

    /// Read a public key without loading the private key.
    pub fn public_key(&self, name: &str) -> Result<Vec<u8>, CryptoError> {
        std::fs::read(self.keys_dir.join(format!("{name}.pub")))
            .map_err(|_| CryptoError::InvalidKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{RegistryVerifier, ALG_ED25519, ALG_P256};

    fn temp_store() -> (tempfile::TempDir, KeyStore) {
        let dir = tempfile::TempDir::new().unwrap();
        let ks = KeyStore::new(dir.path()).unwrap();
        (dir, ks)
    }

    #[test]
    fn generate_creates_files() {
        let (_dir, ks) = temp_store();
        let _signer = ks.generate("default", ALG_ED25519).unwrap();
        assert!(ks.keys_dir.join("default.key").exists());
        assert!(ks.keys_dir.join("default.pub").exists());
        assert!(ks.keys_dir.join("default.blake3").exists());
        assert!(ks.keys_dir.join("default.algorithm").exists());
        let alg = std::fs::read_to_string(ks.keys_dir.join("default.algorithm")).unwrap();
        assert_eq!(alg, ALG_ED25519);
    }

    #[test]
    fn load_after_generate() {
        let (_dir, ks) = temp_store();
        let signer1 = ks.generate("default", ALG_ED25519).unwrap();
        let signer2 = ks.load("default").unwrap();
        assert_eq!(signer1.public_key_bytes(), signer2.public_key_bytes());
    }

    #[test]
    fn load_detects_tamper() {
        let (_dir, ks) = temp_store();
        ks.generate("default", ALG_ED25519).unwrap();
        // Corrupt the private key
        let key_path = ks.keys_dir.join("default.key");
        std::fs::write(&key_path, vec![0u8; 32]).unwrap();
        assert!(ks.load("default").is_err());
    }

    #[test]
    fn load_or_generate_creates_on_first_call() {
        let (_dir, ks) = temp_store();
        let signer = ks.load_or_generate(ALG_ED25519).unwrap();
        assert!(!signer.public_key_bytes().is_empty());
        assert!(ks.keys_dir.join("default.key").exists());
    }

    #[test]
    fn load_or_generate_loads_on_second_call() {
        let (_dir, ks) = temp_store();
        let s1 = ks.load_or_generate(ALG_ED25519).unwrap();
        let s2 = ks.load_or_generate(ALG_ED25519).unwrap();
        assert_eq!(s1.public_key_bytes(), s2.public_key_bytes());
    }

    #[test]
    fn public_key_without_private() {
        let (_dir, ks) = temp_store();
        let signer = ks.generate("default", ALG_ED25519).unwrap();
        let pk_from_signer = signer.public_key_bytes();
        let pk_from_disk = ks.public_key("default").unwrap();
        assert_eq!(pk_from_signer, pk_from_disk);
    }

    #[test]
    fn p256_generate_load_roundtrip() {
        let (_dir, ks) = temp_store();
        let s1 = ks.generate("default", ALG_P256).unwrap();
        let s2 = ks.load("default").unwrap();
        assert_eq!(s1.public_key_bytes(), s2.public_key_bytes());
        let msg = b"p256 keystore test";
        let sig = s2.sign(msg).unwrap();
        let verifier = crate::crypto::ecdsa::P256Verifier;
        assert!(verifier.verify(msg, &sig, &s2.public_key_bytes()).unwrap());
    }
}
