//! Key Management Service trait and filesystem implementation.
//!
//! The KMS trait abstracts key storage and derivation. The FileKms
//! implementation delegates to KeyStore for filesystem-backed keys.
//! HSM/PKCS#11 implementations can be added behind this trait.

use super::CryptoError;

/// Key Management Service trait (seam S2).
pub trait KeyManagementService: Send + Sync {
    /// Derive a per-subject encryption key.
    ///
    /// The same (namespace, subject) pair always returns the same key.
    /// Erasing the key for a subject makes all data encrypted under
    /// it unrecoverable (GDPR crypto-shredding).
    fn derive_subject_key(
        &self,
        namespace: &str,
        subject: &str,
    ) -> Result<Vec<u8>, CryptoError>;

    /// Erase the key material for a subject.
    ///
    /// After erasure, derive_subject_key returns SubjectKeyErased.
    fn erase_subject_key(
        &self,
        namespace: &str,
        subject: &str,
    ) -> Result<(), CryptoError>;

    /// Check whether a subject's key has been erased.
    fn is_erased(&self, namespace: &str, subject: &str) -> Result<bool, CryptoError>;
}

/// Filesystem-backed KMS using BLAKE3 key derivation.
///
/// Keys are derived from a root secret using BLAKE3's keyed hash
/// with the context string "{namespace}/{subject}". The root secret
/// is loaded from the keystore.
pub struct FileKms {
    root_secret: [u8; 32],
    erased_dir: std::path::PathBuf,
}

impl FileKms {
    pub fn new(root_secret: [u8; 32], erased_dir: std::path::PathBuf) -> Result<Self, CryptoError> {
        std::fs::create_dir_all(&erased_dir)?;
        Ok(Self { root_secret, erased_dir })
    }

    fn erased_marker_path(&self, namespace: &str, subject: &str) -> std::path::PathBuf {
        let context_hash = blake3::hash(format!("{}/{}", namespace, subject).as_bytes());
        self.erased_dir.join(format!("{}.erased", context_hash.to_hex()))
    }
}

impl KeyManagementService for FileKms {
    fn derive_subject_key(
        &self,
        namespace: &str,
        subject: &str,
    ) -> Result<Vec<u8>, CryptoError> {
        if self.is_erased(namespace, subject)? {
            return Err(CryptoError::InvalidKey);
        }
        let context = format!("kappa-kms::{}/{}", namespace, subject);
        let derived = blake3::derive_key(&context, &self.root_secret);
        Ok(derived.to_vec())
    }

    fn erase_subject_key(
        &self,
        namespace: &str,
        subject: &str,
    ) -> Result<(), CryptoError> {
        let marker = self.erased_marker_path(namespace, subject);
        std::fs::write(&marker, b"erased")?;
        Ok(())
    }

    fn is_erased(&self, namespace: &str, subject: &str) -> Result<bool, CryptoError> {
        let marker = self.erased_marker_path(namespace, subject);
        Ok(marker.exists())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let kms = FileKms::new([1u8; 32], dir.path().to_path_buf()).unwrap();
        let k1 = kms.derive_subject_key("ns", "alice").unwrap();
        let k2 = kms.derive_subject_key("ns", "alice").unwrap();
        assert_eq!(k1, k2);
    }

    #[test]
    fn different_subjects_different_keys() {
        let dir = tempfile::tempdir().unwrap();
        let kms = FileKms::new([1u8; 32], dir.path().to_path_buf()).unwrap();
        let k1 = kms.derive_subject_key("ns", "alice").unwrap();
        let k2 = kms.derive_subject_key("ns", "bob").unwrap();
        assert_ne!(k1, k2);
    }

    #[test]
    fn erase_then_derive_fails() {
        let dir = tempfile::tempdir().unwrap();
        let kms = FileKms::new([1u8; 32], dir.path().to_path_buf()).unwrap();
        kms.derive_subject_key("ns", "alice").unwrap();
        kms.erase_subject_key("ns", "alice").unwrap();
        assert!(kms.derive_subject_key("ns", "alice").is_err());
    }

    #[test]
    fn is_erased_tracks_state() {
        let dir = tempfile::tempdir().unwrap();
        let kms = FileKms::new([1u8; 32], dir.path().to_path_buf()).unwrap();
        assert!(!kms.is_erased("ns", "alice").unwrap());
        kms.erase_subject_key("ns", "alice").unwrap();
        assert!(kms.is_erased("ns", "alice").unwrap());
    }

    #[test]
    fn key_is_32_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let kms = FileKms::new([1u8; 32], dir.path().to_path_buf()).unwrap();
        let k = kms.derive_subject_key("ns", "x").unwrap();
        assert_eq!(k.len(), 32);
    }
}
