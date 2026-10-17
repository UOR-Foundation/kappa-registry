use std::fs;
use std::io::Write;
use std::path::PathBuf;

use super::CryptoError;

/// Backend-specific errors for KMS operations.
enum KmsError {
    KeyErased { namespace: String, subject: String },
}

impl From<KmsError> for CryptoError {
    fn from(e: KmsError) -> Self {
        match e {
            KmsError::KeyErased { namespace, subject } => CryptoError::InvalidKey {
                reason: format!(
                    "key for {}/{} has been erased and cannot be derived",
                    namespace, subject,
                ),
            },
        }
    }
}

/// Key derivation and erasure contract.
///
/// Implementations derive per-namespace per-subject encryption keys
/// from a root secret via a KDF. Erasure marks a key as permanently
/// unavailable -- subsequent derivation attempts fail.
pub trait KeyManagementService: Send + Sync {
    /// Derive a 32-byte subject key from the root secret.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if the key has been erased.
    fn derive_subject_key(&self, namespace: &str, subject: &str) -> Result<Vec<u8>, CryptoError>;

    /// Permanently erase a subject key. After erasure, derive_subject_key
    /// returns an error. The erasure is durable -- it survives restarts.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::Io` if the erasure marker cannot be written.
    fn erase_subject_key(&self, namespace: &str, subject: &str) -> Result<(), CryptoError>;

    /// Check whether a subject key has been erased.
    fn is_erased(&self, namespace: &str, subject: &str) -> Result<bool, CryptoError>;
}

/// Filesystem-backed KMS using BLAKE3 key derivation.
///
/// Root secret is a 32-byte key from which all subject keys are
/// derived via BLAKE3's derive_key mode with a domain-separated
/// context string. Erasure creates a marker file on disk that
/// prevents future derivation.
pub struct FileKms {
    root_secret: zeroize::Zeroizing<[u8; 32]>,
    erased_dir: PathBuf,
}

impl FileKms {
    pub fn new(root_secret: [u8; 32], erased_dir: PathBuf) -> Result<Self, CryptoError> {
        fs::create_dir_all(&erased_dir)?;
        Ok(Self {
            root_secret: zeroize::Zeroizing::new(root_secret),
            erased_dir,
        })
    }

    fn erased_marker_path(&self, namespace: &str, subject: &str) -> PathBuf {
        let context_hash = blake3::hash(&subject_identity(namespace, subject));
        self.erased_dir
            .join(format!("{}.erased", context_hash.to_hex()))
    }
}

fn subject_identity(namespace: &str, subject: &str) -> Vec<u8> {
    let mut identity = Vec::new();
    // Rust slice lengths fit u64 on supported targets. Encode both boundaries
    // explicitly; separators cannot distinguish arbitrary namespace/subject text.
    identity.extend_from_slice(&(namespace.len() as u64).to_be_bytes());
    identity.extend_from_slice(namespace.as_bytes());
    identity.extend_from_slice(&(subject.len() as u64).to_be_bytes());
    identity.extend_from_slice(subject.as_bytes());
    identity
}

impl KeyManagementService for FileKms {
    fn derive_subject_key(&self, namespace: &str, subject: &str) -> Result<Vec<u8>, CryptoError> {
        if self.is_erased(namespace, subject)? {
            return Err(KmsError::KeyErased {
                namespace: namespace.into(),
                subject: subject.into(),
            }
            .into());
        }
        let mut material = zeroize::Zeroizing::new(subject_identity(namespace, subject));
        material.extend_from_slice(self.root_secret.as_ref());
        let derived = blake3::derive_key("kappa-kms subject-key", &material);
        Ok(derived.to_vec())
    }

    fn erase_subject_key(&self, namespace: &str, subject: &str) -> Result<(), CryptoError> {
        let marker = self.erased_marker_path(namespace, subject);
        // Existence denies derivation, so even an interrupted marker write is
        // conservative. Synchronize both its contents and directory entry
        // before acknowledging erasure to the caller.
        let mut file = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&marker)?;
        file.write_all(b"erased")?;
        file.sync_all()?;
        fs::File::open(&self.erased_dir)?.sync_all()?;
        Ok(())
    }

    fn is_erased(&self, namespace: &str, subject: &str) -> Result<bool, CryptoError> {
        if !fs::metadata(&self.erased_dir)?.is_dir() {
            return Err(std::io::Error::other("KMS erasure store is not a directory").into());
        }
        match fs::metadata(self.erased_marker_path(namespace, subject)) {
            Ok(_) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kms() -> (FileKms, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("rng");
        let kms = FileKms::new(secret, dir.path().join("erased")).expect("kms");
        (kms, dir)
    }

    #[test]
    fn derive_is_deterministic() {
        let (kms, _dir) = test_kms();
        let a = kms.derive_subject_key("ns", "subj").expect("derive");
        let b = kms.derive_subject_key("ns", "subj").expect("derive");
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
    }

    #[test]
    fn different_subjects_produce_different_keys() {
        let (kms, _dir) = test_kms();
        let a = kms.derive_subject_key("ns", "subj-a").expect("derive");
        let b = kms.derive_subject_key("ns", "subj-b").expect("derive");
        assert_ne!(a, b);
    }

    #[test]
    fn different_namespaces_produce_different_keys() {
        let (kms, _dir) = test_kms();
        let a = kms.derive_subject_key("ns-a", "subj").expect("derive");
        let b = kms.derive_subject_key("ns-b", "subj").expect("derive");
        assert_ne!(a, b);
    }

    #[test]
    fn component_boundaries_separate_keys_and_erasure() {
        let (kms, _dir) = test_kms();
        let first = kms.derive_subject_key("a/b", "c").expect("first key");
        let second = kms.derive_subject_key("a", "b/c").expect("second key");
        assert_ne!(first, second);
        kms.erase_subject_key("a/b", "c").expect("erase first");
        assert!(kms.derive_subject_key("a/b", "c").is_err());
        assert_eq!(
            kms.derive_subject_key("a", "b/c").expect("second remains"),
            second
        );
    }

    #[test]
    fn erase_prevents_derivation() {
        let (kms, _dir) = test_kms();
        kms.derive_subject_key("ns", "doomed")
            .expect("derive before erase");
        kms.erase_subject_key("ns", "doomed").expect("erase");
        let result = kms.derive_subject_key("ns", "doomed");
        assert!(matches!(result, Err(CryptoError::InvalidKey { .. })));
    }

    #[test]
    fn erase_is_durable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).expect("rng");
        let erased_path = dir.path().join("erased");

        {
            let kms = FileKms::new(secret, erased_path.clone()).expect("kms");
            kms.erase_subject_key("ns", "doomed").expect("erase");
        }

        let kms2 = FileKms::new(secret, erased_path).expect("kms2");
        assert!(kms2.is_erased("ns", "doomed").expect("is_erased"));
        let result = kms2.derive_subject_key("ns", "doomed");
        assert!(matches!(result, Err(CryptoError::InvalidKey { .. })));
    }

    #[test]
    fn is_erased_false_for_unerased() {
        let (kms, _dir) = test_kms();
        assert!(!kms.is_erased("ns", "active").expect("is_erased"));
    }

    #[test]
    fn marker_lookup_failure_does_not_allow_derivation() {
        let (kms, _dir) = test_kms();
        fs::remove_dir(&kms.erased_dir).expect("remove marker directory");
        fs::write(&kms.erased_dir, b"not a directory").expect("replace directory");
        assert!(matches!(
            kms.is_erased("ns", "subject"),
            Err(CryptoError::Io(_))
        ));
        assert!(matches!(
            kms.derive_subject_key("ns", "subject"),
            Err(CryptoError::Io(_))
        ));
        assert!(matches!(
            kms.erase_subject_key("ns", "subject"),
            Err(CryptoError::Io(_))
        ));
    }

    #[test]
    fn missing_erasure_store_does_not_allow_derivation() {
        let (kms, _dir) = test_kms();
        fs::remove_dir(&kms.erased_dir).expect("remove marker directory");
        assert!(matches!(
            kms.derive_subject_key("ns", "subject"),
            Err(CryptoError::Io(_))
        ));
    }

    #[test]
    fn erase_does_not_affect_other_subjects() {
        let (kms, _dir) = test_kms();
        let key_before = kms.derive_subject_key("ns", "safe").expect("derive");
        kms.erase_subject_key("ns", "doomed").expect("erase");
        let key_after = kms
            .derive_subject_key("ns", "safe")
            .expect("derive after erase");
        assert_eq!(key_before, key_after);
    }
}
