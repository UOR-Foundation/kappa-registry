//! Blob-at-rest AEAD encryption via rekindle-aead.
//!
//! Derives per-namespace encryption keys from the KMS root secret.
//! Derives per-blob nonces from HMAC(ns_key, kappa) truncated to 12 bytes.
//! Delegates seal/open to `BulkAead` (AesGcmKey or Aegis128LKey).
//!
//! The kappa-label is passed as AAD so the ciphertext is bound to its
//! content address. Moving ciphertext to a different kappa address
//! causes authentication failure on decrypt.

use super::kms::KeyManagementService;
use super::CryptoError;

use rekindle_aead::aes_gcm::AesGcmKey;
use rekindle_aead::BulkAead;

/// Blob encryption context for a single namespace.
///
/// Holds a pre-expanded AES-256-GCM key derived from the KMS for this
/// namespace. All blob encrypt/decrypt for this namespace uses this key.
/// The nonce is derived from the blob's kappa-label so the same blob
/// always produces the same ciphertext (deterministic encryption for
/// content-addressed dedup).
pub struct BlobEncryptor {
    key: AesGcmKey,
    ns_key_bytes: [u8; 32],
}

impl BlobEncryptor {
    /// Create an encryptor for a namespace using a KMS-derived key.
    pub fn new(
        kms: &dyn KeyManagementService,
        namespace: &str,
    ) -> Result<Self, CryptoError> {
        let derived = kms.derive_subject_key(namespace, "_blob_encryption")?;
        let key_bytes: [u8; 32] = derived
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let aes_key = AesGcmKey::new(&key_bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            key: aes_key,
            ns_key_bytes: key_bytes,
        })
    }

    /// Derive a 12-byte nonce from the kappa-label.
    ///
    /// nonce = BLAKE3-keyed(ns_key, kappa)[..12]
    ///
    /// Deterministic: same kappa always produces the same nonce.
    /// Safe because each kappa is unique (content-addressed), so
    /// (key, nonce) pairs never repeat.
    fn nonce_for_kappa(&self, kappa: &str) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new_keyed(&self.ns_key_bytes);
        hasher.update(kappa.as_bytes());
        let hash = hasher.finalize();
        let bytes = hash.as_bytes();
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&bytes[..16]);
        nonce
    }

    /// Encrypt a blob. Returns (ciphertext, tag).
    ///
    /// The kappa-label is used as AAD, binding the ciphertext to its
    /// content address. The nonce is derived from the kappa.
    pub fn encrypt(
        &self,
        kappa: &str,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, [u8; 16]), CryptoError> {
        let nonce = self.nonce_for_kappa(kappa);
        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        self.key
            .seal_detached(
                &nonce[..self.key.nonce_len()],
                kappa.as_bytes(),
                plaintext,
                &mut ciphertext,
                &mut tag,
            )
            .map_err(|e| CryptoError::SigningFailed(format!("AEAD seal failed: {e}")))?;
        Ok((ciphertext, tag))
    }

    /// Decrypt a blob. Returns plaintext.
    ///
    /// Verifies the tag and AAD (kappa-label). Returns an error if the
    /// ciphertext was tampered, the kappa was changed, or the wrong key
    /// is used.
    pub fn decrypt(
        &self,
        kappa: &str,
        ciphertext: &[u8],
        tag: &[u8; 16],
    ) -> Result<Vec<u8>, CryptoError> {
        let nonce = self.nonce_for_kappa(kappa);
        let mut plaintext = vec![0u8; ciphertext.len()];
        self.key
            .open_detached(
                &nonce[..self.key.nonce_len()],
                kappa.as_bytes(),
                ciphertext,
                tag,
                &mut plaintext,
            )
            .map_err(|e| CryptoError::SigningFailed(format!("AEAD open failed: {e}")))?;
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kms::FileKms;

    fn test_kms() -> (FileKms, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let kms = FileKms::new([0x42u8; 32], dir.path().join("erased")).unwrap();
        (kms, dir)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let plaintext = b"hello encrypted world";
        let kappa = "sha256:aabbccdd";
        let (ct, tag) = enc.encrypt(kappa, plaintext).unwrap();
        let pt = enc.decrypt(kappa, &ct, &tag).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_kappa_fails() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let (ct, tag) = enc.encrypt("sha256:aaa", b"secret").unwrap();
        // Decrypt with different kappa (different AAD) must fail
        assert!(enc.decrypt("sha256:bbb", &ct, &tag).is_err());
    }

    #[test]
    fn wrong_namespace_fails() {
        let (kms, _dir) = test_kms();
        let enc_a = BlobEncryptor::new(&kms, "ns-a").unwrap();
        let enc_b = BlobEncryptor::new(&kms, "ns-b").unwrap();
        let kappa = "sha256:same";
        let (ct, tag) = enc_a.encrypt(kappa, b"data").unwrap();
        // Different namespace key must fail
        assert!(enc_b.decrypt(kappa, &ct, &tag).is_err());
    }

    #[test]
    fn deterministic_encryption() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let kappa = "sha256:deterministic";
        let (ct1, tag1) = enc.encrypt(kappa, b"same content").unwrap();
        let (ct2, tag2) = enc.encrypt(kappa, b"same content").unwrap();
        // Same key + same nonce + same plaintext + same AAD = same ciphertext
        assert_eq!(ct1, ct2);
        assert_eq!(tag1, tag2);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let kappa = "sha256:tamper";
        let (mut ct, tag) = enc.encrypt(kappa, b"original").unwrap();
        ct[0] ^= 0xFF;
        assert!(enc.decrypt(kappa, &ct, &tag).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let kappa = "sha256:empty";
        let (ct, tag) = enc.encrypt(kappa, b"").unwrap();
        assert!(ct.is_empty());
        let pt = enc.decrypt(kappa, &ct, &tag).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn erased_key_prevents_new_encryptor() {
        let (kms, _dir) = test_kms();
        let _enc = BlobEncryptor::new(&kms, "erase-ns").unwrap();
        kms.erase_subject_key("erase-ns", "_blob_encryption").unwrap();
        // After erasure, creating a new encryptor fails
        assert!(BlobEncryptor::new(&kms, "erase-ns").is_err());
    }
}
