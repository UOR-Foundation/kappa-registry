//! Encrypted wrapper for redb table operations.
//!
//! Provides encrypt-on-write / decrypt-on-read for all redb table values
//! and HMAC-keyed table keys. This protects metadata (tag names, edge
//! relations, asserter identities, sequence counters) at rest.
//!
//! Architecture:
//! - Keys are HMAC'd with a per-namespace key before storage. This hides
//!   the plaintext key from anyone with disk access but no KMS key.
//! - Values are AEAD-encrypted (AES-256-GCM) with the plaintext key as AAD.
//!   This binds the ciphertext to its key -- moving a value to a different
//!   key causes authentication failure.
//! - The 16-byte authentication tag is prepended to the encrypted value.
//!   Stored format: [tag:16][ciphertext:N].
//! - The nonce is derived from BLAKE3-keyed(ns_key, plaintext_key)[..12].
//!   Deterministic so the same key always produces the same nonce. Safe
//!   because each (namespace, key) pair is unique.
//!
//! Range scans: tag_list and tag_prefix decrypt all keys in the namespace
//! and filter in memory. This is O(n) per namespace but acceptable for
//! single-node deployments with thousands to millions of tags.

use rekindle_aead::aes_gcm::AesGcmKey;
use rekindle_aead::BulkAead;

/// Encrypted table key/value operations.
///
/// Holds a pre-expanded AES-256-GCM key for a namespace. Created once
/// per namespace, reused for all table operations in that namespace.
pub struct TableEncryptor {
    key: AesGcmKey,
    ns_key_bytes: [u8; 32],
}

impl TableEncryptor {
    /// Create from a 32-byte namespace key (derived from KMS).
    pub fn new(ns_key: &[u8; 32]) -> Result<Self, EncryptionError> {
        let aes_key =
            AesGcmKey::new(ns_key).map_err(|_| EncryptionError::KeyInit)?;
        Ok(Self {
            key: aes_key,
            ns_key_bytes: *ns_key,
        })
    }

    /// HMAC a table key for storage. Returns hex-encoded HMAC.
    pub fn hmac_key(&self, plaintext_key: &str) -> String {
        let mut hasher = blake3::Hasher::new_keyed(&self.ns_key_bytes);
        hasher.update(plaintext_key.as_bytes());
        let hash = hasher.finalize();
        hex::encode(hash.as_bytes())
    }

    /// Derive a 12-byte nonce from a plaintext key.
    fn nonce_for_key(&self, plaintext_key: &str) -> [u8; 16] {
        let mut hasher = blake3::Hasher::new_keyed(&self.ns_key_bytes);
        hasher.update(b"nonce:");
        hasher.update(plaintext_key.as_bytes());
        let hash = hasher.finalize();
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&hash.as_bytes()[..16]);
        nonce
    }

    /// Encrypt a value for storage. Returns [tag:16][ciphertext:N].
    /// The plaintext key is used as AAD.
    pub fn encrypt_value(
        &self,
        plaintext_key: &str,
        value: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        let nonce = self.nonce_for_key(plaintext_key);
        let mut ciphertext = vec![0u8; value.len()];
        let mut tag = [0u8; 16];
        self.key
            .seal_detached(
                &nonce[..self.key.nonce_len()],
                plaintext_key.as_bytes(),
                value,
                &mut ciphertext,
                &mut tag,
            )
            .map_err(|_| EncryptionError::SealFailed)?;

        // Prepend tag to ciphertext: [tag:16][ct:N]
        let mut result = Vec::with_capacity(16 + ciphertext.len());
        result.extend_from_slice(&tag);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    /// Decrypt a stored value. Input format: [tag:16][ciphertext:N].
    /// The plaintext key is used as AAD for verification.
    pub fn decrypt_value(
        &self,
        plaintext_key: &str,
        stored: &[u8],
    ) -> Result<Vec<u8>, EncryptionError> {
        if stored.len() < 16 {
            return Err(EncryptionError::TruncatedValue);
        }
        let tag = &stored[..16];
        let ciphertext = &stored[16..];

        let nonce = self.nonce_for_key(plaintext_key);
        let mut plaintext = vec![0u8; ciphertext.len()];
        self.key
            .open_detached(
                &nonce[..self.key.nonce_len()],
                plaintext_key.as_bytes(),
                ciphertext,
                tag,
                &mut plaintext,
            )
            .map_err(|_| EncryptionError::AuthFailed)?;
        Ok(plaintext)
    }
}

/// Errors from table encryption operations.
#[derive(Debug)]
pub enum EncryptionError {
    /// AES-256-GCM key initialization failed.
    KeyInit,
    /// AEAD seal operation failed.
    SealFailed,
    /// AEAD authentication failed (tampered data or wrong key).
    AuthFailed,
    /// Stored value too short to contain a 16-byte tag.
    TruncatedValue,
}

impl std::fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyInit => write!(f, "AEAD key initialization failed"),
            Self::SealFailed => write!(f, "AEAD seal failed"),
            Self::AuthFailed => write!(f, "AEAD authentication failed"),
            Self::TruncatedValue => write!(f, "stored value too short for tag"),
        }
    }
}

impl std::error::Error for EncryptionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let enc = TableEncryptor::new(&[0x42u8; 32]).unwrap();
        let key = "test-ns\x00latest";
        let value = b"sha256:aabbccdd\x001";
        let encrypted = enc.encrypt_value(key, value).unwrap();
        assert_ne!(&encrypted[16..], value); // ciphertext differs from plaintext
        let decrypted = enc.decrypt_value(key, &encrypted).unwrap();
        assert_eq!(decrypted, value);
    }

    #[test]
    fn wrong_key_fails() {
        let enc = TableEncryptor::new(&[0x42u8; 32]).unwrap();
        let encrypted = enc.encrypt_value("key-a", b"data").unwrap();
        // Decrypt with different key (different AAD) must fail
        assert!(enc.decrypt_value("key-b", &encrypted).is_err());
    }

    #[test]
    fn wrong_namespace_key_fails() {
        let enc_a = TableEncryptor::new(&[0x42u8; 32]).unwrap();
        let enc_b = TableEncryptor::new(&[0x43u8; 32]).unwrap();
        let encrypted = enc_a.encrypt_value("same-key", b"data").unwrap();
        assert!(enc_b.decrypt_value("same-key", &encrypted).is_err());
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let enc = TableEncryptor::new(&[0x42u8; 32]).unwrap();
        let mut encrypted = enc.encrypt_value("key", b"data").unwrap();
        encrypted[20] ^= 0xFF; // tamper after the tag
        assert!(enc.decrypt_value("key", &encrypted).is_err());
    }

    #[test]
    fn tampered_tag_fails() {
        let enc = TableEncryptor::new(&[0x42u8; 32]).unwrap();
        let mut encrypted = enc.encrypt_value("key", b"data").unwrap();
        encrypted[0] ^= 0xFF; // tamper the tag
        assert!(enc.decrypt_value("key", &encrypted).is_err());
    }

    #[test]
    fn hmac_key_deterministic() {
        let enc = TableEncryptor::new(&[0x42u8; 32]).unwrap();
        assert_eq!(enc.hmac_key("test"), enc.hmac_key("test"));
    }

    #[test]
    fn hmac_key_differs_for_different_inputs() {
        let enc = TableEncryptor::new(&[0x42u8; 32]).unwrap();
        assert_ne!(enc.hmac_key("a"), enc.hmac_key("b"));
    }

    #[test]
    fn empty_value_roundtrip() {
        let enc = TableEncryptor::new(&[0x42u8; 32]).unwrap();
        let encrypted = enc.encrypt_value("key", b"").unwrap();
        assert_eq!(encrypted.len(), 16); // tag only, no ciphertext
        let decrypted = enc.decrypt_value("key", &encrypted).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn truncated_value_rejected() {
        let enc = TableEncryptor::new(&[0x42u8; 32]).unwrap();
        assert!(enc.decrypt_value("key", &[0u8; 10]).is_err());
    }
}
