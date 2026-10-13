//! The AEAD backend behind blob-at-rest and table encryption.
//!
//! With the `encryption` feature (on by default) this is `rekindle-aead`:
//! AES-256-GCM on aws-lc. Without it no key can be constructed, so every
//! encryption path fails closed when a store is configured with a key, and
//! nothing links aws-lc. An embedder that stores plaintext only (the default
//! `PersistentStoreConfig`) loses nothing by turning the feature off.

#[cfg(feature = "encryption")]
pub use rekindle_aead::{aes_gcm::AesGcmKey, BulkAead};

#[cfg(not(feature = "encryption"))]
pub use disabled::AesGcmKey;

#[cfg(not(feature = "encryption"))]
mod disabled {
    /// Why an AEAD operation did not happen: the backend is not compiled in.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Unavailable;

    impl std::fmt::Display for Unavailable {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "encryption is not compiled in (feature `encryption` is off)")
        }
    }

    impl std::error::Error for Unavailable {}

    /// Stand-in for the AES-256-GCM key. It cannot be constructed, so the
    /// methods below are unreachable; they exist so callers compile unchanged.
    pub struct AesGcmKey(());

    impl AesGcmKey {
        pub fn new(_key_bytes: &[u8; 32]) -> Result<Self, Unavailable> {
            Err(Unavailable)
        }

        pub fn nonce_len(&self) -> usize {
            12
        }

        pub fn seal_detached(
            &self,
            _nonce: &[u8],
            _aad: &[u8],
            _plaintext: &[u8],
            _ciphertext_out: &mut [u8],
            _tag_out: &mut [u8],
        ) -> Result<(), Unavailable> {
            Err(Unavailable)
        }

        pub fn open_detached(
            &self,
            _nonce: &[u8],
            _aad: &[u8],
            _ciphertext: &[u8],
            _tag: &[u8],
            _plaintext_out: &mut [u8],
        ) -> Result<(), Unavailable> {
            Err(Unavailable)
        }
    }
}
