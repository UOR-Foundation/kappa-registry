//! Store-wide blob encryption ownership and durable revocation.
use std::sync::RwLock;

use kappa_crypto::{
    aead::BlobEncryptor,
    kms::{FileKms, KeyManagementService},
};
use kappa_types::StoreError;

/// The store's blob encryption domain.
///
/// Encrypted readers hold this through an `Arc` and outlive the store that
/// opened them (a streaming response moves only its reader into the
/// producer). Every later decryption and cached-plaintext delivery consults
/// the KMS erasure directory under the store's blob root, so the domain
/// retains the owner of that filesystem scope: a reader's checks never
/// observe a deleted scope as an I/O failure instead of deliberate erasure.
/// Retention does not bypass revocation; `erase` still denies every holder.
pub struct BlobEncryption {
    kms: FileKms,
    cipher: RwLock<Option<BlobEncryptor>>,
    /// Declared last so it drops after the KMS and cipher.
    _scope: Option<std::sync::Arc<dyn Send + Sync>>,
}

impl BlobEncryption {
    pub(crate) fn new(
        kms: FileKms,
        scope: Option<std::sync::Arc<dyn Send + Sync>>,
    ) -> Result<Self, StoreError> {
        let cipher = BlobEncryptor::new(&kms, "_default").map_err(crate::error::crypto)?;
        Ok(Self {
            kms,
            cipher: RwLock::new(Some(cipher)),
            _scope: scope,
        })
    }

    fn access<T>(
        &self,
        operation: impl FnOnce(&BlobEncryptor) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let guard = self
            .cipher
            .read()
            .map_err(|_| StoreError::Internal("blob encryption ownership poisoned".into()))?;
        if self
            .kms
            .is_erased("_default", "_blob_encryption")
            .map_err(crate::error::crypto)?
        {
            return Err(StoreError::Rejected("blob encryption key erased".into()));
        }
        let cipher = guard
            .as_ref()
            .ok_or_else(|| StoreError::Rejected("blob encryption key erased".into()))?;
        let result = operation(cipher);
        drop(guard);
        result
    }

    pub(crate) fn encrypt(&self, context: &str, bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.access(|cipher| crate::blob_cipher::encrypt(cipher, context, bytes))
    }

    pub(crate) fn while_active<T>(&self, operation: impl FnOnce() -> T) -> Result<T, StoreError> {
        self.access(|_| Ok(operation()))
    }

    pub(crate) fn decrypt(&self, context: &str, bytes: &[u8]) -> Result<Vec<u8>, StoreError> {
        self.access(|cipher| crate::blob_cipher::decrypt(cipher, context, bytes))
    }

    pub(crate) fn erase(&self) -> Result<(), StoreError> {
        let mut guard = self
            .cipher
            .write()
            .map_err(|_| StoreError::Internal("blob encryption ownership poisoned".into()))?;
        let result = self
            .kms
            .erase_subject_key("_default", "_blob_encryption")
            .map_err(crate::error::crypto);
        // Revoke cached access even if durable acknowledgement fails. A caller
        // must retry erasure to establish durable completion in that case.
        guard.take();
        drop(guard);
        result
    }
}

impl crate::PersistentStore {
    /// Durably revoke this store's entire blob encryption domain, including
    /// retained readers. This is distinct from logical content deletion.
    pub fn erase_blob_encryption(&self) -> Result<(), StoreError> {
        self.blob_encryptor
            .as_ref()
            .ok_or_else(|| StoreError::NotSupported("store has no blob encryption domain".into()))?
            .erase()
    }
}

#[cfg(test)]
#[path = "blob_encryption_tests.rs"]
mod tests;
