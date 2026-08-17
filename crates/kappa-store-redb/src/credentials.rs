//! Credential store backed by redb CREDENTIALS table.
//!
//! Secrets are envelope-encrypted via TableEncryptor at rest.
//! Rotation stores current + previous secret with a 5-minute grace period.

use kappa_core::crypto::sigv4::{CredentialLookup, CredentialResult};
use kappa_core::types::StoreError;
use redb::ReadableDatabase;

use crate::tables::CREDENTIALS;
use crate::PersistentStore;

/// Credential record stored in redb.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Credential {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub previous_secret: Option<String>,
    pub previous_secret_expires_ms: Option<u64>,
    pub principal_anchor: String,
    pub created_ms: u64,
    pub active: bool,
}

impl PersistentStore {
    /// Create a new credential for a principal.
    pub fn credential_create(&self, principal: &str) -> Result<Credential, StoreError> {
        let mut access_key_bytes = [0u8; 15];
        getrandom::fill(&mut access_key_bytes)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
        let access_key_id = format!("KAPPA{}", hex::encode(&access_key_bytes[..10]).to_uppercase());

        let mut secret_bytes = [0u8; 30];
        getrandom::fill(&mut secret_bytes)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
        let secret_access_key = base64_encode(&secret_bytes);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let cred = Credential {
            access_key_id: access_key_id.clone(),
            secret_access_key,
            previous_secret: None,
            previous_secret_expires_ms: None,
            principal_anchor: principal.to_string(),
            created_ms: now_ms,
            active: true,
        };

        self.credential_store(&cred)?;
        Ok(cred)
    }

    /// Rotate a credential's secret. Current secret moves to previous
    /// with a 5-minute (300,000 ms) grace period.
    pub fn credential_rotate(&self, access_key_id: &str) -> Result<Credential, StoreError> {
        let mut cred = self.credential_load(access_key_id)?;

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        cred.previous_secret = Some(cred.secret_access_key.clone());
        cred.previous_secret_expires_ms = Some(now_ms + 300_000);

        let mut new_secret_bytes = [0u8; 30];
        getrandom::fill(&mut new_secret_bytes)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;
        cred.secret_access_key = base64_encode(&new_secret_bytes);

        self.credential_store(&cred)?;
        Ok(cred)
    }

    /// Deactivate a credential.
    pub fn credential_deactivate(&self, access_key_id: &str) -> Result<(), StoreError> {
        let mut cred = self.credential_load(access_key_id)?;
        cred.active = false;
        self.credential_store(&cred)
    }

    /// Load a credential by access key ID.
    pub fn credential_load(&self, access_key_id: &str) -> Result<Credential, StoreError> {
        let txn = self.db.begin_read().map_err(Self::redb_err)?;
        let table = txn.open_table(CREDENTIALS).map_err(Self::redb_err)?;
        let raw = table.get(access_key_id).map_err(Self::redb_err)?
            .ok_or_else(|| StoreError::NotFound(format!("credential {}", access_key_id)))?;

        let decrypted = match &self.table_encryptor {
            Some(enc) => enc.decrypt_value(access_key_id, raw.value())
                .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?,
            None => raw.value().to_vec(),
        };

        serde_json::from_slice(&decrypted)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))
    }

    fn credential_store(&self, cred: &Credential) -> Result<(), StoreError> {
        let json = serde_json::to_vec(cred)
            .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?;

        let stored = match &self.table_encryptor {
            Some(enc) => enc.encrypt_value(&cred.access_key_id, &json)
                .map_err(|e| StoreError::Io(std::io::Error::other(e.to_string())))?,
            None => json,
        };

        let txn = self.db.begin_write().map_err(Self::redb_err)?;
        {
            let mut table = txn.open_table(CREDENTIALS).map_err(Self::redb_err)?;
            table.insert(cred.access_key_id.as_str(), stored.as_slice())
                .map_err(Self::redb_err)?;
        }
        txn.commit().map_err(Self::redb_err)?;
        Ok(())
    }
}

impl CredentialLookup for PersistentStore {
    fn lookup_credential(&self, access_key_id: &str) -> Option<CredentialResult> {
        let cred = self.credential_load(access_key_id).ok()?;
        if !cred.active {
            return None;
        }

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Check if previous secret is still within the grace period
        let previous_secret = match (&cred.previous_secret, cred.previous_secret_expires_ms) {
            (Some(prev), Some(expires)) if now_ms <= expires => Some(prev.clone()),
            _ => None,
        };

        Some(CredentialResult {
            current_secret: cred.secret_access_key,
            previous_secret,
            principal_anchor: cred.principal_anchor,
        })
    }
}

fn base64_encode(bytes: &[u8]) -> String {
    use base64_simd::STANDARD;
    STANDARD.encode_to_string(bytes)
}

#[cfg(test)]
mod tests {
    use kappa_core::crypto::sigv4::CredentialLookup;
    use kappa_core::clock::ntp_lamport::NtpLamportClock;
    use crate::PersistentStore;
    use std::sync::Arc;

    fn new_store() -> (PersistentStore, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let blob_root = tmp.path().join("blobs");
        let db_path = tmp.path().join("state.redb");
        let clock = Arc::new(NtpLamportClock::new());
        let mut config = crate::PersistentStoreConfig::new(blob_root, db_path);
        config.fsync = false;
        let store = PersistentStore::new(config, clock).unwrap();
        (store, tmp)
    }

    #[test]
    fn create_and_lookup() {
        let (store, _tmp) = new_store();
        let cred = store.credential_create("test-principal").unwrap();
        assert!(cred.access_key_id.starts_with("KAPPA"));
        assert!(cred.active);

        let result = store.lookup_credential(&cred.access_key_id).unwrap();
        assert_eq!(result.current_secret, cred.secret_access_key);
        assert!(result.previous_secret.is_none());
        assert_eq!(result.principal_anchor, "test-principal");
    }

    #[test]
    fn deactivate_returns_none() {
        let (store, _tmp) = new_store();
        let cred = store.credential_create("principal").unwrap();
        store.credential_deactivate(&cred.access_key_id).unwrap();
        assert!(store.lookup_credential(&cred.access_key_id).is_none());
    }

    #[test]
    fn rotate_provides_both_secrets() {
        let (store, _tmp) = new_store();
        let cred = store.credential_create("principal").unwrap();
        let old_secret = cred.secret_access_key.clone();

        let rotated = store.credential_rotate(&cred.access_key_id).unwrap();
        assert_ne!(rotated.secret_access_key, old_secret);

        let result = store.lookup_credential(&cred.access_key_id).unwrap();
        assert_eq!(result.current_secret, rotated.secret_access_key);
        assert_eq!(result.previous_secret, Some(old_secret));
    }

    #[test]
    fn missing_credential_returns_none() {
        let (store, _tmp) = new_store();
        assert!(store.lookup_credential("KAPPA_NONEXISTENT").is_none());
    }
}
