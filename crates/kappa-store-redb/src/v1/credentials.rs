use dashmap::DashMap;
use dcbor::prelude::*;
use redb::{ReadableDatabase, ReadableTable};

use kappa_crypto::sigv4::{CredentialLookup, CredentialResult};
use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::clock::ClockMs;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;

use crate::PersistentStore;
use crate::tables::CREDENTIALS;

/// Grace period for rotation: the previous secret remains valid
/// for this many milliseconds after rotation.
const ROTATION_GRACE_MS: i64 = 300_000;

/// Internal storage format for credentials.
///
/// Serialized to canonical dCBOR for redb persistence. The hot
/// path reads from the in-memory `DashMap`, never from redb.
/// Mutations write through to both the `DashMap` and redb.
///
/// CBOR key assignments (PERMANENT):
///   0: `access_key_id`
///   1: `secret_access_key`
///   2: `previous_secret`
///   3: `previous_secret_expires_ms`
///   4: `principal_anchor`
///   5: `created_ms`
///   6: active
#[derive(Clone, CBORCodable)]
pub struct Credential {
    #[cbor(n = 0)]
    pub access_key_id: String,
    #[cbor(n = 1)]
    pub secret_access_key: String,
    #[cbor(n = 2)]
    pub previous_secret: Option<String>,
    #[cbor(n = 3)]
    pub previous_secret_expires_ms: Option<i64>,
    #[cbor(n = 4)]
    pub principal_anchor: Kappa,
    #[cbor(n = 5)]
    pub created_ms: i64,
    #[cbor(n = 6)]
    pub active: bool,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credential")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "previous_secret",
                &self.previous_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "previous_secret_expires_ms",
                &self.previous_secret_expires_ms,
            )
            .field("principal_anchor", &self.principal_anchor)
            .field("created_ms", &self.created_ms)
            .field("active", &self.active)
            .finish()
    }
}

/// In-memory credential cache with redb write-through.
///
/// Hot path: `DashMap` lookup. Zero I/O, zero deserialization.
/// Cold path: redb write on create/rotate/deactivate.
/// Startup: load all credentials from redb into the `DashMap`.
pub struct CredentialCache {
    cache: DashMap<String, Credential>,
}

impl CredentialCache {
    /// Load all credentials from redb into memory.
    /// Called once at server startup.
    pub fn load_from_store(store: &PersistentStore) -> Result<Self, StoreError> {
        let cache = DashMap::new();
        let txn = store.registry.begin_read().map_err(crate::error::redb)?;
        let table = match txn.open_table(CREDENTIALS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Self { cache }),
            Err(e) => return Err(crate::error::redb(e)),
        };

        for entry in table.iter().map_err(crate::error::redb)? {
            let (key, value) = entry.map_err(crate::error::redb)?;
            let decrypted = match &store.table_encryptor {
                Some(enc) => enc.decrypt_value(key.value(), value.value()).map_err(|e| {
                    StoreError::Internal(format!("credential decrypt on load: {e}"))
                })?,
                None => value.value().to_vec(),
            };
            match from_canonical::<Credential>(&decrypted) {
                Ok(cred) => {
                    cache.insert(cred.access_key_id.clone(), cred);
                }
                Err(e) => {
                    tracing::warn!(
                        key = key.value(),
                        error = %e,
                        "skipping corrupt credential on load",
                    );
                }
            }
        }

        Ok(Self { cache })
    }

    /// Get a credential by access key ID. In-memory only.
    pub fn get(&self, access_key_id: &str) -> Option<Credential> {
        self.cache.get(access_key_id).map(|r| r.value().clone())
    }

    /// Insert or update a credential in the cache.
    /// Called after a successful redb write.
    fn update(&self, cred: &Credential) {
        self.cache.insert(cred.access_key_id.clone(), cred.clone());
    }
}

impl PersistentStore {
    pub fn credential_create(
        &self,
        principal: &Kappa,
        now: ClockMs,
    ) -> Result<Credential, StoreError> {
        let mut access_key_bytes = [0u8; 10];
        getrandom::fill(&mut access_key_bytes)
            .map_err(|e| StoreError::Internal(format!("getrandom: {e}")))?;
        let access_key_id = format!("KAPPA{}", hex::encode(access_key_bytes).to_uppercase());

        let mut secret_bytes = [0u8; 30];
        getrandom::fill(&mut secret_bytes)
            .map_err(|e| StoreError::Internal(format!("getrandom: {e}")))?;
        let secret_access_key = base64_simd::STANDARD.encode_to_string(secret_bytes);

        let cred = Credential {
            access_key_id,
            secret_access_key,
            previous_secret: None,
            previous_secret_expires_ms: None,
            principal_anchor: principal.clone(),
            created_ms: now.as_i64(),
            active: true,
        };

        self.credential_persist(&cred)?;
        if let Some(ref cc) = self.credential_cache {
            cc.update(&cred);
        }
        Ok(cred)
    }

    pub fn credential_rotate(
        &self,
        access_key_id: &str,
        now: ClockMs,
    ) -> Result<Credential, StoreError> {
        let mut cred = self.credential_load(access_key_id)?;

        cred.previous_secret = Some(cred.secret_access_key.clone());
        cred.previous_secret_expires_ms =
            Some(now.as_i64().checked_add(ROTATION_GRACE_MS).ok_or_else(|| {
                StoreError::Rejected("credential rotation deadline overflow".into())
            })?);

        let mut new_secret_bytes = [0u8; 30];
        getrandom::fill(&mut new_secret_bytes)
            .map_err(|e| StoreError::Internal(format!("getrandom: {e}")))?;
        cred.secret_access_key = base64_simd::STANDARD.encode_to_string(new_secret_bytes);

        self.credential_persist(&cred)?;
        if let Some(ref cc) = self.credential_cache {
            cc.update(&cred);
        }
        Ok(cred)
    }

    pub fn credential_deactivate(&self, access_key_id: &str) -> Result<(), StoreError> {
        let mut cred = self.credential_load(access_key_id)?;
        cred.active = false;
        self.credential_persist(&cred)?;
        if let Some(ref cc) = self.credential_cache {
            cc.update(&cred);
        }
        Ok(())
    }

    /// Load a credential. Tries the in-memory cache first,
    /// falls back to redb if the cache is not initialized.
    fn credential_load(&self, access_key_id: &str) -> Result<Credential, StoreError> {
        if let Some(ref cc) = self.credential_cache
            && let Some(cred) = cc.get(access_key_id)
        {
            return Ok(cred);
        }
        self.credential_load_from_redb(access_key_id)
    }

    /// Load directly from redb. Used during cache initialization
    /// and as fallback when the cache doesn't have the entry.
    fn credential_load_from_redb(&self, access_key_id: &str) -> Result<Credential, StoreError> {
        let txn = self.registry.begin_read().map_err(crate::error::redb)?;
        let table = txn.open_table(CREDENTIALS).map_err(crate::error::redb)?;
        let raw = table
            .get(access_key_id)
            .map_err(crate::error::redb)?
            .ok_or_else(|| StoreError::NotFound(format!("credential {access_key_id}")))?;

        let decrypted = self.decrypt_bytes(access_key_id, raw.value())?;

        from_canonical::<Credential>(&decrypted)
            .map_err(|e| StoreError::Internal(format!("credential decode: {e}")))
    }

    /// Persist a credential to redb. The `DashMap` update happens
    /// at the call site after this succeeds.
    fn credential_persist(&self, cred: &Credential) -> Result<(), StoreError> {
        let cbor_bytes = canonical_bytes(cred);

        let stored = self.encrypt_bytes(&cred.access_key_id, &cbor_bytes)?;

        let txn = self.registry.begin_write().map_err(crate::error::redb)?;
        {
            let mut table = txn.open_table(CREDENTIALS).map_err(crate::error::redb)?;
            table
                .insert(cred.access_key_id.as_str(), stored.as_slice())
                .map_err(crate::error::redb)?;
        }
        Self::commit_write(txn)
    }
}

impl CredentialLookup for PersistentStore {
    fn lookup_credential(&self, access_key_id: &str, now: ClockMs) -> Option<CredentialResult> {
        // Hot path: DashMap lookup. Zero I/O.
        let cred = if let Some(ref cc) = self.credential_cache {
            cc.get(access_key_id)?
        } else {
            self.credential_load(access_key_id).ok()?
        };

        if !cred.active {
            return None;
        }

        let previous_secret = match (&cred.previous_secret, cred.previous_secret_expires_ms) {
            (Some(prev), Some(expires)) if now.as_i64() <= expires => Some(prev.clone()),
            _ => None,
        };

        Some(CredentialResult {
            current_secret: cred.secret_access_key.into(),
            previous_secret: previous_secret.map(Into::into),
            principal_anchor: cred.principal_anchor,
        })
    }
}
