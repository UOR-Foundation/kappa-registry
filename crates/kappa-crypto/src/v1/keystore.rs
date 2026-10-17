//! Durable private keys, owned exclusively by one [`KeyStore`].
//!
//! Ownership and filesystem identity are established by `keystore_dir`:
//! one retained directory descriptor owned by the process's effective user,
//! an exclusive lock held for the store's lifetime, and recovery of staging
//! files an interrupted publication left behind. Lifecycle operations of
//! one store are serialized by its mutex.
//!
//! Records: each key is one immutable record file (see `keystore_record`)
//! published without replacing an existing entry: written to a fresh
//! owner-only staging file created exclusively, synchronized, hard-linked
//! to its final name, and the directory synchronized. A crash leaves either
//! no record or a complete one plus, possibly, a staging file removed at the
//! next open. Every load re-validates the record against the signer it
//! reconstructs.
//!
//! Node signing keys follow the lifecycle in `keystore_node`, driven by the
//! backend's committed authority through a [`NodeKeys`] guard. Retiring a
//! record unlinks the key store's copy; it is not cryptographic erasure of
//! the storage medium, and signers already handed out keep working until
//! dropped: publication authority is enforced by the store's authority
//! history, not by file deletion.

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use zeroize::Zeroizing;

use super::CryptoError;
use super::keystore_dir::{Cleanup, KeyDir};
use super::keystore_record::{KeyRecord, MAX_RECORD_BYTES};

#[path = "keystore_node.rs"]
mod node_keys;
pub use node_keys::{Candidates, NodeKeys, Settlement, Staged};

/// Load an operator-provisioned binary root key with bounded admission:
/// at most 33 bytes are read, and exactly 32 are required.
pub fn load_root_key(path: &Path) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
    let mut file = fs::File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(CryptoError::InvalidKey {
            reason: "root key source is not a regular file".into(),
        });
    }
    let mut bytes = Zeroizing::new([0u8; 33]);
    let mut count = 0;
    while count < bytes.len() {
        match file.read(&mut bytes[count..]) {
            Ok(0) => break,
            Ok(n) => count += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    if count != 32 {
        return Err(CryptoError::InvalidKey {
            reason: "root key must contain exactly 32 binary bytes".into(),
        });
    }
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&bytes[..32]);
    Ok(key)
}

/// Prefix reserved for node signing-key records.
pub(super) const NODE_PREFIX: &str = "node-";

/// A named record outside the node lifecycle: 1 to 64 characters of
/// lowercase ASCII letters, digits, `_` and `-`, starting with a letter or
/// digit, and never in the reserved node namespace.
fn valid_named(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && !name.starts_with(NODE_PREFIX)
}

pub struct KeyStore {
    keys_dir: PathBuf,
    dir: KeyDir,
    lifecycle: Mutex<()>,
    /// Identifies this open store among every store opened by the process,
    /// so authorities it hands out can be tied back to its custody.
    id: u64,
    /// Opaque owner of the filesystem scope holding `keys_dir`, retained
    /// for the store's lifetime so a store that escapes its creator (into a
    /// detached worker, an `Arc`, an application context) keeps the scope
    /// alive. Fixture acquisition supplies it; a production key store in an
    /// operator-managed directory has none. Declared last so the directory
    /// descriptor and its lock are released before the scope can go.
    scope: Option<Arc<dyn Send + Sync>>,
}

/// Source of [`KeyStore::id`].
static NEXT_STORE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl KeyStore {
    /// Open, creating if absent, the key store in `keys_dir` and take
    /// exclusive ownership of it.
    ///
    /// # Errors
    ///
    /// `Io` when the directory cannot be created, opened or locked (another
    /// owner holds it), is a symlink, or is not owned by the effective
    /// user; or when orphaned staging files cannot be removed.
    pub fn new(keys_dir: PathBuf) -> Result<Self, CryptoError> {
        let dir = KeyDir::open(&keys_dir)?;
        Ok(Self {
            keys_dir,
            dir,
            lifecycle: Mutex::new(()),
            id: NEXT_STORE.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            scope: None,
        })
    }

    /// Retain `scope`, the owner of the filesystem scope holding this
    /// store's directory, for as long as the store lives.
    #[must_use]
    pub fn retaining(mut self, scope: Arc<dyn Send + Sync>) -> Self {
        self.scope = Some(scope);
        self
    }

    /// The path the store was opened at. Operations do not re-resolve it.
    pub fn keys_dir(&self) -> &Path {
        &self.keys_dir
    }

    /// Serialize one lifecycle operation of this store.
    fn exclusive(&self) -> Result<MutexGuard<'_, ()>, CryptoError> {
        self.lifecycle.lock().map_err(|_| {
            CryptoError::Io(io::Error::other(
                "key store lifecycle lock poisoned by an interrupted operation",
            ))
        })
    }

    #[cfg(test)]
    pub(super) const fn dir(&self) -> &KeyDir {
        &self.dir
    }

    /// Read and validate the record `name`; `None` when it does not exist.
    fn read_record(&self, name: &str) -> Result<Option<KeyRecord>, CryptoError> {
        self.dir
            .read(&format!("{name}.key"), MAX_RECORD_BYTES)?
            .map(|bytes| KeyRecord::decode(&bytes, name))
            .transpose()
    }

    /// Publish `record` as `name`. `Ok` means the record is durable; the
    /// returned [`Cleanup`] reports removal of its staging file.
    fn write_record(&self, name: &str, record: &KeyRecord) -> Result<Cleanup, CryptoError> {
        self.dir
            .publish_new(&format!("{name}.key"), &record.encode()?)
    }

    /// The Ed25519 record `name`, generated and stored on first use. For
    /// named keys outside the node signing lifecycle (the AKD VRF key).
    ///
    /// # Errors
    ///
    /// `InvalidKey` for a name outside the named-record syntax or a record
    /// of another algorithm; `IntegrityFailure` for a damaged record;
    /// `KeyGeneration` when entropy is unavailable; `Io` when the record
    /// cannot be made durable.
    pub fn load_or_generate_ed25519(
        &self,
        name: &str,
    ) -> Result<super::ed25519::Ed25519Signer, CryptoError> {
        if !valid_named(name) {
            return Err(CryptoError::InvalidKey {
                reason: format!("'{name}' is not a valid named key"),
            });
        }
        let _guard = self.exclusive()?;
        let record = match self.read_record(name)? {
            Some(record) => record,
            None => {
                let (record, _) = super::keystore_record::generate("ed25519")?;
                if let Err(error) = self.write_record(name, &record)? {
                    // The record is durable. Its staging copy, holding the
                    // same secret owner-only inside this directory, is
                    // removed when the store next opens.
                    tracing::warn!(%error, key = name, "staging file of a new key not removed");
                }
                record
            }
        };
        if record.algorithm != "ed25519" {
            return Err(CryptoError::InvalidKey {
                reason: format!("key '{name}' is {}, expected ed25519", record.algorithm),
            });
        }
        let seed: &[u8; 32] =
            record
                .secret
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidKey {
                    reason: format!("key '{name}' secret is not 32 bytes"),
                })?;
        super::ed25519::Ed25519Signer::from_bytes(seed)
    }
}

#[cfg(test)]
#[path = "keystore_tests.rs"]
mod tests;
