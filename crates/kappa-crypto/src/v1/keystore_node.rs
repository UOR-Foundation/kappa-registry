//! The node signing-key lifecycle, decided by committed backend authority.
//!
//! The key store holds keys; the store's authority history decides which
//! one signs. Every lifecycle operation runs through a [`NodeKeys`] guard,
//! which holds the key store's lifecycle lock. A coordinator that reads the
//! backend's committed authority, commits a rotation, or settles must hold
//! one guard across all of those steps, so evidence it read cannot be made
//! stale by another lifecycle operation of this store before it acts.
//!
//! - [`NodeKeys::candidates`] is non-destructive. It reports every intact
//!   node key, the one `current` names when that pointer is intact, and
//!   damage found. It generates a first key only when the directory holds
//!   no node record and no pointer at all, and makes that key and the
//!   `current` pointer durable before returning it.
//! - [`NodeKeys::settle`] makes the key store agree with an anchor the
//!   backend durably committed. Selection searches intact records only, so
//!   a damaged record that is not the committed one never blocks it.
//!   Activation re-establishes durability of the selected record and the
//!   `current` pointer even when the pointer already names it, so a retry
//!   after a failed synchronization does not take an unconfirmed pointer
//!   for a durable one. Errors up to and including activation are `Err`.
//!   Cleanup then removes the `successor` pointer, every other node entry,
//!   intact or damaged, and every staging file an earlier publication left
//!   (each holds a copy of some key's secret; under the lifecycle guard no
//!   publication is in flight, so all of them are leftovers); its failures
//!   are reported in [`Settlement::cleanup`] and the next settlement
//!   repeats them.
//!
//! [`Settlement`] and [`Staged`] carry the identity of the key store that
//! produced them, so a live identity built from one can require that every
//! later change runs under the same store's custody.
//! - [`NodeKeys::stage_successor`] durably stages the next key without
//!   touching the current record or pointer.

use std::ffi::CString;
use std::sync::{Arc, MutexGuard};

use kappa_types::kappa::Kappa;

use super::{KeyStore, NODE_PREFIX};
use crate::keystore_dir::Cleanup;
use crate::keystore_record::generate;
use crate::{CryptoError, Signer, SigningAuthority};

/// Pointer to the record the node signs with.
const CURRENT: &str = "current";
/// Pointer to the record staged by an unfinished rotation.
const SUCCESSOR: &str = "successor";
/// Hexadecimal digits of a node record name after its prefix.
const NODE_NAME_DIGITS: usize = 32;
/// A pointer holds one node record name.
const MAX_POINTER_BYTES: u64 = 64;

/// Record name of the node key holding `public_key`.
fn node_record(public_key: &[u8]) -> String {
    let digest = blake3::hash(public_key);
    format!("{NODE_PREFIX}{}", &digest.to_hex()[..NODE_NAME_DIGITS])
}

/// Exactly `node-` followed by 32 lowercase hexadecimal digits.
fn valid_node_name(name: &str) -> bool {
    name.strip_prefix(NODE_PREFIX).is_some_and(|digits| {
        digits.len() == NODE_NAME_DIGITS
            && digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn bad_pointer(pointer: &str, reason: &str) -> CryptoError {
    CryptoError::IntegrityFailure {
        path: pointer.into(),
        reason: reason.into(),
    }
}

fn entry_name(name: &str) -> Result<CString, CryptoError> {
    CString::new(name).map_err(|_| CryptoError::InvalidKey {
        reason: format!("entry name {name:?} contains NUL"),
    })
}

/// An intact node record with its signing authority.
struct NodeKey {
    name: String,
    authority: SigningAuthority,
}

/// Node entries found in the directory.
struct Scan {
    intact: Vec<NodeKey>,
    /// Node entries that are malformed or fail validation, by raw name.
    damaged: Vec<(CString, CryptoError)>,
    /// Staging files left by earlier publications.
    stages: Vec<CString>,
    /// Whether either pointer entry exists.
    pointers: bool,
}

/// Outcome of [`NodeKeys::candidates`].
pub struct Candidates {
    /// The key `current` names, when the pointer and its record are intact.
    pub current: Option<SigningAuthority>,
    /// Every intact node key, `current` included.
    pub keys: Vec<SigningAuthority>,
    /// Damage found, described; selection by committed authority may still
    /// succeed when the committed key is intact.
    pub damaged: Vec<String>,
    /// Removal of the staging file when a first key was generated.
    pub cleanup: Cleanup,
}

/// Outcome of [`NodeKeys::settle`].
pub struct Settlement {
    /// The authority the node signs with: the one the backend committed.
    pub authority: SigningAuthority,
    /// Removal of the staged pointer, every other node entry and every
    /// leftover staging file. A failure leaves the active authority correct
    /// and durable; the next settlement repeats it.
    pub cleanup: Cleanup,
    /// [`KeyStore`] that holds `authority`'s key.
    pub(crate) custodian: u64,
}

/// Outcome of [`NodeKeys::stage_successor`].
pub struct Staged {
    /// The durably staged next authority.
    pub authority: SigningAuthority,
    /// Removal of its record's staging file.
    pub cleanup: Cleanup,
    /// [`KeyStore`] that holds `authority`'s key.
    pub(crate) custodian: u64,
}

/// Exclusive access to the node key lifecycle of one key store.
pub struct NodeKeys<'a> {
    store: &'a KeyStore,
    _guard: MutexGuard<'a, ()>,
}

impl KeyStore {
    /// Take the node key lifecycle. Held across every step of an authority
    /// change that reads backend evidence or destroys keys.
    ///
    /// # Errors
    ///
    /// `Io` when a previous lifecycle operation panicked.
    pub fn node_keys(&self) -> Result<NodeKeys<'_>, CryptoError> {
        Ok(NodeKeys {
            store: self,
            _guard: self.exclusive()?,
        })
    }

    /// Load the node record `name` and require its name to be the one its
    /// public key derives.
    fn node_key(&self, name: &str) -> Result<Option<NodeKey>, CryptoError> {
        let Some(record) = self.read_record(name)? else {
            return Ok(None);
        };
        if node_record(&record.public_key) != name {
            return Err(CryptoError::IntegrityFailure {
                path: format!("{name}.key"),
                reason: "record name does not derive from its public key".into(),
            });
        }
        let signer: Arc<dyn Signer> = record.signer(name)?;
        Ok(Some(NodeKey {
            name: name.to_owned(),
            authority: SigningAuthority::new(signer)?,
        }))
    }

    /// The node record a pointer names. `Ok(None)` when the pointer does
    /// not exist; an error when it is damaged or names a missing record.
    fn pointed(&self, pointer: &'static str) -> Result<Option<NodeKey>, CryptoError> {
        let Some(bytes) = self.dir.read(pointer, MAX_POINTER_BYTES)? else {
            return Ok(None);
        };
        let name = std::str::from_utf8(&bytes)
            .ok()
            .filter(|name| valid_node_name(name))
            .ok_or_else(|| bad_pointer(pointer, "pointer does not name a node record"))?;
        self.node_key(name)?
            .map(Some)
            .ok_or_else(|| bad_pointer(pointer, "pointer names a missing node record"))
    }

    /// Classify every node entry. Validation failures are collected, not
    /// returned, so one damaged record cannot hide an intact one.
    fn scan(&self) -> Result<Scan, CryptoError> {
        let mut scan = Scan {
            intact: Vec::new(),
            damaged: Vec::new(),
            stages: Vec::new(),
            pointers: false,
        };
        for raw in self.dir.entries()? {
            let bytes = raw.to_bytes();
            if bytes == CURRENT.as_bytes() || bytes == SUCCESSOR.as_bytes() {
                scan.pointers = true;
                continue;
            }
            if crate::keystore_dir::is_stage_name(bytes) {
                scan.stages.push(raw);
                continue;
            }
            if !bytes.starts_with(NODE_PREFIX.as_bytes()) {
                continue;
            }
            let name = std::str::from_utf8(bytes)
                .ok()
                .and_then(|file| file.strip_suffix(".key"))
                .filter(|name| valid_node_name(name));
            let Some(name) = name else {
                let error = CryptoError::IntegrityFailure {
                    path: raw.to_string_lossy().into_owned(),
                    reason: "malformed node entry name".into(),
                };
                scan.damaged.push((raw, error));
                continue;
            };
            match self.node_key(name) {
                Ok(Some(key)) => scan.intact.push(key),
                Ok(None) => {}
                Err(error) => scan.damaged.push((raw, error)),
            }
        }
        Ok(scan)
    }
}

impl NodeKeys<'_> {
    /// The keys the backend's committed authority may select from, without
    /// changing any existing entry. See the module documentation.
    ///
    /// # Errors
    ///
    /// `IntegrityFailure` when node entries exist but none is intact;
    /// `KeyGeneration` and `Io` from first-key generation.
    pub fn candidates(&self, algorithm: &str) -> Result<Candidates, CryptoError> {
        let store = self.store;
        let scan = store.scan()?;
        let mut damaged: Vec<String> = scan
            .damaged
            .iter()
            .map(|(name, error)| format!("{}: {error}", name.to_string_lossy()))
            .collect();
        if scan.intact.is_empty() {
            if scan.damaged.is_empty() && !scan.pointers {
                return Self::first_key(store, algorithm);
            }
            return Err(CryptoError::IntegrityFailure {
                path: "node records".into(),
                reason: format!("no intact node key; damage: {}", damaged.join("; ")),
            });
        }
        let current = match store.pointed(CURRENT) {
            Ok(current) => current.map(|key| key.authority),
            Err(error) => {
                damaged.push(format!("{CURRENT}: {error}"));
                None
            }
        };
        Ok(Candidates {
            current,
            keys: scan.intact.into_iter().map(|key| key.authority).collect(),
            damaged,
            cleanup: Ok(()),
        })
    }

    /// Generate the node's first key and make it and `current` durable.
    fn first_key(store: &KeyStore, algorithm: &str) -> Result<Candidates, CryptoError> {
        let (record, signer) = generate(algorithm)?;
        let name = node_record(&record.public_key);
        let cleanup = store.write_record(&name, &record)?;
        store.dir.publish_replace(CURRENT, name.as_bytes())?;
        let authority = SigningAuthority::new(signer)?;
        Ok(Candidates {
            current: Some(authority.clone()),
            keys: vec![authority],
            damaged: Vec::new(),
            cleanup,
        })
    }

    /// Make the key store agree with `committed`, the anchor the backend's
    /// durable authority history ends at, and return the authority the node
    /// signs with. See the module documentation.
    ///
    /// # Errors
    ///
    /// `InvalidKey` when no record holds the committed key;
    /// `IntegrityFailure` when it may be among damaged records; `Io` from
    /// activation.
    pub fn settle(&self, committed: &Kappa) -> Result<Settlement, CryptoError> {
        let store = self.store;
        let scan = store.scan()?;
        let mut selected = None;
        let mut retire = Vec::new();
        for key in scan.intact {
            if selected.is_none() && key.authority.anchor() == committed {
                selected = Some(key);
            } else {
                retire.push(entry_name(&format!("{}.key", key.name))?);
            }
        }
        let Some(selected) = selected else {
            if scan.damaged.is_empty() {
                return Err(CryptoError::InvalidKey {
                    reason: format!(
                        "the store's committed authority {committed} has no key in this key store"
                    ),
                });
            }
            let damage: Vec<String> = scan
                .damaged
                .iter()
                .map(|(name, error)| format!("{}: {error}", name.to_string_lossy()))
                .collect();
            return Err(CryptoError::IntegrityFailure {
                path: "node records".into(),
                reason: format!(
                    "the store's committed authority {committed} has no intact key; damage: {}",
                    damage.join("; ")
                ),
            });
        };
        retire.extend(scan.damaged.into_iter().map(|(name, _)| name));
        retire.extend(scan.stages);

        // Activation: durability is re-established, never inferred.
        let record = format!("{}.key", selected.name);
        store.dir.confirm(&record)?;
        let active = match store.dir.read(CURRENT, MAX_POINTER_BYTES) {
            Ok(Some(bytes)) => bytes.as_slice() == selected.name.as_bytes(),
            Ok(None) | Err(CryptoError::IntegrityFailure { .. }) => false,
            Err(error) => return Err(error),
        };
        if active {
            store.dir.confirm(CURRENT)?;
        } else {
            store
                .dir
                .publish_replace(CURRENT, selected.name.as_bytes())?;
        }

        retire.push(entry_name(SUCCESSOR)?);
        let cleanup = store.dir.remove_all(&retire);
        Ok(Settlement {
            authority: selected.authority,
            cleanup,
            custodian: store.id,
        })
    }

    /// Generate and durably stage the next node key, leaving the current
    /// record and pointer untouched. After the backend commits or rejects
    /// the rotation, settle with its committed authority: success promotes
    /// the staged key, a rotation that did not commit discards it.
    ///
    /// # Errors
    ///
    /// `KeyGeneration` when a successor is already staged (settle first)
    /// or entropy is unavailable; `InvalidKey` or `IntegrityFailure` when
    /// there is no intact current key to succeed.
    pub fn stage_successor(&self, algorithm: &str) -> Result<Staged, CryptoError> {
        let store = self.store;
        if store.dir.read(SUCCESSOR, MAX_POINTER_BYTES)?.is_some() {
            return Err(CryptoError::KeyGeneration {
                algorithm: algorithm.into(),
                reason: "a successor key is already staged by an unresolved rotation".into(),
            });
        }
        if store.pointed(CURRENT)?.is_none() {
            return Err(CryptoError::InvalidKey {
                reason: "no current node key to succeed; settle to the committed authority first"
                    .into(),
            });
        }
        let (record, signer) = generate(algorithm)?;
        let name = node_record(&record.public_key);
        let cleanup = store.write_record(&name, &record)?;
        store.dir.publish_replace(SUCCESSOR, name.as_bytes())?;
        Ok(Staged {
            authority: SigningAuthority::new(signer)?,
            cleanup,
            custodian: store.id,
        })
    }

    /// Identity of the key store this guard holds custody of.
    pub(crate) const fn custodian(&self) -> u64 {
        self.store.id
    }

    /// The staged successor, if a rotation is unresolved.
    ///
    /// # Errors
    ///
    /// `IntegrityFailure` for a damaged pointer or record.
    pub fn successor(&self) -> Result<Option<SigningAuthority>, CryptoError> {
        Ok(self.store.pointed(SUCCESSOR)?.map(|key| key.authority))
    }
}

#[cfg(test)]
pub(super) fn record_name(public_key: &[u8]) -> String {
    node_record(public_key)
}
