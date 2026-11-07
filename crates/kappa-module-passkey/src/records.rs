//! Key records in the store.
//!
//! A record is a JSON blob, content addressed like everything else in the
//! registry. Tags in the passkey namespace index it:
//!
//!   credential/<credential>      the record for a credential (first write wins)
//!   account/<account>/<key>      every record of an account
//!   revoked/<key>                the revocation evidence for a key
//!
//! The namespace sits under the reserved `kappa/identity` prefix, so the
//! generic `/v2/` routes cannot write these tags without `_root` authority:
//! only the verified `/passkey/` routes do.

use kappa_core::kappa::Axis;
use kappa_core::store::KappaStore;
use kappa_core::types::{NamespaceRef, StoreError, TagUpdate};
use serde::{Deserialize, Serialize};

use crate::error::PasskeyError;
use crate::webauthn::Assertion;

pub const KEY_SPEC: &str = "prism/identity/key/1";
pub const REVOCATION_SPEC: &str = "prism/identity/revocation/1";

/// The longest binding chain a key may sit at the end of.
pub const MAX_CHAIN: usize = 5;

/// A key record as prism/identity/1 defines it. Field order is the
/// protocol's, and serde_json keeps it, so the stored bytes read as written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRecord {
    pub spec: String,
    pub key: String,
    pub account: String,
    pub credential: String,
    pub alg: i64,
    pub spki: String,
    pub origin: String,
    pub created: u64,
    pub binding: Option<Assertion>,
}

/// A record and the exact bytes it is stored as.
pub struct Stored {
    pub record: KeyRecord,
    pub bytes: Vec<u8>,
}

fn credential_tag(credential: &str) -> String {
    format!("credential/{credential}")
}

fn account_prefix(account: &str) -> String {
    format!("account/{account}/")
}

fn revoked_tag(key: &str) -> String {
    format!("revoked/{key}")
}

fn read(store: &dyn KappaStore, kappa: &str) -> Result<Stored, PasskeyError> {
    let bytes = store.blob_get_verified(kappa)?;
    let record = serde_json::from_slice(&bytes).map_err(|e| {
        PasskeyError::Store(StoreError::Rejected(format!("key record {kappa}: {e}")))
    })?;
    Ok(Stored { record, bytes })
}

fn tag(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    name: &str,
) -> Result<Option<String>, PasskeyError> {
    match store.tag_get(ns, name) {
        Ok(entry) => Ok(Some(entry.kappa)),
        Err(StoreError::NotFound(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// The record registered for `credential`, revoked or not.
pub fn by_credential(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    credential: &str,
) -> Result<Option<Stored>, PasskeyError> {
    tag(store, ns, &credential_tag(credential))?
        .map(|kappa| read(store, &kappa))
        .transpose()
}

/// Every record of `account`, in key order.
pub fn of_account(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    account: &str,
) -> Result<Vec<KeyRecord>, PasskeyError> {
    let mut entries = store.tag_prefix(ns, &account_prefix(account))?;
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    entries
        .iter()
        .map(|entry| read(store, &entry.kappa).map(|stored| stored.record))
        .collect()
}

pub fn is_revoked(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    key: &str,
) -> Result<bool, PasskeyError> {
    Ok(tag(store, ns, &revoked_tag(key))?.is_some())
}

/// How many bindings lead from the account's first key to `record`.
/// Stops counting past `MAX_CHAIN`, which is already too long.
pub fn chain_length(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    record: &KeyRecord,
) -> Result<usize, PasskeyError> {
    let mut length = 0;
    let mut binder = record.binding.as_ref().map(|b| b.credential.clone());
    while let Some(credential) = binder {
        length += 1;
        if length > MAX_CHAIN {
            break;
        }
        let parent = by_credential(store, ns, &credential)?.ok_or_else(|| {
            PasskeyError::Binding("a key in the binding chain is not registered".into())
        })?;
        binder = parent.record.binding.map(|b| b.credential);
    }
    Ok(length)
}

/// Store `record` and index it, atomically. Both tags must be new, so a
/// credential or key is registered once and a race has one winner.
pub fn insert(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    record: &KeyRecord,
) -> Result<(), PasskeyError> {
    let bytes = serde_json::to_vec(record)
        .map_err(|e| PasskeyError::Store(StoreError::Rejected(e.to_string())))?;
    let kappa = store.ingest_compute(Axis::Sha256, &bytes)?.kappa;
    let updates = [
        TagUpdate {
            name: credential_tag(&record.credential),
            kappa: kappa.clone(),
            expected_version: Some(0),
        },
        TagUpdate {
            name: format!("{}{}", account_prefix(&record.account), record.key),
            kappa,
            expected_version: Some(0),
        },
    ];
    match store.tag_set_batch(ns, &updates) {
        Ok(()) => Ok(()),
        Err(StoreError::Conflict(_)) => Err(PasskeyError::Exists),
        Err(e) => Err(e.into()),
    }
}

/// Record `key` as revoked with `evidence`. Returns false when it already was.
pub fn revoke(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    key: &str,
    evidence: &[u8],
) -> Result<bool, PasskeyError> {
    let kappa = store.ingest_compute(Axis::Sha256, evidence)?.kappa;
    let update = TagUpdate {
        name: revoked_tag(key),
        kappa,
        expected_version: Some(0),
    };
    match store.tag_set_batch(ns, &[update]) {
        Ok(()) => Ok(true),
        Err(StoreError::Conflict(_)) => Ok(false),
        Err(e) => Err(e.into()),
    }
}
