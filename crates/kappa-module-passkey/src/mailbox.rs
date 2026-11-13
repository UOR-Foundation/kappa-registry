//! The Prism mailbox (prism/identity/3).
//!
//! A Prism id (stitch's Prism id) keeps no record here. Its devices leave
//! opaque messages under names only their holders can derive: a recovery
//! escrow under the locator its recovery code derives, and sealed sync
//! messages under the sync topic a private boundary key derives. The
//! registry stores the bytes, content addressed, and returns the newest
//! ones for a name. It reads none of them: every message is sealed, and
//! every record inside one is signed and checked by the device that reads
//! it, so a hostile registry can only withhold.
//!
//! A topic's index is a JSON array of message kappas, newest last, stored as
//! a blob and named by one tag, `topic/<name>`. Appends race through the
//! tag's version, so concurrent posts both land or one retries.

use kappa_core::kappa::Axis;
use kappa_core::store::KappaStore;
use kappa_core::types::{NamespaceRef, StoreError, TagUpdate};

use crate::error::PasskeyError;

/// The namespace holding mailbox indexes. Under the reserved
/// `kappa/identity` prefix, so only these routes write it.
pub const MAILBOX_NAMESPACE: &str = "kappa/identity/prism";

/// Messages a topic keeps; older ones fall out of its index.
pub const KEEP: usize = 64;

/// Largest message a topic accepts.
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;

/// Appends that lose a version race retry this many times, then the caller
/// is told to try again.
const RETRIES: usize = 8;

/// The longest scheme a topic name may carry before its colon.
const MAX_SCHEME_LEN: usize = 32;

/// A topic name is `<scheme>:<64 lowercase hex>`, the scheme lowercase
/// letters, digits and hyphens: `sha256:` (an escrow locator),
/// `prism-sync:`, `prism-rendezvous:`.
pub fn check_topic(topic: &str) -> Result<(), PasskeyError> {
    let malformed = || {
        PasskeyError::Request(format!(
            "topic {topic:?} is not <scheme>:<64 lowercase hex characters>"
        ))
    };
    let (scheme, hex) = topic.split_once(':').ok_or_else(malformed)?;
    let scheme_ok = !scheme.is_empty()
        && scheme.len() <= MAX_SCHEME_LEN
        && scheme
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    let hex_ok = hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if scheme_ok && hex_ok {
        Ok(())
    } else {
        Err(malformed())
    }
}

fn index_tag(topic: &str) -> String {
    format!("topic/{topic}")
}

/// The topic's index and the tag version it was read at (0: no index yet).
fn index(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    topic: &str,
) -> Result<(u64, Vec<String>), PasskeyError> {
    match store.tag_get(ns, &index_tag(topic)) {
        Ok(entry) => {
            let bytes = store.blob_get_verified(&entry.kappa)?;
            let kappas: Vec<String> = serde_json::from_slice(&bytes).map_err(|e| {
                PasskeyError::Store(StoreError::Rejected(format!(
                    "mailbox index {}: {e}",
                    entry.kappa
                )))
            })?;
            Ok((entry.version, kappas))
        }
        Err(StoreError::NotFound(_)) => Ok((0, Vec::new())),
        Err(e) => Err(e.into()),
    }
}

/// Keep `message` under `topic`. Returns true when it is new to the topic,
/// false when the topic already holds those exact bytes.
pub fn post(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    topic: &str,
    message: &[u8],
) -> Result<bool, PasskeyError> {
    check_topic(topic)?;
    if message.is_empty() {
        return Err(PasskeyError::Request(
            "a message has at least one byte".into(),
        ));
    }
    if message.len() > MAX_MESSAGE_BYTES {
        return Err(PasskeyError::Request(format!(
            "a message is at most {MAX_MESSAGE_BYTES} bytes"
        )));
    }
    let kappa = store.ingest_compute(Axis::Sha256, message)?.kappa;
    for _ in 0..RETRIES {
        let (version, mut kappas) = index(store, ns, topic)?;
        if kappas.contains(&kappa) {
            return Ok(false);
        }
        kappas.push(kappa.clone());
        if kappas.len() > KEEP {
            let excess = kappas.len() - KEEP;
            kappas.drain(..excess);
        }
        let bytes = serde_json::to_vec(&kappas)
            .map_err(|e| PasskeyError::Store(StoreError::Rejected(e.to_string())))?;
        let index_kappa = store.ingest_compute(Axis::Sha256, &bytes)?.kappa;
        let update = TagUpdate {
            name: index_tag(topic),
            kappa: index_kappa,
            expected_version: Some(version),
        };
        match store.tag_set_batch(ns, &[update]) {
            Ok(()) => return Ok(true),
            Err(StoreError::Conflict(_)) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(PasskeyError::Rate)
}

/// The messages `topic` keeps, oldest first.
pub fn messages(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    topic: &str,
) -> Result<Vec<Vec<u8>>, PasskeyError> {
    check_topic(topic)?;
    let (version, kappas) = index(store, ns, topic)?;
    if version == 0 {
        return Err(PasskeyError::UnknownTopic);
    }
    kappas
        .iter()
        .map(|kappa| store.blob_get_verified(kappa).map_err(PasskeyError::from))
        .collect()
}
