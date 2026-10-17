//! Tag fingerprints and counts committed in the same transaction as tag data.

use kappa_types::{Kappa, NamespaceRef, StateDigest, StoreError};
use redb::ReadableTable;

use crate::{PersistentStore, tables::LIVE_TAG_STATE};

/// The AEAD context of the `LIVE_TAG_STATE` row of namespace `ns`.
fn state_context(ns: &[u8]) -> String {
    crate::encrypted::bound("live_tag_state", ns)
}

fn decode(bytes: &[u8]) -> Result<(StateDigest, u64), StoreError> {
    if bytes.len() != 40 {
        return Err(StoreError::Internal("invalid live tag state length".into()));
    }
    let digest = bytes[..32]
        .try_into()
        .map_err(|_| StoreError::Internal("live tag digest decode".into()))?;
    let count = bytes[32..]
        .try_into()
        .map_err(|_| StoreError::Internal("live tag count decode".into()))?;
    Ok((StateDigest::from_bytes(digest), u64::from_be_bytes(count)))
}

impl PersistentStore {
    /// The live tag state of `ns` as `states`, a snapshot's or an
    /// execution's, holds it: empty before the first tag.
    fn tag_state_from(
        &self,
        states: &impl ReadableTable<&'static [u8], &'static [u8]>,
        ns: &NamespaceRef,
    ) -> Result<(StateDigest, u64), StoreError> {
        match states.get(ns.id().as_slice()).map_err(crate::error::redb)? {
            Some(value) => decode(&self.decrypt_bytes(&state_context(ns.id()), value.value())?),
            None => Ok((StateDigest::default(), 0)),
        }
    }

    pub(crate) fn persisted_tag_state(
        &self,
        ns: &NamespaceRef,
    ) -> Result<([u8; 32], u64), StoreError> {
        let snapshot = self.namespace_snapshot(ns)?;
        let (digest, count) = self.tag_state_from(&snapshot.table(LIVE_TAG_STATE)?, ns)?;
        Ok((digest.into_bytes(), count))
    }

    pub(crate) fn tag_state_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
    ) -> Result<(StateDigest, u64), StoreError> {
        let states = txn.open_table(LIVE_TAG_STATE).map_err(crate::error::redb)?;
        self.tag_state_from(&states, ns)
    }

    pub(crate) fn write_tag_state_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        uuid: &[u8; 16],
        digest: StateDigest,
        count: u64,
    ) -> Result<(), StoreError> {
        let mut bytes = [0; 40];
        bytes[..32].copy_from_slice(digest.as_bytes());
        bytes[32..].copy_from_slice(&count.to_be_bytes());
        let encrypted = self.encrypt_bytes(&state_context(uuid), &bytes)?;
        txn.open_table(LIVE_TAG_STATE)
            .map_err(crate::error::redb)?
            .insert(uuid.as_slice(), encrypted.as_slice())
            .map_err(crate::error::redb)?;
        Ok(())
    }

    pub(crate) fn update_tag_state_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        name: &str,
        old: Option<&Kappa>,
        new: Option<&Kappa>,
    ) -> Result<(), StoreError> {
        let (mut digest, mut count) = self.tag_state_in_txn(txn, ns)?;
        if let Some(old) = old {
            digest.remove(name, old);
            count = count
                .checked_sub(1)
                .ok_or_else(|| StoreError::Internal("live tag count underflow".into()))?;
        }
        if let Some(new) = new {
            digest.insert(name, new);
            count = count
                .checked_add(1)
                .ok_or_else(|| StoreError::Internal("live tag count exhausted".into()))?;
        }
        self.write_tag_state_in_txn(txn, ns.id(), digest, count)
    }
}
