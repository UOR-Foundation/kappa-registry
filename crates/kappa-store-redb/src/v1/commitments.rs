//! `COMMITMENTS` values: the coordinates of a content commitment in signed
//! history. Written by the seal for every `ContentPublish` it commits, read
//! by range readers before they trust a chunk root (`content_read`).
//!
//! The chunk root a range reader checks is authenticated by epoch state,
//! not by the row: `COMMITMENTS` maps the identity to the epoch that
//! published its `ContentCommitment` and to the commitment's identity; the
//! epoch root is admitted through its signature, its ledger must carry the
//! `ContentPublish` of that commitment, and the commitment content must
//! hash to its identity and name this identity. Admitted commitments are
//! cached per process.

use redb::ReadableDatabase;

use kappa_store::ContentCommitment;
use kappa_store::epoch::MutationOp;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::work::{Dimension, Meter};

use crate::content_read::ReadView;
use crate::tables::{BLOB_INDEX, COMMITMENTS};

impl ReadView {
    /// The epoch-authenticated commitment for `identity`, admitted once per
    /// process, on `work`. Absent when no published epoch commits it. The
    /// entry's lookup, decryption and the two identities it names are
    /// charged before each is done; the epoch is admitted with its ledger
    /// read and decoded once (`admitted_epoch`), and each mutation compared
    /// is charged before the scan.
    pub(crate) fn resolve_commitment(
        &self,
        identity: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Option<ContentCommitment>, StoreError> {
        if let Some(cached) = self.commitments.get(identity) {
            return Ok(Some(cached.clone()));
        }
        let txn = self.db.begin_read().map_err(crate::error::redb)?;
        let table = txn.open_table(COMMITMENTS).map_err(crate::error::redb)?;
        work.charge_all(&[
            (Dimension::BytesAllocated, identity.key_len() as u64),
            (Dimension::Entries, 1),
        ])?;
        let key = identity.key_bytes();
        let Some(entry) = table.get(key.as_slice()).map_err(crate::error::redb)? else {
            return Ok(None);
        };
        let stored = entry.value().len() as u64;
        work.charge_all(&[
            (Dimension::BytesRead, stored),
            (Dimension::BytesDecoded, stored),
            (Dimension::BytesAllocated, stored),
            (
                Dimension::BytesAllocated,
                crate::encrypted::bound_allocation(COMMITMENTS_CONTEXT, key.len()),
            ),
        ])?;
        let value = self.decrypt(
            &crate::encrypted::bound(COMMITMENTS_CONTEXT, &key),
            entry.value(),
        )?;
        drop(entry);
        let (epoch_key, commitment_key) = split_commitment_entry(&value)?;
        work.charge(
            Dimension::BytesAllocated,
            (epoch_key.len() + commitment_key.len()) as u64,
        )?;
        let epoch_identity = Kappa::from_key_bytes(epoch_key)?;
        let commitment_identity = Kappa::from_key_bytes(commitment_key)?;
        let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        let (_, mutations) = self.admitted_epoch(&index, &epoch_identity, work)?;
        work.charge(Dimension::Entries, mutations.len() as u64)?;
        if !mutations.iter().any(|mutation| {
            mutation.op == MutationOp::ContentPublish && mutation.kappa == commitment_identity
        }) {
            return Err(StoreError::Internal(format!(
                "epoch {epoch_identity} does not commit content {identity}"
            )));
        }
        drop(mutations);
        let bytes = self.epoch_content_from_index(&index, &commitment_identity, None, work)?;
        work.charge(Dimension::BytesDecoded, bytes.len() as u64)?;
        let commitment: ContentCommitment = kappa_store::canonical::from_canonical(&bytes)?;
        if commitment.identity() != identity {
            return Err(StoreError::Internal(format!(
                "commitment {commitment_identity} names {} not {identity}",
                commitment.identity()
            )));
        }
        self.commitments
            .insert(identity.clone(), commitment.clone());
        Ok(Some(commitment))
    }
}

/// Table-encryption context of `COMMITMENTS` values.
pub const COMMITMENTS_CONTEXT: &str = "commitments";

/// `[epoch_len:1][epoch root key bytes][commitment_len:1][commitment key
/// bytes]`. A key longer than one length byte can frame is refused rather
/// than truncated into an entry that decodes as different identities.
pub fn commitment_entry(epoch: &Kappa, commitment: &Kappa) -> Result<Vec<u8>, StoreError> {
    let epoch = epoch.key_bytes();
    let commitment = commitment.key_bytes();
    let framed = |key: &[u8]| {
        u8::try_from(key.len()).map_err(|_| {
            StoreError::Internal(format!(
                "identity of {} key bytes exceeds the commitment entry framing",
                key.len()
            ))
        })
    };
    let mut value = Vec::with_capacity(2 + epoch.len() + commitment.len());
    value.push(framed(&epoch)?);
    value.extend_from_slice(&epoch);
    value.push(framed(&commitment)?);
    value.extend_from_slice(&commitment);
    Ok(value)
}

/// The epoch root and commitment key bytes of an entry, each exactly as
/// long as its length byte states.
pub fn split_commitment_entry(value: &[u8]) -> Result<(&[u8], &[u8]), StoreError> {
    let malformed = || StoreError::Internal("malformed commitment entry".into());
    let (epoch_len, rest) = value.split_first().ok_or_else(malformed)?;
    let epoch_len = usize::from(*epoch_len);
    if rest.len() < epoch_len + 1 {
        return Err(malformed());
    }
    let (epoch, rest) = rest.split_at(epoch_len);
    let (commitment_len, commitment) = rest.split_first().ok_or_else(malformed)?;
    if commitment.len() != usize::from(*commitment_len) {
        return Err(malformed());
    }
    Ok((epoch, commitment))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entries_roundtrip_and_malformed_entries_are_refused() -> Result<(), StoreError> {
        let epoch = Kappa::sha256(b"epoch");
        let commitment = Kappa::sha256(b"commitment");
        let entry = commitment_entry(&epoch, &commitment)?;
        let (epoch_key, commitment_key) = split_commitment_entry(&entry)?;
        assert_eq!(epoch_key, epoch.key_bytes().as_slice());
        assert_eq!(commitment_key, commitment.key_bytes().as_slice());
        assert!(split_commitment_entry(&[]).is_err());
        assert!(split_commitment_entry(&entry[..entry.len() - 1]).is_err());
        let mut extended = entry.clone();
        extended.push(0);
        assert!(split_commitment_entry(&extended).is_err());
        Ok(())
    }
}
