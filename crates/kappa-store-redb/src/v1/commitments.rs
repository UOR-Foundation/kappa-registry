//! `COMMITMENTS` values: the coordinates of a content commitment in signed
//! history. Written by the seal for every `ContentPublish` it commits, read
//! by range readers before they trust a chunk root (`content_read`).

use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;

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
