//! The authenticated envelope of one content chunk.
//!
//! A chunk is encrypted under a context bound to the allocation's
//! publication identity and the chunk's ordinal (`content_prepare`), so a
//! chunk can be neither moved within an allocation nor spliced in from
//! another allocation of the same content. The envelope is
//! `[salt:32][base nonce:8][plaintext size:8][frames]`; the salt derives a
//! per-publication key so the same context never reuses a key stream.
//! Delivery integrity against the committed content is separate: every
//! delivered chunk is also verified against the epoch-committed chunk
//! root (`chunk_integrity`).

use kappa_crypto::aead::BlobEncryptor;
use kappa_types::StoreError;

pub fn encrypt(
    encryptor: &BlobEncryptor,
    context: &str,
    bytes: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt)
        .map_err(|error| StoreError::Internal(format!("publication entropy: {error}")))?;
    let publication = encryptor
        .derive_publication(&salt, context)
        .map_err(crate::error::crypto)?;
    let encrypted = publication
        .encrypt(context, bytes)
        .map_err(crate::error::crypto)?;
    let mut stored = Vec::with_capacity(48 + encrypted.disk_bytes.len());
    stored.extend_from_slice(&salt);
    stored.extend_from_slice(&encrypted.base_nonce);
    stored.extend_from_slice(&encrypted.plaintext_size.to_be_bytes());
    stored.extend_from_slice(&encrypted.disk_bytes);
    Ok(stored)
}

pub fn decrypt(
    encryptor: &BlobEncryptor,
    context: &str,
    stored: &[u8],
) -> Result<Vec<u8>, StoreError> {
    if stored.len() < 48 {
        return Err(StoreError::Internal(
            "truncated encrypted chunk envelope".into(),
        ));
    }
    let salt = stored[..32]
        .try_into()
        .map_err(|_| StoreError::Internal("invalid publication salt".into()))?;
    let publication = encryptor
        .derive_publication(salt, context)
        .map_err(crate::error::crypto)?;
    let nonce = stored[32..40]
        .try_into()
        .map_err(|_| StoreError::Internal("invalid chunk nonce".into()))?;
    let size = u64::from_be_bytes(
        stored[40..48]
            .try_into()
            .map_err(|_| StoreError::Internal("invalid chunk size".into()))?,
    );
    publication
        .decrypt_all(context, &stored[48..], &nonce, size)
        .map_err(crate::error::crypto)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_envelope_authenticates_empty_content_size_nonce_and_finality()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let kms = kappa_crypto::kms::FileKms::new([23; 32], directory.path().join("erased"))?;
        let cipher = BlobEncryptor::new(&kms, "chunks")?;
        for content in [Vec::new(), vec![61; 65_536], vec![61; 65_537]] {
            let stored = encrypt(&cipher, "context", &content)?;
            let second = encrypt(&cipher, "context", &content)?;
            assert_ne!(&stored[..32], &second[..32]);
            let mut spliced = stored.clone();
            spliced[..32].copy_from_slice(&second[..32]);
            assert!(decrypt(&cipher, "context", &spliced).is_err());
            assert_eq!(decrypt(&cipher, "context", &stored)?, content);
            assert!(decrypt(&cipher, "other context", &stored).is_err());
            for offset in [0, 31, 32, 40, 47, stored.len() - 1] {
                let mut changed = stored.clone();
                changed[offset] ^= 1;
                assert!(decrypt(&cipher, "context", &changed).is_err());
            }
            assert!(decrypt(&cipher, "context", &stored[..15]).is_err());
        }
        Ok(())
    }
}
