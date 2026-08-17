//! Git object envelope codec.
//!
//! Git hashes the envelope `"{type} {size}\0{content}"`, not the raw content.
//! The store holds envelope bytes. Protocol handlers strip the envelope
//! before serving content to Git clients.

use gix_hash::ObjectId;
use gix_object::Kind;

/// Errors from envelope operations.
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("invalid envelope: {0}")]
    Invalid(String),
    #[error("hash computation failed: {0}")]
    Hash(String),
}

/// Wrap raw content in a Git object envelope for hashing.
///
/// Returns the envelope bytes: `"{type} {decimal_size}\0{content}"`.
/// The hash of these bytes IS the Git object ID.
pub fn wrap(kind: Kind, content: &[u8]) -> Vec<u8> {
    let header = gix_object::encode::loose_header(kind, content.len() as u64);
    let mut envelope = Vec::with_capacity(header.len() + content.len());
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(content);
    envelope
}

/// Parse a Git object envelope. Returns (kind, content) where content
/// is the slice after the NUL byte.
pub fn unwrap(envelope: &[u8]) -> Result<(Kind, &[u8]), EnvelopeError> {
    let nul_pos = envelope
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| EnvelopeError::Invalid("no NUL byte in envelope".into()))?;

    let header = &envelope[..nul_pos];
    let space_pos = header
        .iter()
        .position(|&b| b == b' ')
        .ok_or_else(|| EnvelopeError::Invalid("no space in header".into()))?;

    let kind_bytes = &header[..space_pos];
    let kind = Kind::from_bytes(kind_bytes)
        .map_err(|e| EnvelopeError::Invalid(e.to_string()))?;

    let size_bytes = &header[space_pos + 1..];
    let declared_size: usize = std::str::from_utf8(size_bytes)
        .map_err(|_| EnvelopeError::Invalid("size not utf8".into()))?
        .parse()
        .map_err(|_| EnvelopeError::Invalid("size not decimal".into()))?;

    let content = &envelope[nul_pos + 1..];
    if content.len() != declared_size {
        return Err(EnvelopeError::Invalid(format!(
            "declared size {} but content is {} bytes",
            declared_size,
            content.len()
        )));
    }

    Ok((kind, content))
}

/// Compute the Git object ID (SHA-1) of content wrapped in an envelope.
///
/// This is the canonical Git object hash: hash("{type} {size}\0{content}").
/// Returns the kappa-label string "sha1:{hex}".
pub fn git_object_id_sha1(kind: Kind, content: &[u8]) -> Result<String, EnvelopeError> {
    let id = gix_object::compute_hash(gix_hash::Kind::Sha1, kind, content)
        .map_err(|e| EnvelopeError::Hash(e.to_string()))?;
    Ok(format!("sha1:{}", id))
}

/// Compute the Git object ID (SHA-256) of content wrapped in an envelope.
///
/// For Git's SHA-256 object format. Returns "sha256:{hex}".
pub fn git_object_id_sha256(kind: Kind, content: &[u8]) -> Result<String, EnvelopeError> {
    let id = gix_object::compute_hash(gix_hash::Kind::Sha256, kind, content)
        .map_err(|e| EnvelopeError::Hash(e.to_string()))?;
    Ok(format!("sha256:{}", id))
}

/// Convert a kappa-label string ("sha1:{hex}" or "sha256:{hex}") to a
/// gix_hash::ObjectId.
pub fn kappa_to_oid(kappa: &str) -> Result<ObjectId, EnvelopeError> {
    let (algo, hex) = kappa
        .split_once(':')
        .ok_or_else(|| EnvelopeError::Invalid("no colon in kappa-label".into()))?;

    let hash_kind = match algo {
        "sha1" => gix_hash::Kind::Sha1,
        "sha256" => gix_hash::Kind::Sha256,
        _ => return Err(EnvelopeError::Invalid(format!("unsupported git hash: {}", algo))),
    };

    ObjectId::from_hex(hex.as_bytes())
        .map_err(|e| EnvelopeError::Invalid(format!("invalid hex: {}", e)))
        .and_then(|id| {
            if id.kind() == hash_kind {
                Ok(id)
            } else {
                // ObjectId::from_hex infers kind from length. Verify it matches.
                Err(EnvelopeError::Invalid(format!(
                    "hash kind mismatch: expected {}, got {}",
                    hash_kind.len_in_bytes(),
                    id.kind().len_in_bytes()
                )))
            }
        })
}

/// Convert a gix_hash::ObjectId to a kappa-label string.
pub fn oid_to_kappa(id: &ObjectId) -> Result<String, EnvelopeError> {
    match id.kind() {
        gix_hash::Kind::Sha1 => Ok(format!("sha1:{}", id)),
        gix_hash::Kind::Sha256 => Ok(format!("sha256:{}", id)),
        _ => Err(EnvelopeError::Invalid(format!(
            "unsupported hash kind: {} bytes",
            id.kind().len_in_bytes()
        ))),
    }
}

/// Determine the gix_object::Kind from an envelope stored in the blob store.
/// Reads only the header bytes (before NUL), not the full content.
pub fn kind_from_envelope(envelope: &[u8]) -> Result<Kind, EnvelopeError> {
    let (kind, _) = unwrap(envelope)?;
    Ok(kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrap_blob_hello() {
        let envelope = wrap(Kind::Blob, b"hello");
        assert_eq!(&envelope, b"blob 5\0hello");
    }

    #[test]
    fn wrap_empty_blob() {
        let envelope = wrap(Kind::Blob, b"");
        assert_eq!(&envelope, b"blob 0\0");
    }

    #[test]
    fn unwrap_blob() {
        let (kind, content) = unwrap(b"blob 5\0hello").unwrap();
        assert_eq!(kind, Kind::Blob);
        assert_eq!(content, b"hello");
    }

    #[test]
    fn unwrap_commit() {
        let body = b"tree abc\nauthor x\n";
        let envelope = wrap(Kind::Commit, body);
        let (kind, content) = unwrap(&envelope).unwrap();
        assert_eq!(kind, Kind::Commit);
        assert_eq!(content, body);
    }

    #[test]
    fn unwrap_rejects_no_nul() {
        assert!(unwrap(b"blob 5hello").is_err());
    }

    #[test]
    fn unwrap_rejects_wrong_size() {
        assert!(unwrap(b"blob 3\0hello").is_err());
    }

    #[test]
    fn unwrap_rejects_unknown_kind() {
        assert!(unwrap(b"widget 5\0hello").is_err());
    }

    #[test]
    fn git_object_id_sha1_hello() {
        let kappa = git_object_id_sha1(Kind::Blob, b"hello").unwrap();
        // printf 'hello' | git hash-object --stdin -t blob
        assert_eq!(kappa, "sha1:b6fc4c620b67d95f953a5c1c1230aaab5db5a1b0");
    }

    #[test]
    fn roundtrip_wrap_unwrap() {
        for kind in [Kind::Blob, Kind::Tree, Kind::Commit, Kind::Tag] {
            let content = b"test content for roundtrip";
            let envelope = wrap(kind, content);
            let (k, c) = unwrap(&envelope).unwrap();
            assert_eq!(k, kind);
            assert_eq!(c, content);
        }
    }

    #[test]
    fn kappa_to_oid_sha1() {
        let kappa = "sha1:ce013625030ba8dba906f756967f9e9ca394464a";
        let oid = kappa_to_oid(kappa).unwrap();
        assert_eq!(oid.kind(), gix_hash::Kind::Sha1);
        assert_eq!(format!("{}", oid), "ce013625030ba8dba906f756967f9e9ca394464a");
    }

    #[test]
    fn oid_to_kappa_roundtrip() {
        let kappa = "sha1:ce013625030ba8dba906f756967f9e9ca394464a";
        let oid = kappa_to_oid(kappa).unwrap();
        let back = oid_to_kappa(&oid).unwrap();
        assert_eq!(back, kappa);
    }

    #[test]
    fn kappa_to_oid_rejects_blake3() {
        assert!(kappa_to_oid("blake3:abcd").is_err());
    }
}
