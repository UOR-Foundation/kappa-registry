use gix_hash::ObjectId;
use gix_object::Kind;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    #[error("invalid envelope: {0}")]
    Invalid(String),
    #[error("hash computation failed: {0}")]
    Hash(String),
    #[error("invalid OID: {0}")]
    InvalidOid(String),
}

/// Wrap raw content in a Git object envelope for hashing.
///
/// Returns `"{type} {decimal_size}\0{content}"`.
/// The hash of these bytes IS the Git object ID.
pub fn wrap(kind: Kind, content: &[u8]) -> Vec<u8> {
    let header = gix_object::encode::loose_header(kind, content.len() as u64);
    let mut envelope = Vec::with_capacity(header.len() + content.len());
    envelope.extend_from_slice(&header);
    envelope.extend_from_slice(content);
    envelope
}

/// Parse a Git object envelope. Returns (kind, content).
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

    let kind = Kind::from_bytes(&header[..space_pos])
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
pub fn git_object_id_sha1(kind: Kind, content: &[u8]) -> Result<String, EnvelopeError> {
    let id = gix_object::compute_hash(gix_hash::Kind::Sha1, kind, content)
        .map_err(|e| EnvelopeError::Hash(e.to_string()))?;
    Ok(format!("sha1:{}", id))
}

/// Compute the Git object ID (SHA-256) of content wrapped in an envelope.
pub fn git_object_id_sha256(kind: Kind, content: &[u8]) -> Result<String, EnvelopeError> {
    let id = gix_object::compute_hash(gix_hash::Kind::Sha256, kind, content)
        .map_err(|e| EnvelopeError::Hash(e.to_string()))?;
    Ok(format!("sha256:{}", id))
}

/// Convert a kappa-label string to a gix_hash::ObjectId.
pub fn kappa_to_oid(kappa: &str) -> Result<ObjectId, EnvelopeError> {
    let (algo, hex) = kappa
        .split_once(':')
        .ok_or_else(|| EnvelopeError::Invalid("no colon in kappa-label".into()))?;

    let expected_kind = match algo {
        "sha1" => gix_hash::Kind::Sha1,
        "sha256" => gix_hash::Kind::Sha256,
        _ => {
            return Err(EnvelopeError::Invalid(format!(
                "unsupported git hash: {}",
                algo
            )));
        }
    };

    let id = ObjectId::from_hex(hex.as_bytes())
        .map_err(|e| EnvelopeError::Invalid(format!("invalid hex: {}", e)))?;

    if id.kind() != expected_kind {
        return Err(EnvelopeError::Invalid(format!(
            "hash kind mismatch: expected {}, got {}",
            expected_kind.len_in_bytes(),
            id.kind().len_in_bytes()
        )));
    }

    Ok(id)
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

/// Extract the hex OID from a kappa-label string.
pub fn kappa_to_hex_oid(kappa: &str) -> &str {
    kappa.split_once(':').map(|(_, hex)| hex).unwrap_or(kappa)
}

/// Determine the gix_object::Kind from envelope bytes.
pub fn kind_from_envelope(envelope: &[u8]) -> Result<Kind, EnvelopeError> {
    let (kind, _) = unwrap(envelope)?;
    Ok(kind)
}

/// Build a kappa-label from a hex OID and hash kind.
pub fn oid_to_kappa_string(object_hash: gix_hash::Kind, hex_oid: &str) -> String {
    let prefix = match object_hash {
        gix_hash::Kind::Sha1 => "sha1",
        gix_hash::Kind::Sha256 => "sha256",
        _ => "sha1",
    };
    format!("{}:{}", prefix, hex_oid)
}

/// Kappa axis prefix for a given hash kind.
pub fn hash_prefix(object_hash: gix_hash::Kind) -> &'static str {
    match object_hash {
        gix_hash::Kind::Sha1 => "sha1",
        gix_hash::Kind::Sha256 => "sha256",
        _ => "sha1",
    }
}

/// Compute the correct kappa-label for a Git object given its kind,
/// content, and the repository's hash algorithm.
pub fn compute_git_kappa(
    object_hash: gix_hash::Kind,
    kind: Kind,
    content: &[u8],
) -> Result<String, EnvelopeError> {
    match object_hash {
        gix_hash::Kind::Sha1 => git_object_id_sha1(kind, content),
        gix_hash::Kind::Sha256 => git_object_id_sha256(kind, content),
        _ => Err(EnvelopeError::Hash("unsupported hash kind".into())),
    }
}

/// Extract child kappa-labels from a Git object envelope.
///
/// Parses commit parent/tree lines, tree entries with raw hash bytes,
/// and tag object lines. `hash_len` is 20 for SHA-1, 32 for SHA-256.
pub fn extract_children(envelope_bytes: &[u8], hash_len: usize, prefix: &str) -> Vec<String> {
    let mut children = Vec::new();
    let (kind, content) = match unwrap(envelope_bytes) {
        Ok(r) => r,
        Err(_) => return children,
    };

    match kind {
        Kind::Commit => {
            for line in content.split(|&b| b == b'\n') {
                if let Some(rest) = line.strip_prefix(b"tree ") {
                    if let Ok(hex) = std::str::from_utf8(rest) {
                        children.push(format!("{}:{}", prefix, hex.trim()));
                    }
                } else if let Some(rest) = line.strip_prefix(b"parent ") {
                    if let Ok(hex) = std::str::from_utf8(rest) {
                        children.push(format!("{}:{}", prefix, hex.trim()));
                    }
                } else if line.is_empty() {
                    break;
                }
            }
        }
        Kind::Tree => {
            let mut pos = 0;
            while pos < content.len() {
                let nul = match content[pos..].iter().position(|&b| b == 0) {
                    Some(p) => pos + p,
                    None => break,
                };
                let hash_start = nul + 1;
                let hash_end = hash_start + hash_len;
                if hash_end > content.len() {
                    break;
                }
                children.push(format!(
                    "{}:{}",
                    prefix,
                    hex::encode(&content[hash_start..hash_end])
                ));
                pos = hash_end;
            }
        }
        Kind::Tag => {
            for line in content.split(|&b| b == b'\n') {
                if let Some(rest) = line.strip_prefix(b"object ")
                    && let Ok(hex) = std::str::from_utf8(rest)
                {
                    children.push(format!("{}:{}", prefix, hex.trim()));
                }
            }
        }
        Kind::Blob => {}
    }

    children
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
        assert_eq!(
            format!("{}", oid),
            "ce013625030ba8dba906f756967f9e9ca394464a"
        );
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

    #[test]
    fn kappa_to_hex_oid_strips_prefix() {
        assert_eq!(kappa_to_hex_oid("sha1:abc123"), "abc123");
        assert_eq!(kappa_to_hex_oid("sha256:def456"), "def456");
        assert_eq!(kappa_to_hex_oid("noprefix"), "noprefix");
    }

    #[test]
    fn compute_git_kappa_sha1() {
        let k = compute_git_kappa(gix_hash::Kind::Sha1, Kind::Blob, b"hello").unwrap();
        assert!(k.starts_with("sha1:"));
    }

    #[test]
    fn compute_git_kappa_sha256() {
        let k = compute_git_kappa(gix_hash::Kind::Sha256, Kind::Blob, b"hello").unwrap();
        assert!(k.starts_with("sha256:"));
    }
}
