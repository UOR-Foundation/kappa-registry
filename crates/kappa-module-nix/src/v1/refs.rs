//! Nix store path reference scanning and NAR verification.
//!
//! Reference scanning searches uncompressed NAR byte streams for
//! 32-character nix-base32 store path hash substrings. This replicates
//! the logic in NixOS/nix src/libstore/references.cc: scan for the
//! bare hash part only, not the /nix/store/ prefix or the name suffix.
//!
//! `decompress_and_verify` combines bounded streaming decompression,
//! NarSize and NarHash verification, and reference scanning into a single
//! pipeline that rejects corrupted or misrepresented narinfo on ingest.

use std::collections::HashSet;
use std::io::Read;

use kappa_store::compression::Codec;
use sha2::{Digest, Sha256};

const STORE_PATH_HASH_LEN: usize = 32;

/// NAR verification errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VerifyError {
    #[error("NarHash mismatch: expected {expected}, computed {computed}")]
    NarHashMismatch { expected: String, computed: String },

    #[error("references mismatch: narinfo claims {narinfo:?}, scan found {scanned:?}")]
    ReferencesMismatch {
        narinfo: Vec<String>,
        scanned: Vec<String>,
    },

    #[error("NarSize mismatch: narinfo declares {declared} bytes, NAR decodes to {decoded}")]
    NarSizeMismatch { declared: u64, decoded: u64 },

    #[error("NarSize mismatch: narinfo declares {declared} bytes, NAR decodes past them")]
    NarTooLong { declared: u64 },

    #[error("decompression error: {0}")]
    Decompression(String),

    #[error("unsupported compression: {0}")]
    UnsupportedCompression(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Check if a byte is in the nix-base32 alphabet.
///
/// Alphabet: 0123456789abcdfghijklmnpqrsvwxyz (32 chars)
/// Missing from lowercase ASCII: e, o, t, u
pub fn is_nixbase32_byte(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'd' | b'f'..=b'n' | b'p'..=b's' | b'v'..=b'z')
}

/// Scan a byte buffer for nix store path hash references.
///
/// `candidates` is a set of 32-character nix-base32 hash strings.
/// Returns the subset of candidates found in `data`, sorted.
pub fn scan_references(data: &[u8], candidates: &[&str]) -> Vec<String> {
    if candidates.is_empty() || data.len() < STORE_PATH_HASH_LEN {
        return Vec::new();
    }
    let candidate_set: HashSet<&str> = candidates.iter().copied().collect();
    let mut found = HashSet::new();

    for window_start in 0..=(data.len() - STORE_PATH_HASH_LEN) {
        let first = data[window_start];
        if !is_nixbase32_byte(first) {
            continue;
        }
        let window = &data[window_start..window_start + STORE_PATH_HASH_LEN];
        if !is_nixbase32_byte(window[STORE_PATH_HASH_LEN - 1]) {
            continue;
        }
        if let Ok(window_str) = std::str::from_utf8(window)
            && candidate_set.contains(window_str)
        {
            found.insert(window_str.to_string());
        }
    }

    let mut result: Vec<String> = found.into_iter().collect();
    result.sort();
    result
}

/// Scan with chunk boundary handling.
///
/// Matches the behavior of RefScanSink in references.cc: retain a
/// tail of 31 bytes from the previous chunk to catch hashes spanning
/// chunk boundaries.
///
/// Returns (found_hashes, new_tail_for_next_chunk).
pub fn scan_references_chunked(
    chunk: &[u8],
    tail: &[u8],
    candidates: &[&str],
) -> (Vec<String>, Vec<u8>) {
    let mut overlap_found = Vec::new();
    if !tail.is_empty() && !chunk.is_empty() {
        let overlap_take = (STORE_PATH_HASH_LEN - 1).min(chunk.len());
        let mut combined = Vec::with_capacity(tail.len() + overlap_take);
        combined.extend_from_slice(tail);
        combined.extend_from_slice(&chunk[..overlap_take]);
        overlap_found = scan_references(&combined, candidates);
    }

    let mut main_found = scan_references(chunk, candidates);

    main_found.extend(overlap_found);
    main_found.sort();
    main_found.dedup();

    let new_tail_start = chunk.len().saturating_sub(STORE_PATH_HASH_LEN - 1);
    let new_tail = chunk[new_tail_start..].to_vec();

    (main_found, new_tail)
}

/// Bytes of decoded NAR examined per step.
const DECODE_CHUNK: usize = 64 * 1024;

/// The 32-character hash parts of the store path basenames in
/// `references`, sorted and deduplicated.
fn claimed_hashes(references: &[String]) -> Vec<String> {
    let mut hashes: Vec<String> = references
        .iter()
        .filter_map(|basename| {
            if basename.len() > STORE_PATH_HASH_LEN
                && basename.as_bytes().get(STORE_PATH_HASH_LEN) == Some(&b'-')
            {
                Some(basename[..STORE_PATH_HASH_LEN].to_string())
            } else {
                None
            }
        })
        .collect();
    hashes.sort();
    hashes.dedup();
    hashes
}

/// Decompress a NAR blob, verify NarSize and NarHash, and scan for
/// references.
///
/// This is the ingest verification pipeline. The NAR is decoded through
/// the shared bounded decoder (`kappa_store::compression`), the one the
/// store admits and reads compressed content through, one chunk at a time
/// and never held whole; at most one byte past `expected_nar_size` is ever
/// decoded. It ensures:
/// 1. The compressed NAR decompresses successfully within the decoder
///    memory bound
/// 2. It decodes to exactly `expected_nar_size` bytes
/// 3. SHA-256 of the decompressed NAR matches `expected_nar_hash`
/// 4. Every store path hash claimed in `claimed_references` appears
///    in the decompressed NAR byte stream, including across chunk
///    boundaries
///
/// # Errors
///
/// Returns `VerifyError::UnsupportedCompression` for an algorithm no
/// shared decoder decodes.
/// Returns `VerifyError::Decompression` if decompression fails.
/// Returns `VerifyError::NarTooLong` or `VerifyError::NarSizeMismatch` if
/// the decoded size differs from `expected_nar_size`.
/// Returns `VerifyError::NarHashMismatch` if the computed hash differs.
/// Returns `VerifyError::ReferencesMismatch` if a claimed reference
/// hash is not found in the decompressed NAR.
pub fn decompress_and_verify(
    compressed_data: &[u8],
    compression: &str,
    expected_nar_hash: &str,
    expected_nar_size: u64,
    claimed_references: &[String],
) -> Result<(), VerifyError> {
    let codec = Codec::of(compression)
        .map_err(|_| VerifyError::UnsupportedCompression(compression.to_string()))?;
    let decoder = codec
        .decoder(compressed_data)
        .map_err(|error| VerifyError::Decompression(format!("{compression}: {error}")))?;
    let claimed = claimed_hashes(claimed_references);
    let candidates: Vec<&str> = claimed.iter().map(String::as_str).collect();

    let mut hasher = Sha256::new();
    let mut scanned: Vec<String> = Vec::new();
    let mut tail: Vec<u8> = Vec::new();
    let mut decoded = 0u64;
    let mut bounded = decoder.take(expected_nar_size.saturating_add(1));
    let mut chunk = vec![0u8; DECODE_CHUNK];
    loop {
        let read = match bounded.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(VerifyError::Decompression(format!(
                    "{compression}: {error}"
                )));
            }
        };
        decoded += read as u64;
        if decoded > expected_nar_size {
            return Err(VerifyError::NarTooLong {
                declared: expected_nar_size,
            });
        }
        let piece = &chunk[..read];
        hasher.update(piece);
        let (found, next) = scan_references_chunked(piece, &tail, &candidates);
        scanned.extend(found);
        tail = next;
    }
    if decoded != expected_nar_size {
        return Err(VerifyError::NarSizeMismatch {
            declared: expected_nar_size,
            decoded,
        });
    }

    let computed_hash = format!(
        "sha256:{}",
        nix_derivation::nixbase32::encode(&hasher.finalize())
    );
    if computed_hash != expected_nar_hash {
        return Err(VerifyError::NarHashMismatch {
            expected: expected_nar_hash.to_string(),
            computed: computed_hash,
        });
    }

    scanned.sort();
    scanned.dedup();
    for hash in &claimed {
        if !scanned.contains(hash) {
            return Err(VerifyError::ReferencesMismatch {
                narinfo: claimed,
                scanned,
            });
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_known_hash_in_buffer() {
        let data = b"/nix/store/r5sjd57x0r07bwgipryaxqdkx1gglhiy-libidn2";
        let candidates = &["r5sjd57x0r07bwgipryaxqdkx1gglhiy"];
        let found = scan_references(data, candidates);
        assert_eq!(found, vec!["r5sjd57x0r07bwgipryaxqdkx1gglhiy"]);
    }

    #[test]
    fn rejects_partial_hash() {
        let data = b"r5sjd57x0r07bwgipryaxqdkx1gglhi_padding";
        let candidates = &["r5sjd57x0r07bwgipryaxqdkx1gglhiy"];
        let found = scan_references(data, candidates);
        assert!(found.is_empty());
    }

    #[test]
    fn empty_candidates_returns_empty() {
        let data = b"r5sjd57x0r07bwgipryaxqdkx1gglhiy";
        let found = scan_references(data, &[]);
        assert!(found.is_empty());
    }

    #[test]
    fn self_reference_found() {
        let hash = "r5sjd57x0r07bwgipryaxqdkx1gglhiy";
        let data = format!("/nix/store/{}-mypackage", hash);
        let found = scan_references(data.as_bytes(), &[hash]);
        assert_eq!(found, vec![hash]);
    }

    #[test]
    fn chunked_scan_finds_hash_spanning_boundary() {
        let hash = "r5sjd57x0r07bwgipryaxqdkx1gglhiy";
        let full = format!("prefix{hash}suffix");
        let split_at = 6 + 16;
        let chunk1 = &full.as_bytes()[..split_at];
        let chunk2 = &full.as_bytes()[split_at..];

        let (found1, tail) = scan_references_chunked(chunk1, &[], &[hash]);
        assert!(found1.is_empty());

        let (found2, _) = scan_references_chunked(chunk2, &tail, &[hash]);
        assert_eq!(found2, vec![hash]);
    }

    fn nar_hash(nar: &[u8]) -> String {
        format!(
            "sha256:{}",
            nix_derivation::nixbase32::encode(&Sha256::digest(nar))
        )
    }

    /// A NAR naming `hash` at an offset that straddles the first decode
    /// chunk boundary.
    fn straddling_nar(hash: &str) -> Vec<u8> {
        let mut nar = vec![b'.'; DECODE_CHUNK - 10];
        nar.extend_from_slice(format!("/nix/store/{hash}-dep").as_bytes());
        nar.extend_from_slice(&[b'.'; 4096]);
        nar
    }

    #[test]
    fn stored_and_zstd_nars_verify_with_a_reference_across_chunks() {
        let hash = "r5sjd57x0r07bwgipryaxqdkx1gglhiy";
        let nar = straddling_nar(hash);
        let references = vec![format!("{hash}-dep")];
        let compressed = zstd::encode_all(std::io::Cursor::new(nar.as_slice()), 3).unwrap();
        for (algorithm, data) in [("none", nar.clone()), ("zstd", compressed)] {
            decompress_and_verify(
                &data,
                algorithm,
                &nar_hash(&nar),
                nar.len() as u64,
                &references,
            )
            .unwrap();
        }
    }

    #[test]
    fn a_nar_of_another_size_than_declared_is_refused() {
        let nar = b"nar bytes of a declared size".to_vec();
        let declared = nar.len() as u64;
        assert!(matches!(
            decompress_and_verify(&nar, "none", &nar_hash(&nar), declared - 1, &[]),
            Err(VerifyError::NarTooLong { declared: d }) if d == declared - 1
        ));
        assert!(matches!(
            decompress_and_verify(&nar, "none", &nar_hash(&nar), declared + 1, &[]),
            Err(VerifyError::NarSizeMismatch { declared: d, decoded })
                if d == declared + 1 && decoded == declared
        ));
    }

    #[test]
    fn a_missing_claimed_reference_and_a_wrong_hash_are_refused() {
        let nar = b"a nar that references nothing".to_vec();
        let claimed = vec!["r5sjd57x0r07bwgipryaxqdkx1gglhiy-dep".to_string()];
        assert!(matches!(
            decompress_and_verify(&nar, "none", &nar_hash(&nar), nar.len() as u64, &claimed),
            Err(VerifyError::ReferencesMismatch { .. })
        ));
        assert!(matches!(
            decompress_and_verify(&nar, "none", &nar_hash(b"other"), nar.len() as u64, &[]),
            Err(VerifyError::NarHashMismatch { .. })
        ));
    }

    #[test]
    fn rejects_unsupported_compression() {
        assert!(matches!(
            decompress_and_verify(b"data", "lz4", &nar_hash(b"data"), 4, &[]),
            Err(VerifyError::UnsupportedCompression(_))
        ));
    }

    #[test]
    fn nixbase32_accepts_valid_chars() {
        for b in b'0'..=b'9' {
            assert!(is_nixbase32_byte(b));
        }
        for b in b'a'..=b'd' {
            assert!(is_nixbase32_byte(b));
        }
        for b in b'f'..=b'n' {
            assert!(is_nixbase32_byte(b));
        }
        for b in b'p'..=b's' {
            assert!(is_nixbase32_byte(b));
        }
        for b in b'v'..=b'z' {
            assert!(is_nixbase32_byte(b));
        }
    }

    #[test]
    fn nixbase32_rejects_missing_chars() {
        assert!(!is_nixbase32_byte(b'e'));
        assert!(!is_nixbase32_byte(b'o'));
        assert!(!is_nixbase32_byte(b't'));
        assert!(!is_nixbase32_byte(b'u'));
        assert!(!is_nixbase32_byte(b'A'));
        assert!(!is_nixbase32_byte(b' '));
    }

    #[test]
    fn multiple_references_found() {
        let hash1 = "r5sjd57x0r07bwgipryaxqdkx1gglhiy";
        let hash2 = "0z7sqj4pilbqyp45ix5b0mdgn9xlb024";
        let data = format!(
            "/nix/store/{}-libidn2-2.3.2/nix/store/{}-libunistring-0.9.10",
            hash1, hash2
        );
        let found = scan_references(data.as_bytes(), &[hash1, hash2]);
        assert_eq!(found.len(), 2);
        assert!(found.contains(&hash1.to_string()));
        assert!(found.contains(&hash2.to_string()));
    }

    #[test]
    fn buffer_shorter_than_hash_returns_empty() {
        let data = b"short";
        let candidates = &["r5sjd57x0r07bwgipryaxqdkx1gglhiy"];
        let found = scan_references(data, candidates);
        assert!(found.is_empty());
    }
}
