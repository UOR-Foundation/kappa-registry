//! Nix store path reference scanning and NAR verification.
//!
//! Reference scanning searches uncompressed NAR byte streams for
//! 32-character nix-base32 store path hash substrings. This replicates
//! the logic in NixOS/nix src/libstore/references.cc: scan for the
//! bare hash part only, not the /nix/store/ prefix or the name suffix.
//!
//! `decompress_and_verify` combines decompression, NarHash verification,
//! and reference scanning into a single pipeline that rejects corrupted
//! or misrepresented narinfo on ingest.

use std::collections::HashSet;

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

/// Decompress bytes according to the compression algorithm name.
///
/// # Errors
///
/// Returns `VerifyError::UnsupportedCompression` for unknown algorithms.
/// Returns `VerifyError::Decompression` for corrupt compressed data.
fn decompress(data: &[u8], compression: &str) -> Result<Vec<u8>, VerifyError> {
    match compression {
        "none" => Ok(data.to_vec()),
        "zstd" => zstd::decode_all(std::io::Cursor::new(data))
            .map_err(|e| VerifyError::Decompression(format!("zstd: {e}"))),
        "xz" | "lzma" => {
            use std::io::Read;
            let mut decoder = xz2::read::XzDecoder::new(data);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| VerifyError::Decompression(format!("xz: {e}")))?;
            Ok(out)
        }
        "bzip2" => {
            use std::io::Read;
            let mut decoder = bzip2::read::BzDecoder::new(data);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| VerifyError::Decompression(format!("bzip2: {e}")))?;
            Ok(out)
        }
        other => Err(VerifyError::UnsupportedCompression(other.to_string())),
    }
}

/// Decompress a NAR blob, verify NarHash, and scan for references.
///
/// This is the ingest verification pipeline. It ensures:
/// 1. The compressed NAR decompresses successfully
/// 2. SHA-256 of the decompressed NAR matches `expected_nar_hash`
/// 3. Every store path hash claimed in `claimed_references` appears
///    in the decompressed NAR byte stream
///
/// # Errors
///
/// Returns `VerifyError::NarHashMismatch` if the computed hash differs.
/// Returns `VerifyError::ReferencesMismatch` if a claimed reference
/// hash is not found in the decompressed NAR.
/// Returns `VerifyError::Decompression` if decompression fails.
pub fn decompress_and_verify(
    compressed_data: &[u8],
    compression: &str,
    expected_nar_hash: &str,
    claimed_references: &[String],
) -> Result<(), VerifyError> {
    let decompressed = decompress(compressed_data, compression)?;

    let hash_bytes = Sha256::digest(&decompressed);
    let computed_hash = format!("sha256:{}", nix_derivation::nixbase32::encode(&hash_bytes));
    if computed_hash != expected_nar_hash {
        return Err(VerifyError::NarHashMismatch {
            expected: expected_nar_hash.to_string(),
            computed: computed_hash,
        });
    }

    let mut claimed_hashes: Vec<String> = claimed_references
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
    claimed_hashes.sort();
    claimed_hashes.dedup();

    let candidate_strs: Vec<&str> = claimed_hashes.iter().map(|s| s.as_str()).collect();
    let scanned = scan_references(&decompressed, &candidate_strs);

    for claimed in &claimed_hashes {
        if !scanned.contains(claimed) {
            return Err(VerifyError::ReferencesMismatch {
                narinfo: claimed_hashes.clone(),
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

    #[test]
    fn decompress_none_returns_input() {
        let data = b"test data";
        let result = decompress(data, "none").unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn decompress_zstd_roundtrip() {
        let original = b"test data for zstd compression roundtrip";
        let compressed = zstd::encode_all(std::io::Cursor::new(original.as_slice()), 3).unwrap();
        let decompressed = decompress(&compressed, "zstd").unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn rejects_unsupported_compression() {
        assert!(matches!(
            decompress(b"data", "lz4"),
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
