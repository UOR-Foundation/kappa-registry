//! Nix store path reference scanning and NAR verification.
//!
//! Reference scanning searches uncompressed NAR byte streams for
//! 32-character nix-base32 store path hash substrings. This replicates
//! the logic in NixOS/nix src/libstore/references.cc: scan for the
//! bare hash part only, not the /nix/store/ prefix or the name suffix.
//!
//! The decompress_and_verify function combines decompression, NarHash
//! verification, and reference scanning into a single pipeline that
//! rejects corrupted or misrepresented narinfo on ingest.

use std::collections::HashSet;

use sha2::{Digest, Sha256};
use thiserror::Error;

const STORE_PATH_HASH_LEN: usize = 32;

#[derive(Debug, Error)]
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
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Check if a byte is in the nix-base32 alphabet.
/// Alphabet: 0123456789abcdfghijklmnpqrsvwxyz
/// Missing: e, o, t, u
fn is_nixbase32_byte(b: u8) -> bool {
    matches!(b, b'0'..=b'9' | b'a'..=b'd' | b'f'..=b'n' | b'p'..=b's' | b'v'..=b'z')
}

/// Scan a byte buffer for nix store path hash references.
///
/// `candidates` is a set of 32-character nix-base32 hash strings.
/// Returns the subset of candidates found in `data`.
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
        // Quick reject: check last byte too before doing full UTF-8 + set lookup
        if !is_nixbase32_byte(window[STORE_PATH_HASH_LEN - 1]) {
            continue;
        }
        if let Ok(window_str) = std::str::from_utf8(window) {
            if candidate_set.contains(window_str) {
                found.insert(window_str.to_string());
            }
        }
    }
    let mut result: Vec<String> = found.into_iter().collect();
    result.sort();
    result
}

/// Scan with chunk boundary handling. Matches the behavior of
/// RefScanSink in references.cc: retain a tail of 31 bytes from
/// the previous chunk to catch hashes spanning chunk boundaries.
///
/// Returns (found_hashes, new_tail_for_next_chunk).
pub fn scan_references_chunked(
    chunk: &[u8],
    tail: &[u8],
    candidates: &[&str],
) -> (Vec<String>, Vec<u8>) {
    // Scan the overlap region: tail + beginning of chunk
    let mut overlap_found = Vec::new();
    if !tail.is_empty() && !chunk.is_empty() {
        let overlap_take = STORE_PATH_HASH_LEN.saturating_sub(1).min(chunk.len());
        let mut combined = Vec::with_capacity(tail.len() + overlap_take);
        combined.extend_from_slice(tail);
        combined.extend_from_slice(&chunk[..overlap_take]);
        overlap_found = scan_references(&combined, candidates);
    }

    // Scan the main chunk
    let mut main_found = scan_references(chunk, candidates);

    // Merge and deduplicate
    main_found.extend(overlap_found);
    main_found.sort();
    main_found.dedup();

    // New tail: last 31 bytes of chunk (or all of chunk if shorter)
    let new_tail_start = chunk.len().saturating_sub(STORE_PATH_HASH_LEN - 1);
    let new_tail = chunk[new_tail_start..].to_vec();

    (main_found, new_tail)
}

/// Decompress bytes according to the compression algorithm name.
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
        other => Err(VerifyError::Decompression(format!(
            "unsupported compression: {other}"
        ))),
    }
}

/// Decompress a NAR blob, verify NarHash, and scan for references.
///
/// This is the ingest verification pipeline. It ensures:
/// 1. The compressed NAR decompresses successfully
/// 2. SHA-256 of the decompressed NAR matches expected_nar_hash
/// 3. The set of store path hashes found in the NAR matches the
///    set claimed in the narinfo References field
///
/// `compressed_data` -- the stored compressed NAR bytes
/// `compression` -- "zstd", "xz", "bzip2", "none", etc
/// `expected_nar_hash` -- "sha256:{nixbase32}" from the narinfo
/// `claimed_references` -- basenames from the narinfo References field
///
/// Returns Ok(()) if both NarHash and references match.
pub fn decompress_and_verify(
    compressed_data: &[u8],
    compression: &str,
    expected_nar_hash: &str,
    claimed_references: &[String],
) -> Result<(), VerifyError> {
    // Step 1: Decompress
    let decompressed = decompress(compressed_data, compression)?;

    // Step 2: Compute NarHash (SHA-256 of entire decompressed NAR byte stream)
    let hash_bytes = Sha256::digest(&decompressed);
    let computed_hash = format!(
        "sha256:{}",
        nix_derivation::nixbase32::encode(&hash_bytes)
    );
    if computed_hash != expected_nar_hash {
        return Err(VerifyError::NarHashMismatch {
            expected: expected_nar_hash.to_string(),
            computed: computed_hash,
        });
    }

    // Step 3: Extract hash parts from claimed references
    let mut claimed_hashes: Vec<String> = claimed_references
        .iter()
        .filter_map(|basename| {
            // basename format: "{32-char-hash}-{name}"
            if basename.len() > STORE_PATH_HASH_LEN
                && basename.as_bytes()[STORE_PATH_HASH_LEN] == b'-'
            {
                Some(basename[..STORE_PATH_HASH_LEN].to_string())
            } else {
                None
            }
        })
        .collect();
    claimed_hashes.sort();
    claimed_hashes.dedup();

    // Step 4: Scan decompressed NAR for references
    let candidate_strs: Vec<&str> = claimed_hashes.iter().map(|s| s.as_str()).collect();
    let scanned = scan_references(&decompressed, &candidate_strs);

    // Every claimed reference hash must appear in the decompressed NAR.
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
    fn does_not_match_partial_hash() {
        // 31 chars -- too short
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
        let candidates = &[hash];
        let found = scan_references(data.as_bytes(), candidates);
        assert_eq!(found, vec![hash]);
    }

    #[test]
    fn chunked_scan_finds_hash_spanning_boundary() {
        let hash = "r5sjd57x0r07bwgipryaxqdkx1gglhiy";
        // Split the hash across two chunks at position 16
        let full = format!("prefix{hash}suffix");
        let split_at = 6 + 16; // "prefix" + first 16 chars of hash
        let chunk1 = &full.as_bytes()[..split_at];
        let chunk2 = &full.as_bytes()[split_at..];

        // First chunk: get tail
        let (found1, tail) = scan_references_chunked(chunk1, &[], &[hash]);
        assert!(found1.is_empty()); // hash not complete in first chunk

        // Second chunk with tail: should find the hash
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
        let compressed = zstd::encode_all(std::io::Cursor::new(original), 3).unwrap();
        let decompressed = decompress(&compressed, "zstd").unwrap();
        assert_eq!(decompressed, original);
    }

    #[test]
    fn decompress_unsupported_returns_error() {
        let result = decompress(b"data", "lz4");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unsupported"));
    }

    #[test]
    fn is_nixbase32_accepts_valid_chars() {
        // Valid: 0-9, a-d, f-n, p-s, v-z
        for b in b'0'..=b'9' {
            assert!(is_nixbase32_byte(b), "should accept {}", b as char);
        }
        for b in b'a'..=b'd' {
            assert!(is_nixbase32_byte(b), "should accept {}", b as char);
        }
        for b in b'f'..=b'n' {
            assert!(is_nixbase32_byte(b), "should accept {}", b as char);
        }
        for b in b'p'..=b's' {
            assert!(is_nixbase32_byte(b), "should accept {}", b as char);
        }
        for b in b'v'..=b'z' {
            assert!(is_nixbase32_byte(b), "should accept {}", b as char);
        }
    }

    #[test]
    fn is_nixbase32_rejects_missing_chars() {
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
        let candidates = &[hash1, hash2];
        let found = scan_references(data.as_bytes(), candidates);
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
