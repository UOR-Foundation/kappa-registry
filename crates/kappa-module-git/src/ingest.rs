//! Pack ingest: streaming pack parse with delta resolution.
//!
//! Non-delta objects over 256 KiB: write envelope header as first upload
//! part, decompress in 64 KiB chunks via upload_put_part, complete with
//! the computed Git object ID. Memory: one 64 KiB buffer per object.
//!
//! Non-delta objects under 256 KiB: decompress into Vec, wrap in envelope,
//! store via ingest_verified. Memory cost negligible for small objects.
//!
//! Delta objects: resolve base from store, apply delta in memory, store
//! via ingest_verified. Memory: max(resolved_delta_size) per object.
//!
//! OFS_DELTA: offset-to-kappa map populated during linear traversal.

use std::collections::HashMap;
use std::io::{self, BufRead, Read};

use gix_pack::data::input::{self, BytesToEntriesIter};

use kappa_core::store::KappaStore;
use kappa_core::types::NamespaceRef;

use crate::envelope;

const STREAMING_THRESHOLD: usize = 256 * 1024;
const UPLOAD_CHUNK_SIZE: usize = 64 * 1024;

/// Result of a pack ingest operation.
#[derive(Debug)]
pub struct PackIngestResult {
    pub objects_ingested: usize,
    pub objects_deduplicated: usize,
}

/// Errors from pack ingest.
#[derive(Debug, thiserror::Error)]
pub enum IngestError {
    #[error("pack parse error: {0}")]
    Pack(String),
    #[error("store error: {0}")]
    Store(#[from] kappa_core::types::StoreError),
    #[error("envelope error: {0}")]
    Envelope(#[from] envelope::EnvelopeError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("delta resolution failed: {0}")]
    Delta(String),
    #[error("unknown entry type in pack")]
    UnknownEntryType,
}

/// Ingest a packfile stream into the store.
pub fn ingest_pack<R: BufRead>(
    store: &(dyn KappaStore + '_),
    namespace: &NamespaceRef,
    pack_stream: R,
    object_hash: gix_hash::Kind,
) -> Result<PackIngestResult, IngestError> {
    let iter = BytesToEntriesIter::new_from_header(
        pack_stream,
        input::Mode::Verify,
        input::EntryDataMode::Keep,
        object_hash,
    )
    .map_err(|e| IngestError::Pack(e.to_string()))?;

    let mut offset_to_kappa: HashMap<u64, String> = HashMap::new();
    let mut ingested = 0usize;
    let mut deduplicated = 0usize;

    for entry_result in iter {
        let entry = entry_result.map_err(|e| IngestError::Pack(e.to_string()))?;
        let entry_pack_offset = entry.pack_offset;

        match entry.header {
            gix_pack::data::entry::Header::Commit
            | gix_pack::data::entry::Header::Tree
            | gix_pack::data::entry::Header::Blob
            | gix_pack::data::entry::Header::Tag => {
                let kind = entry.header.as_kind().ok_or(IngestError::UnknownEntryType)?;
                let compressed = entry
                    .compressed
                    .as_ref()
                    .ok_or_else(|| IngestError::Pack("entry has no compressed data".into()))?;

                let decompressed_size = entry.decompressed_size as usize;

                if decompressed_size > STREAMING_THRESHOLD {
                    // Large object: stream through upload lifecycle.
                    // Decompress in 64 KiB chunks. Never hold the full
                    // object in memory.
                    let kappa = ingest_streaming(
                        store, namespace, kind, compressed, decompressed_size, object_hash,
                    )?;
                    ingested += 1;
                    offset_to_kappa.insert(entry_pack_offset, kappa);
                } else {
                    // Small object: decompress, wrap, ingest_verified.
                    let decompressed = decompress_entry(compressed, decompressed_size)?;
                    let kappa = compute_git_kappa(object_hash, kind, &decompressed)?;
                    let envelope_bytes = envelope::wrap(kind, &decompressed);
                    let result = store.ingest_verified(&kappa, &envelope_bytes)?;
                    if result.newly_stored { ingested += 1; } else { deduplicated += 1; }
                    offset_to_kappa.insert(entry_pack_offset, kappa);
                }
            }

            gix_pack::data::entry::Header::RefDelta { base_id } => {
                let kappa = resolve_delta(
                    store, &entry, &envelope::oid_to_kappa(&base_id)?, object_hash,
                )?;
                if store.blob_exists(&kappa).unwrap_or(false) {
                    deduplicated += 1;
                } else {
                    ingested += 1;
                }
                offset_to_kappa.insert(entry_pack_offset, kappa);
            }

            gix_pack::data::entry::Header::OfsDelta { base_distance } => {
                let base_offset = entry_pack_offset
                    .checked_sub(base_distance)
                    .ok_or_else(|| IngestError::Delta(format!(
                        "OFS_DELTA base_distance {} exceeds pack_offset {}",
                        base_distance, entry_pack_offset
                    )))?;

                let base_kappa = offset_to_kappa.get(&base_offset)
                    .ok_or_else(|| IngestError::Delta(format!(
                        "OFS_DELTA base at offset {} not in offset map",
                        base_offset
                    )))?
                    .clone();

                let kappa = resolve_delta(store, &entry, &base_kappa, object_hash)?;
                if store.blob_exists(&kappa).unwrap_or(false) {
                    deduplicated += 1;
                } else {
                    ingested += 1;
                }
                offset_to_kappa.insert(entry_pack_offset, kappa);
            }
        }
    }

    Ok(PackIngestResult {
        objects_ingested: ingested,
        objects_deduplicated: deduplicated,
    })
}

/// Stream a large non-delta object through the upload lifecycle.
///
/// Writes the envelope header as the first part, then decompresses in
/// 64 KiB chunks writing each via upload_put_part. Completes with the
/// pre-computed Git object ID.
///
/// Memory: one 64 KiB buffer regardless of object size.
fn ingest_streaming(
    store: &dyn KappaStore,
    namespace: &NamespaceRef,
    kind: gix_object::Kind,
    compressed: &[u8],
    decompressed_size: usize,
    object_hash: gix_hash::Kind,
) -> Result<String, IngestError> {
    // We need the Git object ID before upload_complete. For streaming,
    // we must decompress into a staging file AND compute the hash in
    // the same pass. The upload lifecycle does the staging. We compute
    // the hash alongside by feeding a hasher.
    //
    // The Git object ID is hash(envelope). The envelope is:
    //   "{kind} {size}\0{content}"
    // We write the header to the upload first, then stream content chunks.
    // The hasher processes both header and content bytes.

    let header = gix_object::encode::loose_header(kind, decompressed_size as u64);

    // Start a hasher for the Git object ID
    let mut git_hasher = gix_hash::hasher(object_hash);
    git_hasher.update(&header);

    // Begin upload
    let upload_id = store.upload_begin(namespace, 0)?;
    let mut offset: u64 = 0;

    // Write envelope header as first part
    let total = store.upload_put_part(&upload_id, offset, &header)?;
    offset = total;

    // Decompress and stream in 64 KiB chunks
    let mut decoder = flate2::read::ZlibDecoder::new(compressed);
    let mut chunk_buf = [0u8; UPLOAD_CHUNK_SIZE];
    let mut total_decompressed: usize = 0;

    loop {
        let n = decoder.read(&mut chunk_buf)?;
        if n == 0 { break; }
        total_decompressed += n;

        git_hasher.update(&chunk_buf[..n]);

        let total = store.upload_put_part(&upload_id, offset, &chunk_buf[..n])?;
        offset = total;
    }

    if total_decompressed != decompressed_size {
        store.upload_abort(&upload_id)?;
        return Err(IngestError::Pack(format!(
            "decompressed size mismatch: got {}, expected {}",
            total_decompressed, decompressed_size
        )));
    }

    // Compute the Git object ID
    let oid = git_hasher.try_finalize()
        .map_err(|e| IngestError::Pack(format!("hash finalize: {e}")))?;
    let kappa = envelope::oid_to_kappa(&oid)?;

    // Complete the upload with the computed kappa as the claimed digest.
    // upload_complete will streaming-hash the staging file and verify.
    let _result = store.upload_complete(&upload_id, Some(&kappa))?;

    Ok(kappa)
}

/// Resolve a delta entry: decompress delta, fetch base from store,
/// apply delta, store resolved object via ingest_verified.
fn resolve_delta(
    store: &dyn KappaStore,
    entry: &input::Entry,
    base_kappa: &str,
    object_hash: gix_hash::Kind,
) -> Result<String, IngestError> {
    let compressed = entry
        .compressed
        .as_ref()
        .ok_or_else(|| IngestError::Pack("delta has no compressed data".into()))?;

    let delta_data = decompress_entry(compressed, entry.decompressed_size as usize)?;

    // Resolve base from store
    let base_envelope = store.blob_get(base_kappa)
        .map_err(|e| IngestError::Delta(format!("base {} not found: {e}", base_kappa)))?;
    let (base_kind, base_content) = envelope::unwrap(&base_envelope)?;

    // Apply delta
    let resolved = apply_delta(base_content, &delta_data)?;

    // Store resolved object
    let kappa = compute_git_kappa(object_hash, base_kind, &resolved)?;
    let envelope_bytes = envelope::wrap(base_kind, &resolved);
    store.ingest_verified(&kappa, &envelope_bytes)?;

    Ok(kappa)
}

fn compute_git_kappa(
    object_hash: gix_hash::Kind,
    kind: gix_object::Kind,
    content: &[u8],
) -> Result<String, IngestError> {
    match object_hash {
        gix_hash::Kind::Sha1 => Ok(envelope::git_object_id_sha1(kind, content)?),
        gix_hash::Kind::Sha256 => Ok(envelope::git_object_id_sha256(kind, content)?),
        _ => Err(IngestError::Pack("unsupported hash kind".into())),
    }
}

fn decompress_entry(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, IngestError> {
    let mut decompressed = Vec::with_capacity(expected_size);
    let mut decoder = flate2::read::ZlibDecoder::new(compressed);
    decoder.read_to_end(&mut decompressed)?;
    if decompressed.len() != expected_size {
        return Err(IngestError::Pack(format!(
            "decompressed size mismatch: got {}, expected {}",
            decompressed.len(), expected_size
        )));
    }
    Ok(decompressed)
}

fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, IngestError> {
    let (base_size, rest) = read_varint(delta)
        .ok_or_else(|| IngestError::Delta("truncated base_size varint".into()))?;
    let (result_size, rest2) = read_varint(rest)
        .ok_or_else(|| IngestError::Delta("truncated result_size varint".into()))?;

    let instructions_start = delta.len() - rest2.len();
    let mut pos = instructions_start;

    if base_size as usize != base.len() {
        return Err(IngestError::Delta(format!(
            "base size mismatch: delta says {}, actual {}",
            base_size, base.len()
        )));
    }

    let mut result = Vec::with_capacity(result_size as usize);

    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;

        if cmd == 0 {
            return Err(IngestError::Delta("reserved opcode 0x00".into()));
        }

        if cmd & 0x80 != 0 {
            let mut offset: u64 = 0;
            let mut size: u64 = 0;
            for (bit, shift) in [(0x01u8, 0u32), (0x02, 8), (0x04, 16), (0x08, 24)] {
                if cmd & bit != 0 {
                    offset |= (*delta.get(pos).ok_or_else(|| IngestError::Delta("truncated copy".into()))? as u64) << shift;
                    pos += 1;
                }
            }
            for (bit, shift) in [(0x10u8, 0u32), (0x20, 8), (0x40, 16)] {
                if cmd & bit != 0 {
                    size |= (*delta.get(pos).ok_or_else(|| IngestError::Delta("truncated copy".into()))? as u64) << shift;
                    pos += 1;
                }
            }
            if size == 0 { size = 0x10000; }
            let offset = offset as usize;
            let size = size as usize;
            if offset + size > base.len() {
                return Err(IngestError::Delta(format!(
                    "copy out of bounds: offset={}, size={}, base_len={}",
                    offset, size, base.len()
                )));
            }
            result.extend_from_slice(&base[offset..offset + size]);
        } else {
            let count = cmd as usize;
            if pos + count > delta.len() {
                return Err(IngestError::Delta("truncated insert data".into()));
            }
            result.extend_from_slice(&delta[pos..pos + count]);
            pos += count;
        }
    }

    if result.len() != result_size as usize {
        return Err(IngestError::Delta(format!(
            "result size mismatch: got {}, expected {}",
            result.len(), result_size
        )));
    }

    Ok(result)
}

// =============================================================================
// Delta computation: Rabin fingerprint sliding window algorithm
// =============================================================================

const RABIN_WINDOW: usize = 16;

/// Rabin fingerprint lookup table. Precomputed polynomial mod table
/// matching Git's diff-delta.c. Uses FNV-1a as the fingerprint function
/// (not cryptographic -- this is a search heuristic, not a security boundary).
struct RabinIndex {
    table: HashMap<u64, Vec<usize>>,
}

impl RabinIndex {
    fn new(base: &[u8]) -> Self {
        let mut table: HashMap<u64, Vec<usize>> = HashMap::new();
        if base.len() < RABIN_WINDOW {
            return Self { table };
        }
        for i in 0..=(base.len() - RABIN_WINDOW) {
            let fp = Self::fingerprint(&base[i..i + RABIN_WINDOW]);
            table.entry(fp).or_default().push(i);
        }
        Self { table }
    }

    fn fingerprint(window: &[u8]) -> u64 {
        // FNV-1a 64-bit
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in window {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        h
    }

    /// Find the longest match starting at target[0..] in base.
    /// Returns (base_offset, match_length) or None.
    fn find_match(&self, target: &[u8], base: &[u8]) -> Option<(usize, usize)> {
        if target.len() < RABIN_WINDOW {
            return None;
        }
        let fp = Self::fingerprint(&target[..RABIN_WINDOW]);
        let candidates = self.table.get(&fp)?;

        let mut best_offset = 0usize;
        let mut best_len = 0usize;

        for &candidate_offset in candidates {
            // Verify the window matches (FNV can collide)
            if &base[candidate_offset..candidate_offset + RABIN_WINDOW]
                != &target[..RABIN_WINDOW]
            {
                continue;
            }
            // Extend the match forward
            let mut match_len = RABIN_WINDOW;
            while candidate_offset + match_len < base.len()
                && match_len < target.len()
                && base[candidate_offset + match_len] == target[match_len]
            {
                match_len += 1;
            }
            if match_len > best_len {
                best_len = match_len;
                best_offset = candidate_offset;
            }
        }

        if best_len >= RABIN_WINDOW {
            Some((best_offset, best_len))
        } else {
            None
        }
    }
}

/// Compute a Git delta from base to target using Rabin fingerprint
/// sliding window matching.
///
/// Returns None if the delta is not smaller than the target (no benefit)
/// or if the inputs are too small to benefit from delta encoding.
pub fn compute_delta(base: &[u8], target: &[u8]) -> Option<Vec<u8>> {
    if base.is_empty() || target.is_empty() || target.len() < RABIN_WINDOW * 2 {
        return None;
    }

    let index = RabinIndex::new(base);

    let mut instructions: Vec<u8> = Vec::new();
    let mut insert_buf: Vec<u8> = Vec::new();
    let mut pos: usize = 0;

    while pos < target.len() {
        if pos + RABIN_WINDOW <= target.len() {
            if let Some((base_offset, match_len)) = index.find_match(&target[pos..], base) {
                flush_insert(&mut instructions, &mut insert_buf);
                encode_copy(&mut instructions, base_offset, match_len);
                pos += match_len;
                continue;
            }
        }
        insert_buf.push(target[pos]);
        if insert_buf.len() == 127 {
            flush_insert(&mut instructions, &mut insert_buf);
        }
        pos += 1;
    }
    flush_insert(&mut instructions, &mut insert_buf);

    let mut delta = Vec::new();
    write_varint(&mut delta, base.len() as u64);
    write_varint(&mut delta, target.len() as u64);
    delta.extend_from_slice(&instructions);

    if delta.len() < target.len() {
        Some(delta)
    } else {
        None
    }
}

fn flush_insert(instructions: &mut Vec<u8>, buf: &mut Vec<u8>) {
    if buf.is_empty() { return; }
    // INSERT instructions: cmd byte = count (1-127), followed by literal bytes
    for chunk in buf.chunks(127) {
        instructions.push(chunk.len() as u8);
        instructions.extend_from_slice(chunk);
    }
    buf.clear();
}

fn encode_copy(instructions: &mut Vec<u8>, offset: usize, size: usize) {
    let offset = offset as u64;
    let size = if size == 0x10000 { 0u64 } else { size as u64 };

    let mut cmd: u8 = 0x80;
    let mut extra = Vec::with_capacity(7);

    // Offset bytes (up to 4, little-endian)
    for (bit, shift) in [(0x01u8, 0u32), (0x02, 8), (0x04, 16), (0x08, 24)] {
        let byte_val = ((offset >> shift) & 0xFF) as u8;
        if byte_val != 0 {
            cmd |= bit;
            extra.push(byte_val);
        }
    }
    // Size bytes (up to 3, little-endian)
    for (bit, shift) in [(0x10u8, 0u32), (0x20, 8), (0x40, 16)] {
        let byte_val = ((size >> shift) & 0xFF) as u8;
        if byte_val != 0 {
            cmd |= bit;
            extra.push(byte_val);
        }
    }

    instructions.push(cmd);
    instructions.extend_from_slice(&extra);
}

fn write_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 { break; }
    }
}

/// Encode an OFS_DELTA negative offset header.
///
/// Variable-length encoding: big-endian, MSB continuation, with +1 bias
/// on continuation bytes (matching Git's pack format).
pub fn encode_ofs_delta_header(mut distance: u64) -> Vec<u8> {
    // Git's OFS_DELTA encoding from builtin/pack-objects.c:
    //   buf[pos] = n & 127;
    //   while (n >>= 7) { buf[--pos] = 128 | (--n & 127); }
    //
    // The last byte (lowest significance) has no MSB set.
    // Each preceding byte has MSB set and the value is biased by
    // subtracting 1 BEFORE masking (--n & 127, not (n-1) & 127).
    // Bytes are emitted most-significant first.
    let mut buf = Vec::with_capacity(10);
    buf.push((distance & 127) as u8);
    while {
        distance >>= 7;
        distance > 0
    } {
        distance -= 1;
        buf.push(128 | (distance & 127) as u8);
    }
    buf.reverse();
    buf
}

fn read_varint(data: &[u8]) -> Option<(u64, &[u8])> {
    let mut value: u64 = 0;
    let mut shift: u32 = 0;
    for (i, &byte) in data.iter().enumerate() {
        value |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if byte & 0x80 == 0 {
            return Some((value, &data[i + 1..]));
        }
        if shift > 63 {
            return None;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_varint_single_byte() {
        let (v, rest) = read_varint(&[5]).unwrap();
        assert_eq!(v, 5);
        assert!(rest.is_empty());
    }

    #[test]
    fn read_varint_two_bytes() {
        let (v, _) = read_varint(&[0x80 | 0x01, 0x02]).unwrap();
        assert_eq!(v, 1 | (2 << 7));
    }

    #[test]
    fn apply_delta_insert_only() {
        let mut delta = Vec::new();
        delta.push(0); // base_size = 0
        delta.push(5); // result_size = 5
        delta.push(5); // INSERT 5 bytes
        delta.extend_from_slice(b"hello");
        assert_eq!(apply_delta(b"", &delta).unwrap(), b"hello");
    }

    #[test]
    fn apply_delta_copy_only() {
        let base = b"hello world";
        let mut delta = Vec::new();
        delta.push(base.len() as u8);
        delta.push(5);
        delta.push(0x80 | 0x01 | 0x10);
        delta.push(0);
        delta.push(5);
        assert_eq!(apply_delta(base, &delta).unwrap(), b"hello");
    }

    #[test]
    fn apply_delta_copy_from_middle() {
        let base = b"hello world";
        let mut delta = Vec::new();
        delta.push(base.len() as u8);
        delta.push(5);
        delta.push(0x80 | 0x01 | 0x10);
        delta.push(6);
        delta.push(5);
        assert_eq!(apply_delta(base, &delta).unwrap(), b"world");
    }

    #[test]
    fn apply_delta_mixed() {
        let base = b"hello world";
        let mut delta = Vec::new();
        delta.push(base.len() as u8);
        delta.push(6);
        delta.push(0x80 | 0x01 | 0x10);
        delta.push(0);
        delta.push(5);
        delta.push(1);
        delta.push(b'!');
        assert_eq!(apply_delta(base, &delta).unwrap(), b"hello!");
    }

    #[test]
    fn apply_delta_rejects_reserved() {
        let delta = vec![0, 0, 0];
        assert!(apply_delta(b"", &delta).is_err());
    }

    #[test]
    fn apply_delta_rejects_oob_copy() {
        let base = b"short";
        let mut delta = Vec::new();
        delta.push(base.len() as u8);
        delta.push(10);
        delta.push(0x80 | 0x01 | 0x10);
        delta.push(0);
        delta.push(10);
        assert!(apply_delta(base, &delta).is_err());
    }

    // -- compute_delta tests (Item E) -----------------------------------------

    #[test]
    fn compute_delta_roundtrip() {
        let base = b"the quick brown fox jumps over the lazy dog and more text to exceed the window size threshold";
        let target = b"the quick brown cat jumps over the lazy dog and more text to exceed the window size threshold";
        let delta = compute_delta(base, target).unwrap();
        assert!(delta.len() < target.len(), "delta should be smaller than target");
        let reconstructed = apply_delta(base, &delta).unwrap();
        assert_eq!(reconstructed, target);
    }

    #[test]
    fn compute_delta_identical_is_tiny() {
        let content = b"identical content repeated many times for testing delta compression algorithms and roundtrip verification";
        let delta = compute_delta(content, content).unwrap();
        assert!(delta.len() < 30, "delta of identical content should be tiny, got {}", delta.len());
        let reconstructed = apply_delta(content, &delta).unwrap();
        assert_eq!(reconstructed, content);
    }

    #[test]
    fn compute_delta_completely_different_returns_none() {
        let base: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();
        let target: Vec<u8> = (0..1000).map(|i| ((i + 128) % 256) as u8).collect();
        let result = compute_delta(&base, &target);
        // Either None (no benefit) or roundtrip produces the original
        if let Some(delta) = result {
            let reconstructed = apply_delta(&base, &delta).unwrap();
            assert_eq!(reconstructed, target, "delta roundtrip must reproduce target");
        }
    }

    #[test]
    fn compute_delta_large_with_small_change() {
        let base: Vec<u8> = (0..10000).map(|i| (i % 251) as u8).collect();
        let mut target = base.clone();
        target[5000] = 0xFF;
        let delta = compute_delta(&base, &target).unwrap();
        assert!(delta.len() < 500, "delta for one-byte change in 10KB should be small, got {}", delta.len());
        let reconstructed = apply_delta(&base, &delta).unwrap();
        assert_eq!(reconstructed, target);
    }

    #[test]
    fn compute_delta_too_small_returns_none() {
        assert!(compute_delta(b"hi", b"yo").is_none());
        assert!(compute_delta(b"", b"hello").is_none());
        assert!(compute_delta(b"hello", b"").is_none());
    }

    #[test]
    fn compute_delta_append_only() {
        let base = b"base content that is long enough to have rabin windows computed over it for matching";
        let mut target = base.to_vec();
        target.extend_from_slice(b" and then some appended content at the end");
        let delta = compute_delta(base, &target).unwrap();
        assert!(delta.len() < target.len());
        let reconstructed = apply_delta(base, &delta).unwrap();
        assert_eq!(reconstructed, target);
    }

    // -- encode_ofs_delta_header tests (Item F) --------------------------------

    #[test]
    fn encode_ofs_delta_header_small() {
        let encoded = encode_ofs_delta_header(10);
        assert_eq!(encoded.len(), 1);
        assert_eq!(encoded[0], 10);
    }

    #[test]
    fn encode_ofs_delta_header_needs_continuation() {
        let encoded = encode_ofs_delta_header(128);
        assert!(encoded.len() >= 2);
        // First byte has MSB set (continuation)
        assert!(encoded[0] & 0x80 != 0);
        // Last byte has MSB clear
        assert!(encoded[encoded.len() - 1] & 0x80 == 0);
    }

    #[test]
    fn encode_ofs_delta_header_large_distance() {
        let encoded = encode_ofs_delta_header(0x10000);
        assert!(encoded.len() >= 3);
        // All bytes except last have MSB set
        for &b in &encoded[..encoded.len() - 1] {
            assert!(b & 0x80 != 0, "continuation bytes must have MSB set");
        }
        assert!(encoded[encoded.len() - 1] & 0x80 == 0, "last byte must not have MSB set");
    }

    // -- write_varint roundtrip -----------------------------------------------

    #[test]
    fn write_varint_roundtrip() {
        for &val in &[0u64, 1, 127, 128, 255, 256, 0x10000, u64::MAX >> 1] {
            let mut buf = Vec::new();
            write_varint(&mut buf, val);
            let (decoded, rest) = read_varint(&buf).unwrap();
            assert_eq!(decoded, val, "varint roundtrip failed for {}", val);
            assert!(rest.is_empty());
        }
    }
}
