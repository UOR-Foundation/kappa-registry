//! Pack generation: produce a packfile from stored objects.
//!
//! Small objects (under 256 KiB): read fully, compress, write.
//! Large objects: stream from blob_open through zlib encoder in
//! 64 KiB chunks. Memory: one 64 KiB buffer regardless of object size.

use std::io::{self, Read, Write};

use kappa_core::store::KappaStore;

use crate::envelope;

const STREAMING_THRESHOLD: usize = 256 * 1024;
const STREAM_CHUNK: usize = 64 * 1024;

#[derive(Debug)]
pub struct PackGenerateResult {
    pub objects_written: usize,
    pub bytes_written: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum PackGenError {
    #[error("store error: {0}")]
    Store(#[from] kappa_core::types::StoreError),
    #[error("envelope error: {0}")]
    Envelope(#[from] envelope::EnvelopeError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("hash error: {0}")]
    Hash(String),
}

/// Generate a packfile from a set of object kappa-labels.
///
/// Large objects are streamed via blob_open in 64 KiB chunks through
/// the zlib encoder. Memory stays under 256 KiB per object regardless
/// of size.
pub fn generate_pack<W: Write>(
    store: &dyn KappaStore,
    object_kappas: &[String],
    object_hash: gix_hash::Kind,
    mut writer: W,
) -> Result<PackGenerateResult, PackGenError> {
    let num_objects = object_kappas.len() as u32;

    let mut header = [0u8; 12];
    header[0..4].copy_from_slice(b"PACK");
    header[4..8].copy_from_slice(&2u32.to_be_bytes());
    header[8..12].copy_from_slice(&num_objects.to_be_bytes());

    let mut hasher = gix_hash::hasher(object_hash);
    hasher.update(&header);
    writer.write_all(&header)?;
    let mut total_bytes: u64 = 12;

    for kappa in object_kappas {
        // Determine object kind and content size without reading the full blob.
        // Read from blob_open, parse the envelope header from the first bytes.
        let mut reader = store.blob_open(kappa)?;
        let (kind, content_size) = read_envelope_header(&mut reader)?;

        let type_id = match kind {
            gix_object::Kind::Commit => 1u8,
            gix_object::Kind::Tree => 2,
            gix_object::Kind::Blob => 3,
            gix_object::Kind::Tag => 4,
        };

        // Write pack entry header
        let entry_header = encode_pack_entry_header(type_id, content_size);
        hasher.update(&entry_header);
        writer.write_all(&entry_header)?;
        total_bytes += entry_header.len() as u64;

        if content_size as usize <= STREAMING_THRESHOLD {
            // Small object: read remaining content, compress, write
            let mut content = Vec::with_capacity(content_size as usize);
            reader.read_to_end(&mut content)?;

            let mut encoder = flate2::write::ZlibEncoder::new(
                Vec::new(), flate2::Compression::default(),
            );
            encoder.write_all(&content)?;
            let compressed = encoder.finish()?;

            hasher.update(&compressed);
            writer.write_all(&compressed)?;
            total_bytes += compressed.len() as u64;
        } else {
            // Large object: stream through zlib encoder in 64 KiB chunks.
            // The compressed output goes to a HashingWriter that feeds both
            // the pack hasher and the output writer.
            let mut hashing_writer = HashingWriter {
                inner: &mut writer,
                hasher: &mut hasher,
                bytes_written: 0,
            };
            let mut encoder = flate2::write::ZlibEncoder::new(
                &mut hashing_writer, flate2::Compression::default(),
            );

            let mut chunk = [0u8; STREAM_CHUNK];
            loop {
                let n = reader.read(&mut chunk)?;
                if n == 0 { break; }
                encoder.write_all(&chunk[..n])?;
            }
            encoder.finish()?;
            total_bytes += hashing_writer.bytes_written;
        }
    }

    let trailer = hasher.try_finalize()
        .map_err(|e| PackGenError::Hash(e.to_string()))?;
    writer.write_all(trailer.as_slice())?;
    total_bytes += trailer.as_slice().len() as u64;
    writer.flush()?;

    Ok(PackGenerateResult {
        objects_written: num_objects as usize,
        bytes_written: total_bytes,
    })
}

/// Read just the Git envelope header from a reader to determine Kind
/// and content size without reading the full content.
///
/// The envelope is "{type} {size}\0". We read byte by byte until NUL,
/// parse the header, and leave the reader positioned at the content start.
fn read_envelope_header(reader: &mut dyn Read) -> Result<(gix_object::Kind, u64), PackGenError> {
    let mut header_bytes = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte)?;
        if n == 0 {
            return Err(PackGenError::Io(io::Error::other("unexpected EOF in envelope header")));
        }
        if byte[0] == 0 {
            break;
        }
        header_bytes.push(byte[0]);
        if header_bytes.len() > 64 {
            return Err(PackGenError::Io(io::Error::other("envelope header too long")));
        }
    }

    let header_str = std::str::from_utf8(&header_bytes)
        .map_err(|_| PackGenError::Io(io::Error::other("envelope header not utf8")))?;
    let space_pos = header_str.find(' ')
        .ok_or_else(|| PackGenError::Io(io::Error::other("no space in envelope header")))?;

    let kind = gix_object::Kind::from_bytes(header_str[..space_pos].as_bytes())
        .map_err(|e| PackGenError::Io(io::Error::other(e.to_string())))?;
    let size: u64 = header_str[space_pos + 1..].parse()
        .map_err(|_| PackGenError::Io(io::Error::other("envelope size not decimal")))?;

    Ok((kind, size))
}

/// Writer that feeds output to both the pack hasher and the underlying writer.
struct HashingWriter<'a, W: Write> {
    inner: &'a mut W,
    hasher: &'a mut gix_hash::Hasher,
    bytes_written: u64,
}

impl<'a, W: Write> Write for HashingWriter<'a, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.bytes_written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn encode_pack_entry_header(type_id: u8, mut size: u64) -> Vec<u8> {
    let mut header = Vec::with_capacity(10);
    let mut first = (type_id << 4) | (size as u8 & 0x0F);
    size >>= 4;
    if size > 0 { first |= 0x80; }
    header.push(first);
    while size > 0 {
        let mut byte = size as u8 & 0x7F;
        size >>= 7;
        if size > 0 { byte |= 0x80; }
        header.push(byte);
    }
    header
}

// -- Item 53: Pack sorting + sliding-window delta ----------------------------

const DELTA_WINDOW: usize = 10;

/// Object metadata for sorting.
struct PackObject {
    kappa: String,
    kind: gix_object::Kind,
    size: u64,
    name_hint: String,
}

/// Sort objects for pack generation: type, then name hint, then size descending.
/// This groups similar objects together so delta compression works better.
fn sort_objects(
    store: &dyn KappaStore,
    kappas: &[String],
    _name_hints: &std::collections::HashMap<String, String>,
) -> Vec<PackObject> {
    let mut objects: Vec<PackObject> = kappas.iter().filter_map(|kappa| {
        let envelope = store.blob_get(kappa).ok()?;
        let (kind, content) = crate::envelope::unwrap(&envelope).ok()?;
        let hint = _name_hints.get(kappa).cloned().unwrap_or_default();
        Some(PackObject {
            kappa: kappa.clone(),
            kind,
            size: content.len() as u64,
            name_hint: hint,
        })
    }).collect();

    objects.sort_by(|a, b| {
        let kind_ord = kind_sort_key(a.kind).cmp(&kind_sort_key(b.kind));
        kind_ord
            .then(a.name_hint.cmp(&b.name_hint))
            .then(b.size.cmp(&a.size)) // larger first for delta base
    });

    objects
}

fn kind_sort_key(kind: gix_object::Kind) -> u8 {
    match kind {
        gix_object::Kind::Commit => 0,
        gix_object::Kind::Tree => 1,
        gix_object::Kind::Blob => 2,
        gix_object::Kind::Tag => 3,
    }
}

/// Generate a pack with sorted objects, sliding-window delta compression,
/// and progress reporting.
///
/// `name_hints` maps kappa to the filename from tree entries (for sorting).
/// `progress` is called with (objects_written, total_objects) after each object.
pub fn generate_pack_sorted<W: Write>(
    store: &dyn KappaStore,
    object_kappas: &[String],
    object_hash: gix_hash::Kind,
    name_hints: &std::collections::HashMap<String, String>,
    progress: Option<&dyn Fn(u32, u32)>,
    mut writer: W,
) -> Result<PackGenerateResult, PackGenError> {
    let sorted = sort_objects(store, object_kappas, name_hints);
    let num_objects = sorted.len() as u32;

    let mut header = [0u8; 12];
    header[0..4].copy_from_slice(b"PACK");
    header[4..8].copy_from_slice(&2u32.to_be_bytes());
    header[8..12].copy_from_slice(&num_objects.to_be_bytes());

    let mut hasher = gix_hash::hasher(object_hash);
    hasher.update(&header);
    writer.write_all(&header)?;
    let mut total_bytes: u64 = 12;

    // Sliding window of recent object contents for delta base selection
    let mut window: std::collections::VecDeque<(gix_object::Kind, Vec<u8>, u64)> =
        std::collections::VecDeque::with_capacity(DELTA_WINDOW);
    // Track pack offsets for OFS_DELTA encoding
    let mut kappa_to_offset: std::collections::HashMap<String, u64> = std::collections::HashMap::new();

    for (idx, obj) in sorted.iter().enumerate() {
        let entry_offset = total_bytes;
        kappa_to_offset.insert(obj.kappa.clone(), entry_offset);

        let envelope = store.blob_get(&obj.kappa)?;
        let (kind, content) = crate::envelope::unwrap(&envelope)
            .map_err(|e| PackGenError::Envelope(e))?;
        let content = content.to_vec();

        // Try delta against window objects of same type
        let mut best_delta: Option<(Vec<u8>, u64)> = None; // (delta_bytes, base_offset)
        if content.len() >= 32 {
            for (w_kind, w_content, w_offset) in window.iter().rev() {
                if *w_kind != kind { continue; }
                if let Some(delta) = crate::ingest::compute_delta(w_content, &content) {
                    let is_better = match &best_delta {
                        Some((prev, _)) => delta.len() < prev.len(),
                        None => true,
                    };
                    if is_better {
                        best_delta = Some((delta, *w_offset));
                    }
                }
            }
        }

        if let Some((delta, base_offset)) = best_delta {
            if delta.len() < content.len() {
                // Write as OFS_DELTA
                let distance = entry_offset - base_offset;
                let ofs_header = crate::ingest::encode_ofs_delta_header(distance);

                // Pack entry header: type 6 (OFS_DELTA), size = delta.len()
                let entry_header = encode_pack_entry_header(6, delta.len() as u64);
                hasher.update(&entry_header);
                writer.write_all(&entry_header)?;
                total_bytes += entry_header.len() as u64;

                hasher.update(&ofs_header);
                writer.write_all(&ofs_header)?;
                total_bytes += ofs_header.len() as u64;

                // Compress delta
                let mut encoder = flate2::write::ZlibEncoder::new(
                    Vec::new(), flate2::Compression::default(),
                );
                encoder.write_all(&delta)?;
                let compressed = encoder.finish()?;
                hasher.update(&compressed);
                writer.write_all(&compressed)?;
                total_bytes += compressed.len() as u64;

                // Add to window (use full content, not delta, as future base)
                window.push_back((kind, content, entry_offset));
                if window.len() > DELTA_WINDOW {
                    window.pop_front();
                }

                if let Some(cb) = progress {
                    cb(idx as u32 + 1, num_objects);
                }
                continue;
            }
        }

        // Write as full object
        let type_id = match kind {
            gix_object::Kind::Commit => 1u8,
            gix_object::Kind::Tree => 2,
            gix_object::Kind::Blob => 3,
            gix_object::Kind::Tag => 4,
        };

        let entry_header = encode_pack_entry_header(type_id, content.len() as u64);
        hasher.update(&entry_header);
        writer.write_all(&entry_header)?;
        total_bytes += entry_header.len() as u64;

        let mut encoder = flate2::write::ZlibEncoder::new(
            Vec::new(), flate2::Compression::default(),
        );
        encoder.write_all(&content)?;
        let compressed = encoder.finish()?;
        hasher.update(&compressed);
        writer.write_all(&compressed)?;
        total_bytes += compressed.len() as u64;

        // Add to sliding window
        window.push_back((kind, content, entry_offset));
        if window.len() > DELTA_WINDOW {
            window.pop_front();
        }

        if let Some(cb) = progress {
            cb(idx as u32 + 1, num_objects);
        }
    }

    let trailer = hasher.try_finalize()
        .map_err(|e| PackGenError::Hash(e.to_string()))?;
    writer.write_all(trailer.as_slice())?;
    total_bytes += trailer.as_slice().len() as u64;
    writer.flush()?;

    Ok(PackGenerateResult {
        objects_written: num_objects as usize,
        bytes_written: total_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_header_small_blob() {
        let header = encode_pack_entry_header(3, 5);
        assert_eq!(header.len(), 1);
        assert_eq!(header[0], 0x35);
    }

    #[test]
    fn encode_header_large_blob() {
        let header = encode_pack_entry_header(3, 16);
        assert_eq!(header.len(), 2);
        assert_eq!(header[0], 0xB0);
        assert_eq!(header[1], 0x01);
    }

    #[test]
    fn encode_header_very_large() {
        let header = encode_pack_entry_header(3, 0x10000);
        assert!(header.len() >= 3);
        let (parsed_type, parsed_size) = decode_pack_entry_header(&header);
        assert_eq!(parsed_type, 3);
        assert_eq!(parsed_size, 0x10000);
    }

    fn decode_pack_entry_header(data: &[u8]) -> (u8, u64) {
        let first = data[0];
        let type_id = (first >> 4) & 0x07;
        let mut size = (first & 0x0F) as u64;
        let mut shift = 4u32;
        if first & 0x80 != 0 {
            let mut idx = 1;
            while idx < data.len() {
                let byte = data[idx];
                size |= ((byte & 0x7F) as u64) << shift;
                shift += 7;
                idx += 1;
                if byte & 0x80 == 0 { break; }
            }
        }
        (type_id, size)
    }

    #[test]
    fn generate_empty_pack() {
        use kappa_core::clock::ntp_lamport::NtpLamportClock;
        use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let clock = Arc::new(NtpLamportClock::new());
        let store = InMemoryStore::new(
            MemoryStoreConfig::new(tmp.path().join("blobs")),
            clock,
        ).unwrap();

        let mut output = Vec::new();
        let result = generate_pack(&store, &[], gix_hash::Kind::Sha1, &mut output).unwrap();
        assert_eq!(result.objects_written, 0);
        assert_eq!(output.len(), 12 + 20);
        assert_eq!(&output[0..4], b"PACK");
    }

    #[test]
    fn generate_pack_with_blob() {
        use kappa_core::clock::ntp_lamport::NtpLamportClock;
        use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
        use std::sync::Arc;

        let tmp = tempfile::tempdir().unwrap();
        let clock = Arc::new(NtpLamportClock::new());
        let store = InMemoryStore::new(
            MemoryStoreConfig::new(tmp.path().join("blobs")),
            clock,
        ).unwrap();

        let content = b"hello pack generation";
        let envelope_bytes = envelope::wrap(gix_object::Kind::Blob, content);
        let kappa = envelope::git_object_id_sha1(gix_object::Kind::Blob, content).unwrap();
        store.ingest_verified(&kappa, &envelope_bytes).unwrap();

        let mut output = Vec::new();
        let result = generate_pack(
            &store, &[kappa], gix_hash::Kind::Sha1, &mut output,
        ).unwrap();
        assert_eq!(result.objects_written, 1);
        assert_eq!(&output[0..4], b"PACK");
        assert_eq!(u32::from_be_bytes(output[8..12].try_into().unwrap()), 1);

        let (entry_type, entry_size) = decode_pack_entry_header(&output[12..]);
        assert_eq!(entry_type, 3);
        assert_eq!(entry_size, content.len() as u64);
    }

    #[test]
    fn read_envelope_header_parses_correctly() {
        let content = b"test content for header parsing";
        let envelope = envelope::wrap(gix_object::Kind::Blob, content);
        let mut cursor = std::io::Cursor::new(envelope);
        let (kind, size) = read_envelope_header(&mut cursor).unwrap();
        assert_eq!(kind, gix_object::Kind::Blob);
        assert_eq!(size, content.len() as u64);

        // Reader should be positioned at content start
        let mut remaining = Vec::new();
        cursor.read_to_end(&mut remaining).unwrap();
        assert_eq!(remaining, content);
    }
}
