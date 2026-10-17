use std::collections::VecDeque;
use std::io::{self, Read, Write};

use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::blob::BlobStore;

use crate::delta;
use crate::envelope;

const DELTA_WINDOW: usize = 10;

#[derive(Debug)]
pub struct PackGenerateResult {
    pub objects_written: usize,
    pub bytes_written: u64,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PackGenError {
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("envelope error: {0}")]
    Envelope(#[from] envelope::EnvelopeError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("hash error: {0}")]
    Hash(String),
}

/// Generate a packfile with sorted objects and sliding-window delta
/// compression, reading every object as the repository namespace admitted
/// it.
pub fn generate_pack<W: Write, S: BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    object_kappas: &[Kappa],
    object_hash: gix_hash::Kind,
    name_hints: &std::collections::HashMap<Kappa, String>,
    progress: Option<&dyn Fn(u32, u32)>,
    mut writer: W,
) -> Result<PackGenerateResult, PackGenError> {
    let sorted = sort_objects(store, namespace, object_kappas, name_hints)?;
    let num_objects = u32::try_from(sorted.len())
        .map_err(|_| PackGenError::Hash("object count exceeds Git pack format".into()))?;

    let mut header = [0u8; 12];
    header[0..4].copy_from_slice(b"PACK");
    header[4..8].copy_from_slice(&2u32.to_be_bytes());
    header[8..12].copy_from_slice(&num_objects.to_be_bytes());

    let mut hasher = gix_hash::hasher(object_hash);
    hasher.update(&header);
    writer.write_all(&header)?;
    let mut total_bytes: u64 = 12;

    let mut window: VecDeque<(gix_object::Kind, Vec<u8>, u64)> =
        VecDeque::with_capacity(DELTA_WINDOW);

    for (idx, obj) in sorted.iter().enumerate() {
        let entry_offset = total_bytes;

        let envelope_bytes = store.blob_get_in(namespace, &obj.kappa)?;
        let (kind, content) = envelope::unwrap(&envelope_bytes).map_err(PackGenError::Envelope)?;
        let content = content.to_vec();

        // Try delta against window objects of same type
        let mut best_delta: Option<(Vec<u8>, u64)> = None;
        if content.len() >= 32 {
            for (w_kind, w_content, w_offset) in window.iter().rev() {
                if *w_kind != kind {
                    continue;
                }
                if let Some(d) = delta::compute_delta(w_content, &content) {
                    let is_better = match &best_delta {
                        Some((prev, _)) => d.len() < prev.len(),
                        None => true,
                    };
                    if is_better {
                        best_delta = Some((d, *w_offset));
                    }
                }
            }
        }

        if let Some((delta_bytes, base_offset)) = best_delta
            && delta_bytes.len() < content.len()
        {
            let distance = entry_offset - base_offset;
            let ofs_header = delta::encode_ofs_delta_header(distance);

            let entry_header = encode_pack_entry_header(6, delta_bytes.len() as u64);
            hasher.update(&entry_header);
            writer.write_all(&entry_header)?;
            total_bytes += entry_header.len() as u64;

            hasher.update(&ofs_header);
            writer.write_all(&ofs_header)?;
            total_bytes += ofs_header.len() as u64;

            let mut encoder =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            encoder.write_all(&delta_bytes)?;
            let compressed = encoder.finish()?;
            hasher.update(&compressed);
            writer.write_all(&compressed)?;
            total_bytes += compressed.len() as u64;

            window.push_back((kind, content, entry_offset));
            if window.len() > DELTA_WINDOW {
                window.pop_front();
            }

            if let Some(cb) = progress {
                cb(idx as u32 + 1, num_objects);
            }
            continue;
        }

        // Full object
        let type_id = kind_to_type_id(kind);
        let entry_header = encode_pack_entry_header(type_id, content.len() as u64);
        hasher.update(&entry_header);
        writer.write_all(&entry_header)?;
        total_bytes += entry_header.len() as u64;

        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&content)?;
        let compressed = encoder.finish()?;
        hasher.update(&compressed);
        writer.write_all(&compressed)?;
        total_bytes += compressed.len() as u64;

        window.push_back((kind, content, entry_offset));
        if window.len() > DELTA_WINDOW {
            window.pop_front();
        }

        if let Some(cb) = progress {
            cb(idx as u32 + 1, num_objects);
        }
    }

    let trailer = hasher
        .try_finalize()
        .map_err(|e| PackGenError::Hash(e.to_string()))?;
    writer.write_all(trailer.as_slice())?;
    total_bytes += trailer.as_slice().len() as u64;
    writer.flush()?;

    Ok(PackGenerateResult {
        objects_written: num_objects as usize,
        bytes_written: total_bytes,
    })
}

struct PackObject {
    kappa: Kappa,
    kind: gix_object::Kind,
    size: u64,
    name_hint: String,
}

fn sort_objects<S: BlobStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    kappas: &[Kappa],
    name_hints: &std::collections::HashMap<Kappa, String>,
) -> Result<Vec<PackObject>, PackGenError> {
    let mut objects: Vec<PackObject> = kappas
        .iter()
        .map(|kappa| {
            let mut reader = store.blob_open_in(namespace, kappa)?;
            let (kind, size) = read_envelope_header(&mut reader)?;
            let hint = name_hints.get(kappa).cloned().unwrap_or_default();
            Ok(PackObject {
                kappa: kappa.clone(),
                kind,
                size,
                name_hint: hint,
            })
        })
        .collect::<Result<_, PackGenError>>()?;

    objects.sort_by(|a, b| {
        let kind_ord = kind_sort_key(a.kind).cmp(&kind_sort_key(b.kind));
        kind_ord
            .then(a.name_hint.cmp(&b.name_hint))
            .then(b.size.cmp(&a.size))
    });

    Ok(objects)
}

fn kind_sort_key(kind: gix_object::Kind) -> u8 {
    match kind {
        gix_object::Kind::Commit => 0,
        gix_object::Kind::Tree => 1,
        gix_object::Kind::Blob => 2,
        gix_object::Kind::Tag => 3,
    }
}

fn kind_to_type_id(kind: gix_object::Kind) -> u8 {
    match kind {
        gix_object::Kind::Commit => 1,
        gix_object::Kind::Tree => 2,
        gix_object::Kind::Blob => 3,
        gix_object::Kind::Tag => 4,
    }
}

fn encode_pack_entry_header(type_id: u8, mut size: u64) -> Vec<u8> {
    let mut header = Vec::with_capacity(10);
    let mut first = (type_id << 4) | (size as u8 & 0x0F);
    size >>= 4;
    if size > 0 {
        first |= 0x80;
    }
    header.push(first);
    while size > 0 {
        let mut byte = size as u8 & 0x7F;
        size >>= 7;
        if size > 0 {
            byte |= 0x80;
        }
        header.push(byte);
    }
    header
}

/// Read the Git envelope header from a reader to determine Kind and
/// content size without reading the full content.
pub fn read_envelope_header(
    reader: &mut dyn Read,
) -> Result<(gix_object::Kind, u64), PackGenError> {
    let mut header_bytes = Vec::with_capacity(32);
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte)?;
        if n == 0 {
            return Err(PackGenError::Io(io::Error::other(
                "unexpected EOF in envelope header",
            )));
        }
        if byte[0] == 0 {
            break;
        }
        header_bytes.push(byte[0]);
        if header_bytes.len() > 64 {
            return Err(PackGenError::Io(io::Error::other(
                "envelope header too long",
            )));
        }
    }

    let header_str = std::str::from_utf8(&header_bytes)
        .map_err(|_| PackGenError::Io(io::Error::other("envelope header not utf8")))?;
    let space_pos = header_str
        .find(' ')
        .ok_or_else(|| PackGenError::Io(io::Error::other("no space in envelope header")))?;

    let kind = gix_object::Kind::from_bytes(&header_str.as_bytes()[..space_pos])
        .map_err(|e| PackGenError::Io(io::Error::other(e.to_string())))?;
    let size: u64 = header_str[space_pos + 1..]
        .parse()
        .map_err(|_| PackGenError::Io(io::Error::other("envelope size not decimal")))?;

    Ok((kind, size))
}
