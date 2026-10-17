//! Packfile ingest into an execution.
//!
//! Every object is prepared through the store outside the writer
//! (`ContentPreparation::prepare_content`, streaming the decompressed
//! envelope and computing its git identity) and installed in the caller's
//! execution, so the pack's objects publish with the refs that name them
//! and a rejected push leaves no object behind. Delta bases are read
//! through the execution's view, which includes the objects this pack
//! installed before them. A resolved delta is admitted against the
//! per-object bound and the node's shared delta budget before its result
//! is allocated; a pack that declares more than the node admits is
//! refused with a typed error, never served from memory it was not
//! granted.

use std::collections::HashMap;
use std::io::{self, BufRead, Read};
use std::sync::Arc;

use gix_pack::data::input::{self, BytesToEntriesIter};

use kappa_store::axis::Axis;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::{ContentIdentity, ContentPreparation, ExecutionWrites, PreparationBounds};

use crate::delta;
use crate::envelope;

#[derive(Debug)]
pub struct PackIngestResult {
    pub objects_ingested: usize,
    pub objects_deduplicated: usize,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum IngestError {
    #[error("pack parse error: {0}")]
    Pack(String),
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("envelope error: {0}")]
    Envelope(#[from] envelope::EnvelopeError),
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("delta error: {0}")]
    Delta(#[from] delta::DeltaError),
    #[error("unknown entry type in pack")]
    UnknownEntryType,
}

/// The kappa axis whose digest of an object envelope is the git object id.
pub fn object_axis(object_hash: gix_hash::Kind) -> Result<Axis, IngestError> {
    match object_hash {
        gix_hash::Kind::Sha1 => Ok(Axis::Sha1),
        gix_hash::Kind::Sha256 => Ok(Axis::Sha256),
        other => Err(IngestError::Pack(format!(
            "unsupported object hash of {} bytes",
            other.len_in_bytes()
        ))),
    }
}

/// Ingest a packfile stream: prepare every object through `store` and
/// install it in `execution`. Delta results are bounded by
/// `bounds.maximum` and reserved against `budget`.
pub fn ingest_pack<R: BufRead, S: ContentPreparation + ?Sized, E: ExecutionWrites + ?Sized>(
    store: &S,
    execution: &mut E,
    pack_stream: R,
    object_hash: gix_hash::Kind,
    bounds: PreparationBounds,
    budget: &Arc<delta::DeltaBudget>,
) -> Result<PackIngestResult, IngestError> {
    let axis = object_axis(object_hash)?;
    let iter = BytesToEntriesIter::new_from_header(
        pack_stream,
        input::Mode::Verify,
        input::EntryDataMode::Keep,
        object_hash,
    )
    .map_err(|e| IngestError::Pack(e.to_string()))?;

    let mut offset_to_kappa: HashMap<u64, Kappa> = HashMap::new();
    let mut ingested = 0usize;
    let mut deduplicated = 0usize;

    for entry_result in iter {
        let entry = entry_result.map_err(|e| IngestError::Pack(e.to_string()))?;
        let entry_pack_offset = entry.pack_offset;
        let compressed = entry
            .compressed
            .as_ref()
            .ok_or_else(|| IngestError::Pack("entry has no compressed data".into()))?;
        let decompressed_size = entry.decompressed_size;

        let (kappa, newly_stored) = match entry.header {
            gix_pack::data::entry::Header::Commit
            | gix_pack::data::entry::Header::Tree
            | gix_pack::data::entry::Header::Blob
            | gix_pack::data::entry::Header::Tag => {
                let kind = entry
                    .header
                    .as_kind()
                    .ok_or(IngestError::UnknownEntryType)?;
                install_object(
                    store,
                    execution,
                    axis,
                    kind,
                    compressed,
                    decompressed_size,
                    bounds,
                )?
            }
            gix_pack::data::entry::Header::RefDelta { base_id } => {
                let base_kappa_str = envelope::oid_to_kappa(&base_id)?;
                let base_kappa =
                    Kappa::parse(&base_kappa_str).map_err(|e| IngestError::Pack(e.to_string()))?;
                resolve_delta(
                    store,
                    execution,
                    axis,
                    compressed,
                    decompressed_size,
                    &base_kappa,
                    bounds,
                    budget,
                )?
            }
            gix_pack::data::entry::Header::OfsDelta { base_distance } => {
                let base_offset = entry_pack_offset
                    .checked_sub(base_distance)
                    .ok_or_else(|| {
                        IngestError::Pack(format!(
                            "OFS_DELTA base_distance {base_distance} exceeds pack_offset {entry_pack_offset}"
                        ))
                    })?;
                let base_kappa = offset_to_kappa
                    .get(&base_offset)
                    .ok_or_else(|| {
                        IngestError::Pack(format!(
                            "OFS_DELTA base at offset {base_offset} not in offset map"
                        ))
                    })?
                    .clone();
                resolve_delta(
                    store,
                    execution,
                    axis,
                    compressed,
                    decompressed_size,
                    &base_kappa,
                    bounds,
                    budget,
                )?
            }
        };
        if newly_stored {
            ingested += 1;
        } else {
            deduplicated += 1;
        }
        offset_to_kappa.insert(entry_pack_offset, kappa);
    }

    Ok(PackIngestResult {
        objects_ingested: ingested,
        objects_deduplicated: deduplicated,
    })
}

/// Prepare one non-delta object by streaming its envelope (loose header
/// followed by the decompressed content) and install it. The declared
/// size is enforced: the stream is bounded one byte past it, so a longer
/// or shorter object disagrees with the prepared size and is rejected
/// before installation.
fn install_object<S: ContentPreparation + ?Sized, E: ExecutionWrites + ?Sized>(
    store: &S,
    execution: &mut E,
    axis: Axis,
    kind: gix_object::Kind,
    compressed: &[u8],
    decompressed_size: u64,
    bounds: PreparationBounds,
) -> Result<(Kappa, bool), IngestError> {
    let header = gix_object::encode::loose_header(kind, decompressed_size);
    let expected = decompressed_size
        .checked_add(header.len() as u64)
        .ok_or_else(|| IngestError::Pack("envelope size overflows".into()))?;
    let limit = decompressed_size
        .checked_add(1)
        .ok_or_else(|| IngestError::Pack("envelope size overflows".into()))?;
    let decoder = flate2::read::ZlibDecoder::new(compressed).take(limit);
    let mut envelope = header.as_slice().chain(decoder);
    let prepared = store.prepare_content(ContentIdentity::Computed(axis), &mut envelope, bounds)?;
    if prepared.total_size() != expected {
        return Err(IngestError::Pack(format!(
            "decompressed size mismatch: got {}, expected {decompressed_size}",
            prepared.total_size().saturating_sub(header.len() as u64)
        )));
    }
    let installed = execution.content_install(prepared)?;
    Ok((installed.kappa, installed.newly_stored))
}

/// Resolve a delta against its base, read through the execution's view,
/// and install the resolved object. The resolved bytes and their
/// envelope are held against the budget until the object is installed.
#[allow(clippy::too_many_arguments)]
fn resolve_delta<S: ContentPreparation + ?Sized, E: ExecutionWrites + ?Sized>(
    store: &S,
    execution: &mut E,
    axis: Axis,
    compressed: &[u8],
    decompressed_size: u64,
    base_kappa: &Kappa,
    bounds: PreparationBounds,
    budget: &Arc<delta::DeltaBudget>,
) -> Result<(Kappa, bool), IngestError> {
    let delta_size = usize::try_from(decompressed_size)
        .map_err(|_| IngestError::Pack("delta size exceeds the address space".into()))?;
    if u64::try_from(delta_size).is_ok_and(|size| size > bounds.maximum) {
        return Err(IngestError::Delta(delta::DeltaError::ResultTooLarge {
            declared: delta_size,
            limit: usize::try_from(bounds.maximum).unwrap_or(usize::MAX),
        }));
    }
    let delta_data = decompress_entry(compressed, delta_size)?;
    let base_envelope = execution
        .blob_get_verified(base_kappa, bounds.maximum)?
        .ok_or_else(|| IngestError::Pack(format!("base {base_kappa} not found")))?;
    let (base_kind, base_content) = envelope::unwrap(&base_envelope)?;
    let max_result = usize::try_from(bounds.maximum).unwrap_or(usize::MAX);
    let (resolved, mut held) = delta::apply_delta(base_content, &delta_data, max_result, budget)?;
    let envelope_bytes = envelope::wrap(base_kind, &resolved);
    held.grow(envelope_bytes.len().saturating_sub(resolved.len()))?;
    drop(resolved);
    let prepared = store.prepare_content(
        ContentIdentity::Computed(axis),
        &mut envelope_bytes.as_slice(),
        bounds,
    )?;
    let installed = execution.content_install(prepared)?;
    drop(envelope_bytes);
    drop(held);
    Ok((installed.kappa, installed.newly_stored))
}

fn decompress_entry(compressed: &[u8], expected_size: usize) -> Result<Vec<u8>, IngestError> {
    let mut decompressed = Vec::with_capacity(expected_size);
    let limit = u64::try_from(expected_size)
        .ok()
        .and_then(|size| size.checked_add(1))
        .ok_or_else(|| IngestError::Pack("entry size overflows".into()))?;
    flate2::read::ZlibDecoder::new(compressed)
        .take(limit)
        .read_to_end(&mut decompressed)?;
    if decompressed.len() != expected_size {
        return Err(IngestError::Pack(format!(
            "decompressed size mismatch: got {}, expected {expected_size}",
            decompressed.len()
        )));
    }
    Ok(decompressed)
}
