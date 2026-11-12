//! Reads of a namespace view's representations.
//!
//! One resolver ([`plan`]) turns an identity admitted in a view into the
//! ordered leaves its bytes are made of: file allocations and compressed
//! allocations, each with its exact length. Aliases resolve to their
//! holder, composites to their components, recursively, within
//! [`MAX_DEPTH`] levels and [`MAX_LEAVES`] leaves; a representation that
//! names itself through any chain is refused. Composition validates its
//! components through the same resolver, so every composite a namespace
//! admits is one this module can read.
//!
//! A plan holds the allocation of every leaf, so a read keeps every file it
//! may open for as long as it needs it, a reader for its whole life. Every
//! leaf is read with its exact length enforced as it is read: a file is
//! never read past its length plus one probe byte, and a compressed leaf's
//! decoded output must be exactly its length.
//!
//! Every step is charged to the operation's meter before it runs: each
//! representation examined, each buffer grown, each handle opened, each
//! byte read, decoded and hashed. A whole read is verified against the
//! identity. A reader (`blob_stream`) owns the rest of its operation's
//! meter and delivers bytes only from segments checked against the leaf's
//! segment digests (`segments`), so every byte it delivers, at any offset
//! and after any seek, is a byte proven to be its identity's.

use std::fs;
use std::io::{BufReader, Read};
use std::sync::Arc;

use kappa_store::compression::Codec;
use kappa_store::traits::blob::BlobReader;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::verified::VerifiedContent;
use kappa_types::work::{Dimension, Meter, WorkMeter, reserve_charged};

use super::allocation::Allocation;
use super::blob_stream::PlanReader;
use super::segments::Segments;
use super::view::{Held, NamespaceView, Representation};

/// Representation levels one resolution follows.
pub const MAX_DEPTH: usize = 16;
/// Leaves one resolution may produce.
pub const MAX_LEAVES: usize = 1 << 16;

/// Bytes of the buffer a compressed leaf's file is read through
/// (`BufReader::new`'s capacity).
pub const DECODER_INPUT_BUFFER: u64 = 8 * 1024;

/// One stored piece of a resolved identity: a file allocation, a
/// compressed allocation with its algorithm and the segment digests of its
/// decoded bytes, or bytes held in memory, with their retention charge,
/// and their digests.
#[derive(Clone)]
pub enum Leaf {
    File(Allocation),
    Compressed(Allocation, String, Segments),
    Inline(Arc<Held>, Segments),
}

impl Leaf {
    /// The segment digests of the bytes this leaf serves.
    pub(super) fn segments(&self) -> &Segments {
        match self {
            Self::File(allocation) => allocation.segments(),
            Self::Compressed(_, _, decoded) | Self::Inline(_, decoded) => decoded,
        }
    }
}

/// The leaves of a resolved identity, each with its exact length and the
/// logical offset it starts at.
pub struct Plan {
    pub(super) leaves: Vec<(Leaf, u64)>,
    pub(super) starts: Vec<u64>,
    total: u64,
}

impl Plan {
    pub const fn total(&self) -> u64 {
        self.total
    }

    /// Append `leaf` of `length` bytes, the growth of both lists and the
    /// leaf's own heap bytes charged to `work` first.
    fn push(&mut self, leaf: Leaf, length: u64, work: &mut dyn Meter) -> Result<(), StoreError> {
        if self.leaves.len() == MAX_LEAVES {
            return Err(StoreError::CapacityExceeded(format!(
                "representation resolves to more than {MAX_LEAVES} pieces"
            )));
        }
        let total = self.total.checked_add(length).ok_or_else(|| {
            StoreError::CapacityExceeded("representation length overflows".into())
        })?;
        reserve_charged(work, &mut self.leaves)?;
        reserve_charged(work, &mut self.starts)?;
        self.starts.push(self.total);
        self.total = total;
        self.leaves.push((leaf, length));
        Ok(())
    }
}

fn not_found(kappa: &Kappa) -> StoreError {
    StoreError::NotFound(kappa.to_string())
}

fn resolve(
    view: &NamespaceView,
    kappa: &Kappa,
    path: &mut Vec<Kappa>,
    plan: &mut Plan,
    work: &mut dyn Meter,
) -> Result<(), StoreError> {
    work.charge(Dimension::Entries, 1)?;
    let admission = view.held(kappa).ok_or_else(|| {
        if path.is_empty() {
            not_found(kappa)
        } else {
            StoreError::Internal(format!(
                "representation names {kappa}, which its namespace does not admit"
            ))
        }
    })?;
    work.charge(Dimension::Entries, path.len() as u64)?;
    if path.contains(kappa) {
        return Err(StoreError::Rejected(format!(
            "representation of {kappa} names itself"
        )));
    }
    if path.len() == MAX_DEPTH {
        return Err(StoreError::CapacityExceeded(format!(
            "representation of {kappa} is deeper than {MAX_DEPTH} levels"
        )));
    }
    reserve_charged(work, path)?;
    path.push(kappa.clone());
    let before = plan.total;
    match &admission.representation {
        Representation::File(allocation) => {
            plan.push(Leaf::File(allocation.clone()), admission.size, work)?;
        }
        Representation::Compressed {
            storage,
            algorithm,
            decoded,
        } => {
            work.charge(Dimension::BytesAllocated, algorithm.len() as u64)?;
            plan.push(
                Leaf::Compressed(storage.clone(), algorithm.clone(), decoded.clone()),
                admission.size,
                work,
            )?;
        }
        Representation::Inline { bytes, segments } => plan.push(
            Leaf::Inline(Arc::clone(bytes), segments.clone()),
            admission.size,
            work,
        )?,
        Representation::Alias(holder) => resolve(view, holder, path, plan, work)?,
        Representation::Composite(components) => {
            for (component, length) in components.iter() {
                let start = plan.total;
                resolve(view, component, path, plan, work)?;
                if plan.total - start != *length {
                    return Err(StoreError::Rejected(format!(
                        "composite {kappa} declares {length} bytes for {component}, which resolves to {}",
                        plan.total - start
                    )));
                }
            }
        }
    }
    path.pop();
    if plan.total - before != admission.size {
        return Err(StoreError::Internal(format!(
            "{kappa} admits {} bytes but resolves to {}",
            admission.size,
            plan.total - before
        )));
    }
    Ok(())
}

/// Resolve `kappa` in `view` on `work`: each representation examined and
/// each list grown is charged before it is.
pub fn plan(view: &NamespaceView, kappa: &Kappa, work: &mut dyn Meter) -> Result<Plan, StoreError> {
    let mut plan = Plan {
        leaves: Vec::new(),
        starts: Vec::new(),
        total: 0,
    };
    resolve(view, kappa, &mut Vec::new(), &mut plan, work)?;
    Ok(plan)
}

/// Logical size of `kappa` in `view`.
pub fn size(view: &NamespaceView, kappa: &Kappa) -> Result<u64, StoreError> {
    view.held(kappa)
        .map(|admission| admission.size)
        .ok_or_else(|| not_found(kappa))
}

pub(super) fn open_file(allocation: &Allocation) -> Result<fs::File, StoreError> {
    fs::File::open(allocation.path()).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            StoreError::Internal(format!(
                "allocation of {} is missing its file",
                allocation.storage()
            ))
        } else {
            StoreError::Io(error)
        }
    })
}

/// Read exactly `length` bytes from `reader` into `out`: one byte more is
/// read as a probe and refused. `out` has room for the `length` bytes, so
/// only a refused probe byte can grow it.
fn read_exact_length(
    reader: impl Read,
    length: u64,
    out: &mut Vec<u8>,
    what: &str,
) -> Result<(), StoreError> {
    let start = out.len();
    reader.take(length.saturating_add(1)).read_to_end(out)?;
    let read = (out.len() - start) as u64;
    if read != length {
        return Err(StoreError::Internal(format!(
            "{what} holds {read} bytes where {length} are admitted"
        )));
    }
    Ok(())
}

/// The bytes of one leaf, its exact length enforced, on `work`: the handle
/// opened, the bytes read (and, for a compressed leaf, the stored bytes
/// read through its input buffer and the bytes decoded), each with the
/// probe byte, charged before the leaf is opened.
fn leaf_bytes(
    leaf: &Leaf,
    length: u64,
    out: &mut Vec<u8>,
    work: &mut dyn Meter,
) -> Result<(), StoreError> {
    let probed = length.saturating_add(1);
    match leaf {
        Leaf::File(allocation) => {
            work.charge_all(&[(Dimension::Handles, 1), (Dimension::BytesRead, probed)])?;
            read_exact_length(open_file(allocation)?, length, out, "allocation")
        }
        Leaf::Compressed(storage, algorithm, _) => {
            let codec = Codec::of(algorithm)?;
            work.charge_all(&[
                (Dimension::Handles, 1),
                (Dimension::BytesAllocated, DECODER_INPUT_BUFFER),
                (Dimension::BytesAllocated, codec.working_bytes()),
                (Dimension::BytesRead, storage.bytes()),
                (Dimension::BytesDecoded, probed),
            ])?;
            let file = BufReader::new(open_file(storage)?);
            read_exact_length(
                codec.decoder(file)?,
                length,
                out,
                "compressed representation",
            )
        }
        Leaf::Inline(held, _) => {
            work.charge(Dimension::BytesRead, probed)?;
            read_exact_length(held.bytes(), length, out, "inline evidence")
        }
    }
}

/// The bytes of `kappa` in `view`, unverified, on `work`: refused before
/// reading when larger than `maximum`, the whole buffer charged before it
/// is allocated and every leaf charged before it is read.
pub fn bytes(
    view: &NamespaceView,
    kappa: &Kappa,
    maximum: Option<u64>,
    work: &mut dyn Meter,
) -> Result<Vec<u8>, StoreError> {
    let plan = plan(view, kappa, work)?;
    if let Some(maximum) = maximum
        && plan.total > maximum
    {
        return Err(StoreError::CapacityExceeded(format!(
            "content {kappa} is {} bytes, limit {maximum}",
            plan.total
        )));
    }
    let capacity = usize::try_from(plan.total)
        .map_err(|_| StoreError::CapacityExceeded("content exceeds address space".into()))?;
    work.charge(Dimension::BytesAllocated, plan.total)?;
    let mut out = Vec::with_capacity(capacity);
    for (leaf, length) in &plan.leaves {
        leaf_bytes(leaf, *length, &mut out, work)?;
    }
    Ok(out)
}

/// The bytes of `kappa` in `view`, verified against the identity, on
/// `work`: read as [`bytes`] reads them, the hash charged before it runs,
/// and the read buffer moved into the verified content.
pub fn verified(
    view: &NamespaceView,
    kappa: &Kappa,
    maximum: Option<u64>,
    work: &mut dyn Meter,
) -> Result<VerifiedContent, StoreError> {
    let data = bytes(view, kappa, maximum, work)?;
    work.charge(Dimension::BytesHashed, data.len() as u64)?;
    VerifiedContent::verify_owned(kappa, data)
        .map_err(|e| StoreError::Internal(format!("integrity check failed: {e}")))
}

/// The compressed allocation and algorithm `kappa` selects in `view`
/// directly or through aliases, if its representation is compressed,
/// resolved on `work`.
pub fn compressed(
    view: &NamespaceView,
    kappa: &Kappa,
    work: &mut dyn Meter,
) -> Result<Option<(Allocation, String)>, StoreError> {
    let plan = plan(view, kappa, work)?;
    match plan.leaves.as_slice() {
        [(Leaf::Compressed(storage, algorithm, _), _)] => {
            work.charge(Dimension::BytesAllocated, algorithm.len() as u64)?;
            Ok(Some((storage.clone(), algorithm.clone())))
        }
        _ => Ok(None),
    }
}

/// A reader of `kappa` in `view`, holding every allocation it may read:
/// resolved on `meter`, which the reader then owns for every read it
/// serves.
pub fn open(
    view: &NamespaceView,
    kappa: &Kappa,
    mut meter: WorkMeter,
) -> Result<Box<dyn BlobReader>, StoreError> {
    let plan = plan(view, kappa, &mut meter)?;
    Ok(Box::new(PlanReader::new(plan, meter)))
}

/// At most `length` bytes of `kappa` in `view` from `offset`, resolved and
/// read on `meter`: every segment the range touches is read and checked
/// as a reader reads it.
pub fn range(
    view: &NamespaceView,
    kappa: &Kappa,
    offset: u64,
    length: u64,
    mut meter: WorkMeter,
) -> Result<Vec<u8>, StoreError> {
    let plan = plan(view, kappa, &mut meter)?;
    PlanReader::new(plan, meter).range(offset, length)
}

#[cfg(test)]
#[path = "blob_read_tests.rs"]
mod tests;
