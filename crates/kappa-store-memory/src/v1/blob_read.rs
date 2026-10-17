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
//! A whole read is verified against the identity. A reader delivers bytes
//! only from segments checked against the leaf's segment digests
//! (`segments`), so every byte it delivers, at any offset and after any
//! seek, is a byte proven to be its identity's.

use std::fs;
use std::io::{BufReader, Read, Seek, SeekFrom};

use kappa_store::traits::blob::BlobReader;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::verified::VerifiedContent;

use super::allocation::Allocation;
use super::segments::Segments;
use super::view::{NamespaceView, Representation};

/// Representation levels one resolution follows.
pub const MAX_DEPTH: usize = 16;
/// Leaves one resolution may produce.
pub const MAX_LEAVES: usize = 1 << 16;

/// One stored piece of a resolved identity: a file allocation, or a
/// compressed allocation with its algorithm and the segment digests of its
/// decoded bytes.
#[derive(Clone)]
pub enum Leaf {
    File(Allocation),
    Compressed(Allocation, String, Segments),
}

impl Leaf {
    /// The segment digests of the bytes this leaf serves.
    fn segments(&self) -> &Segments {
        match self {
            Self::File(allocation) => allocation.segments(),
            Self::Compressed(_, _, decoded) => decoded,
        }
    }
}

/// The leaves of a resolved identity, each with its exact length and the
/// logical offset it starts at.
pub struct Plan {
    leaves: Vec<(Leaf, u64)>,
    starts: Vec<u64>,
    total: u64,
}

impl Plan {
    pub const fn total(&self) -> u64 {
        self.total
    }

    fn push(&mut self, leaf: Leaf, length: u64) -> Result<(), StoreError> {
        if self.leaves.len() == MAX_LEAVES {
            return Err(StoreError::CapacityExceeded(format!(
                "representation resolves to more than {MAX_LEAVES} pieces"
            )));
        }
        self.starts.push(self.total);
        self.total = self.total.checked_add(length).ok_or_else(|| {
            StoreError::CapacityExceeded("representation length overflows".into())
        })?;
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
) -> Result<(), StoreError> {
    let admission = view.admitted.get(kappa).ok_or_else(|| {
        if path.is_empty() {
            not_found(kappa)
        } else {
            StoreError::Internal(format!(
                "representation names {kappa}, which its namespace does not admit"
            ))
        }
    })?;
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
    path.push(kappa.clone());
    let before = plan.total;
    match &admission.representation {
        Representation::File(allocation) => {
            plan.push(Leaf::File(allocation.clone()), admission.size)?;
        }
        Representation::Compressed {
            storage,
            algorithm,
            decoded,
        } => plan.push(
            Leaf::Compressed(storage.clone(), algorithm.clone(), decoded.clone()),
            admission.size,
        )?,
        Representation::Alias(holder) => resolve(view, holder, path, plan)?,
        Representation::Composite(components) => {
            for (component, length) in components.iter() {
                let start = plan.total;
                resolve(view, component, path, plan)?;
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

/// Resolve `kappa` in `view`.
pub fn plan(view: &NamespaceView, kappa: &Kappa) -> Result<Plan, StoreError> {
    let mut plan = Plan {
        leaves: Vec::new(),
        starts: Vec::new(),
        total: 0,
    };
    resolve(view, kappa, &mut Vec::new(), &mut plan)?;
    Ok(plan)
}

/// Logical size of `kappa` in `view`.
pub fn size(view: &NamespaceView, kappa: &Kappa) -> Result<u64, StoreError> {
    view.admitted
        .get(kappa)
        .map(|admission| admission.size)
        .ok_or_else(|| not_found(kappa))
}

fn open_file(allocation: &Allocation) -> Result<fs::File, StoreError> {
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
/// read as a probe and refused.
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

/// The bytes of one leaf, its exact length enforced.
fn leaf_bytes(leaf: &Leaf, length: u64, out: &mut Vec<u8>) -> Result<(), StoreError> {
    match leaf {
        Leaf::File(allocation) => {
            read_exact_length(open_file(allocation)?, length, out, "allocation")
        }
        Leaf::Compressed(storage, algorithm, _) => {
            let file = BufReader::new(open_file(storage)?);
            read_exact_length(
                decoder(algorithm, file)?,
                length,
                out,
                "compressed representation",
            )
        }
    }
}

/// The bytes of `kappa` in `view`, unverified, refused before reading when
/// larger than `maximum`.
pub fn bytes(
    view: &NamespaceView,
    kappa: &Kappa,
    maximum: Option<u64>,
) -> Result<Vec<u8>, StoreError> {
    let plan = plan(view, kappa)?;
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
    let mut out = Vec::with_capacity(capacity);
    for (leaf, length) in &plan.leaves {
        leaf_bytes(leaf, *length, &mut out)?;
    }
    Ok(out)
}

/// The verified bytes of `kappa` in `view`.
pub fn verified(
    view: &NamespaceView,
    kappa: &Kappa,
    maximum: Option<u64>,
) -> Result<Vec<u8>, StoreError> {
    let data = bytes(view, kappa, maximum)?;
    VerifiedContent::verify(kappa, &data)
        .map_err(|e| StoreError::Internal(format!("integrity check failed: {e}")))?;
    Ok(data)
}

/// The compressed allocation and algorithm `kappa` selects in `view`
/// directly or through aliases, if its representation is compressed.
pub fn compressed(
    view: &NamespaceView,
    kappa: &Kappa,
) -> Result<Option<(Allocation, String)>, StoreError> {
    let plan = plan(view, kappa)?;
    match plan.leaves.as_slice() {
        [(Leaf::Compressed(storage, algorithm, _), _)] => {
            Ok(Some((storage.clone(), algorithm.clone())))
        }
        _ => Ok(None),
    }
}

/// A reader of `kappa` in `view`, holding every allocation it may read.
pub fn open(view: &NamespaceView, kappa: &Kappa) -> Result<Box<dyn BlobReader>, StoreError> {
    Ok(Box::new(PlanReader::new(plan(view, kappa)?)))
}

/// A resolved identity served leaf by leaf: one open leaf at a time, every
/// leaf's allocation held for the reader's life. Sequential reads continue
/// from the current leaf; a seek finds its leaf by binary search over the
/// leaf offsets. A compressed leaf is decoded as it is read, never held
/// whole: reading forward within it decodes forward, reading behind its
/// decoder reopens it.
///
/// A read is served from the segment of its leaf holding the position: the
/// whole segment is read, checked against the leaf's segment digests, and
/// kept for the reads that follow within it. A segment that fails its
/// check is never kept, so a reader delivers no byte that was not proven
/// to be its identity's, whatever its order of reads and seeks.
struct PlanReader {
    plan: Plan,
    position: u64,
    current: usize,
    open: Option<(usize, OpenLeaf)>,
    /// The checked segment last read: its leaf, its start within the leaf,
    /// and its bytes.
    segment: Option<(usize, u64, Vec<u8>)>,
}

enum OpenLeaf {
    File(fs::File),
    /// A decoder over a compressed leaf and the logical offset within the
    /// leaf it has decoded to.
    Decoding(Box<dyn Read + Send>, u64),
}

/// Bytes discarded per read while a decoder skips forward.
const SKIP_CHUNK: usize = 16 * 1024;

fn invalid_data(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

/// Refuse a piece that holds a byte past its admitted length.
fn probe_end(reader: &mut dyn Read) -> std::io::Result<()> {
    let mut probe = [0u8; 1];
    loop {
        match reader.read(&mut probe) {
            Ok(0) => return Ok(()),
            Ok(_) => {
                return Err(invalid_data(
                    "representation piece is longer than its length".into(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Decode forward from `at` to `to`, discarding the decoded bytes.
fn skip_to(decoding: &mut dyn Read, at: &mut u64, to: u64) -> std::io::Result<()> {
    let mut scratch = [0u8; SKIP_CHUNK];
    while *at < to {
        let skip = usize::try_from(to - *at)
            .unwrap_or(usize::MAX)
            .min(SKIP_CHUNK);
        match decoding.read(&mut scratch[..skip]) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "compressed piece decodes shorter than its length",
                ));
            }
            Ok(skipped) => *at += skipped as u64,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

impl PlanReader {
    const fn new(plan: Plan) -> Self {
        Self {
            plan,
            position: 0,
            current: 0,
            open: None,
            segment: None,
        }
    }

    fn leaf_at(&self, position: u64) -> usize {
        // The last leaf whose start is at or before the position.
        self.plan
            .starts
            .partition_point(|start| *start <= position)
            .saturating_sub(1)
    }

    fn open_leaf(leaf: &Leaf) -> std::io::Result<OpenLeaf> {
        Ok(match leaf {
            Leaf::File(allocation) => {
                OpenLeaf::File(open_file(allocation).map_err(std::io::Error::other)?)
            }
            Leaf::Compressed(storage, algorithm, _) => OpenLeaf::Decoding(
                decoder(
                    algorithm,
                    BufReader::new(open_file(storage).map_err(std::io::Error::other)?),
                )
                .map_err(std::io::Error::other)?,
                0,
            ),
        })
    }

    /// Read and check the segment of leaf `index` holding `within`, and
    /// keep it as the current segment.
    fn fill(&mut self, index: usize, within: u64) -> std::io::Result<()> {
        let (leaf, length) = &self.plan.leaves[index];
        let segments = leaf.segments();
        if segments.length() != *length {
            return Err(invalid_data(format!(
                "segment digests cover {} bytes of a {length}-byte piece",
                segments.length()
            )));
        }
        let (start, size) = segments.bounds(within);
        let reopen = match &self.open {
            Some((open, OpenLeaf::Decoding(_, at))) => *open != index || *at > start,
            Some((open, OpenLeaf::File(_))) => *open != index,
            None => true,
        };
        if reopen {
            self.open = Some((index, Self::open_leaf(leaf)?));
        }
        let Some((_, opened)) = self.open.as_mut() else {
            return Err(std::io::Error::other("leaf not open"));
        };
        // The previous segment's buffer is reused; nothing of it survives a
        // failed check.
        let mut bytes = self
            .segment
            .take()
            .map_or_else(Vec::new, |(_, _, bytes)| bytes);
        bytes.clear();
        bytes.resize(usize::try_from(size).map_err(std::io::Error::other)?, 0);
        let last = start + size == *length;
        match opened {
            OpenLeaf::File(file) => {
                file.seek(SeekFrom::Start(start))?;
                file.read_exact(&mut bytes)?;
                if last {
                    probe_end(file)?;
                }
            }
            OpenLeaf::Decoding(decoding, at) => {
                skip_to(decoding, at, start)?;
                decoding.read_exact(&mut bytes)?;
                *at += size;
                if last {
                    probe_end(decoding)?;
                }
            }
        }
        segments.check(start, &bytes)?;
        self.segment = Some((index, start, bytes));
        Ok(())
    }
}

impl Read for PlanReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.position >= self.plan.total {
            return Ok(0);
        }
        while self.current + 1 < self.plan.leaves.len()
            && self.plan.starts[self.current + 1] <= self.position
        {
            self.current += 1;
        }
        let index = self.current;
        let within = self.position - self.plan.starts[index];
        let held = matches!(
            &self.segment,
            Some((leaf, start, bytes)) if *leaf == index && *start <= within && within - start < bytes.len() as u64
        );
        if !held {
            self.fill(index, within)?;
        }
        let Some((_, start, bytes)) = &self.segment else {
            return Err(std::io::Error::other("segment not read"));
        };
        let offset = usize::try_from(within - start).map_err(std::io::Error::other)?;
        let count = buf.len().min(bytes.len() - offset);
        buf[..count].copy_from_slice(&bytes[offset..offset + count]);
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for PlanReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let relative = |base: u64, displacement: i64| {
            if displacement < 0 {
                base.checked_sub(displacement.unsigned_abs())
            } else {
                base.checked_add(displacement.unsigned_abs())
            }
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek outside blob")
            })
        };
        self.position = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => relative(self.plan.total, offset)?,
            SeekFrom::Current(offset) => relative(self.position, offset)?,
        };
        self.current = self.leaf_at(self.position);
        Ok(self.position)
    }
}

/// A range of a reader: at most `length` bytes from `offset`.
pub fn range(
    mut reader: Box<dyn BlobReader>,
    offset: u64,
    length: u64,
) -> Result<Vec<u8>, StoreError> {
    let end = reader.seek(SeekFrom::End(0))?;
    if offset >= end {
        return Ok(Vec::new());
    }
    reader.seek(SeekFrom::Start(offset))?;
    let length = usize::try_from(length.min(end - offset))
        .map_err(|_| StoreError::CapacityExceeded("blob range exceeds address space".into()))?;
    let mut buf = vec![0u8; length];
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(StoreError::Io(e)),
        }
    }
    buf.truncate(total);
    Ok(buf)
}

/// A streaming decoder for `algorithm` over `input`.
pub fn decoder<'a, R: Read + Send + 'a>(
    algorithm: &str,
    input: R,
) -> Result<Box<dyn Read + Send + 'a>, StoreError> {
    Ok(match algorithm {
        "none" => Box::new(input),
        "zstd" => Box::new(zstd::Decoder::new(input)?),
        "xz" | "lzma" => Box::new(xz2::read::XzDecoder::new(input)),
        "bzip2" => Box::new(bzip2::read::BzDecoder::new(input)),
        other => {
            return Err(StoreError::Rejected(format!(
                "unsupported compression: {other}"
            )));
        }
    })
}

#[cfg(test)]
#[path = "blob_read_tests.rs"]
mod tests;
