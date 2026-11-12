//! A resolved identity served as a stream (`blob_read::open`): one open
//! leaf at a time, every leaf's allocation held for the reader's life.
//! Sequential reads continue from the current leaf; a seek finds its leaf
//! by binary search over the leaf offsets. A compressed leaf is decoded as
//! it is read through the shared bounded decoder
//! (`kappa_store::compression`), never held whole: reading forward within
//! it decodes forward, reading behind its decoder reopens it.
//!
//! A read is served from the segment of its leaf holding the position: the
//! whole segment is read, checked against the leaf's segment digests, and
//! kept for the reads that follow within it. A segment that fails its
//! check is never kept, so a reader delivers no byte that was not proven
//! to be its identity's, whatever its order of reads and seeks.
//!
//! The reader owns what is left of its operation's meter and charges every
//! step to it before the step runs: each handle opened with its input
//! buffer and decoder memory, each stored byte read, each byte decoded or
//! skipped, each segment buffer grown and each segment hashed. A refused
//! charge is the reader's `io::Error` of kind `Other` carrying the
//! `StoreError::WorkRefused`.

use std::fs;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::sync::Arc;

use kappa_store::compression::Codec;
use kappa_types::error::StoreError;
use kappa_types::work::{Dimension, WorkMeter};

use super::blob_read::{DECODER_INPUT_BUFFER, Leaf, Plan, open_file};
use super::view::Held;

/// Bytes discarded per read while a decoder skips forward.
const SKIP_CHUNK: usize = 16 * 1024;

pub struct PlanReader {
    plan: Plan,
    /// The rest of the operation's allowance, charged by every read.
    meter: WorkMeter,
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
    /// Inline bytes, read in place; holding them holds their charge.
    Inline(Arc<Held>),
}

fn invalid_data(message: String) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, message)
}

/// `error` as the `io::Error` a reader returns, the `StoreError` kept as
/// its cause: storage I/O is itself, a refused allowance and every other
/// store failure are `Other`.
fn stream_error(error: StoreError) -> std::io::Error {
    match error {
        StoreError::Io(error) => error,
        other => std::io::Error::other(other),
    }
}

/// Charge `charges` to `meter` before the work they name.
fn charge(meter: &mut WorkMeter, charges: &[(Dimension, u64)]) -> std::io::Result<()> {
    meter
        .charge_all(charges)
        .map_err(|refused| stream_error(refused.into()))
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

/// Open `leaf` on `meter`: a file's handle, or a compressed leaf's handle
/// with its input buffer, its decoder's working memory and every stored
/// byte the decoder may read from it, charged before it is opened.
fn open_leaf(leaf: &Leaf, meter: &mut WorkMeter) -> std::io::Result<OpenLeaf> {
    Ok(match leaf {
        Leaf::File(allocation) => {
            charge(meter, &[(Dimension::Handles, 1)])?;
            OpenLeaf::File(open_file(allocation).map_err(stream_error)?)
        }
        Leaf::Compressed(storage, algorithm, _) => {
            let codec = Codec::of(algorithm).map_err(stream_error)?;
            charge(
                meter,
                &[
                    (Dimension::Handles, 1),
                    (Dimension::BytesAllocated, DECODER_INPUT_BUFFER),
                    (Dimension::BytesAllocated, codec.working_bytes()),
                    (Dimension::BytesRead, storage.bytes()),
                ],
            )?;
            let file = BufReader::new(open_file(storage).map_err(stream_error)?);
            OpenLeaf::Decoding(codec.decoder(file).map_err(stream_error)?, 0)
        }
        Leaf::Inline(held, _) => OpenLeaf::Inline(Arc::clone(held)),
    })
}

impl PlanReader {
    pub(super) const fn new(plan: Plan, meter: WorkMeter) -> Self {
        Self {
            plan,
            meter,
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
            Some((open, OpenLeaf::File(_) | OpenLeaf::Inline(_))) => *open != index,
            None => true,
        };
        if reopen {
            self.open = Some((index, open_leaf(leaf, &mut self.meter)?));
        }
        let Some((_, opened)) = self.open.as_mut() else {
            return Err(std::io::Error::other("leaf not open"));
        };
        // The previous segment's buffer is reused; nothing of it survives a
        // failed check. Only growth past its capacity allocates.
        let mut bytes = self
            .segment
            .take()
            .map_or_else(Vec::new, |(_, _, bytes)| bytes);
        bytes.clear();
        let wanted = usize::try_from(size).map_err(std::io::Error::other)?;
        if wanted > bytes.capacity() {
            charge(
                &mut self.meter,
                &[(
                    Dimension::BytesAllocated,
                    (wanted - bytes.capacity()) as u64,
                )],
            )?;
        }
        bytes.resize(wanted, 0);
        let last = start + size == *length;
        let probe = u64::from(last);
        match opened {
            OpenLeaf::File(file) => {
                charge(&mut self.meter, &[(Dimension::BytesRead, size + probe)])?;
                file.seek(SeekFrom::Start(start))?;
                file.read_exact(&mut bytes)?;
                if last {
                    probe_end(file)?;
                }
            }
            OpenLeaf::Decoding(decoding, at) => {
                charge(
                    &mut self.meter,
                    &[(Dimension::BytesDecoded, (start - *at) + size + probe)],
                )?;
                skip_to(decoding, at, start)?;
                decoding.read_exact(&mut bytes)?;
                *at += size;
                if last {
                    probe_end(decoding)?;
                }
            }
            OpenLeaf::Inline(held) => {
                charge(&mut self.meter, &[(Dimension::BytesRead, size)])?;
                let held = held.bytes();
                let from = usize::try_from(start).map_err(std::io::Error::other)?;
                let piece = from
                    .checked_add(bytes.len())
                    .and_then(|to| held.get(from..to))
                    .ok_or_else(|| {
                        invalid_data("inline evidence is shorter than its length".into())
                    })?;
                bytes.copy_from_slice(piece);
                if last && held.len() as u64 != *length {
                    return Err(invalid_data(
                        "inline evidence is longer than its length".into(),
                    ));
                }
            }
        }
        charge(&mut self.meter, &[(Dimension::BytesHashed, size)])?;
        segments.check(start, &bytes)?;
        self.segment = Some((index, start, bytes));
        Ok(())
    }
}

impl Read for PlanReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.position >= self.plan.total() {
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
            SeekFrom::End(offset) => relative(self.plan.total(), offset)?,
            SeekFrom::Current(offset) => relative(self.position, offset)?,
        };
        self.current = self.leaf_at(self.position);
        Ok(self.position)
    }
}

impl PlanReader {
    /// At most `length` bytes from `offset`, on this reader's meter: the
    /// buffer charged before it is allocated, every segment as `read`
    /// charges it. A refused charge is the `StoreError` it carries, never
    /// storage I/O.
    pub(super) fn range(mut self, offset: u64, length: u64) -> Result<Vec<u8>, StoreError> {
        let end = self.plan.total();
        if offset >= end {
            return Ok(Vec::new());
        }
        let wanted = length.min(end - offset);
        let length = usize::try_from(wanted)
            .map_err(|_| StoreError::CapacityExceeded("blob range exceeds address space".into()))?;
        self.meter.charge(Dimension::BytesAllocated, wanted)?;
        self.seek(SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; length];
        let mut total = 0;
        while total < buf.len() {
            match self.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.downcast::<StoreError>().unwrap_or_else(StoreError::Io)),
            }
        }
        buf.truncate(total);
        Ok(buf)
    }
}
