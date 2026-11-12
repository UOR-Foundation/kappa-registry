//! Positional and streaming access to committed content.
//!
//! [`ExternalSource`] reads one allocation chunk by chunk: the allocation
//! is pinned for the source's life, every chunk is decrypted under its
//! publication's frame context and, for partial reads, verified against
//! the epoch-committed chunk root (`ReadView::resolve_commitment`). Every
//! chunk's file read, buffer, decryption and verification is charged to
//! the caller's meter before it is done.
//!
//! A streaming read is one operation: the meter that located the content
//! (`ReadView::open`) is moved into the returned reader, which charges
//! every later chunk, range and delivered byte to it. A reader never
//! obtains another allowance; one whose allowance is spent refuses with
//! the typed `StoreError::WorkRefused` as the cause of its `io::Error`,
//! leaving its position and loaded chunk as they were. [`CompositeReader`]
//! serves a composite range by range through the view, so no component is
//! held open longer than one read.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use kappa_store::work::{Dimension, Meter, Work, WorkMeter};
use kappa_store::{Kappa, StoreError};

use crate::allocation::Pin;
use crate::blob_encryption::BlobEncryption;
use crate::chunk_integrity::ChunkList;
use crate::content_prepare::frame_context;
use crate::content_read::{ENVELOPE_OVERHEAD, ReadView};
use crate::representation::{BlobRecord, Representation};

impl ReadView {
    /// Open the external representation of `identity` for chunk reads, on
    /// `work`. The allocation is pinned for the source's life. With
    /// `partial`, every delivered chunk is verified against the
    /// epoch-committed root, which the identity must have; without it the
    /// caller verifies the whole content afterwards.
    pub(crate) fn open_external(
        &self,
        identity: &Kappa,
        record: &BlobRecord,
        partial: bool,
        work: &mut dyn Meter,
    ) -> Result<ExternalSource, StoreError> {
        let Representation::External {
            allocation,
            chunk_count,
            chunk_size,
            publication_id,
            chunk_root,
        } = record.representation()
        else {
            return Err(StoreError::Internal(
                "external reader opened over a non-external record".into(),
            ));
        };
        let pin = self.protection.pin(*allocation)?;
        work.charge(Dimension::Handles, 1)?;
        let path = crate::allocation::allocation_path(&self.blob_root, allocation);
        let file = File::open(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                StoreError::Internal(format!("allocation {} is missing", allocation.hex()))
            } else {
                StoreError::Io(error)
            }
        })?;
        let overhead = if self.blob_encryptor.is_some() {
            ENVELOPE_OVERHEAD
        } else {
            0
        };
        let stride = u64::from(*chunk_size) + overhead;
        let last = u64::from(*chunk_count - 1);
        let last_plain = record.stored_size() - last * u64::from(*chunk_size);
        let expected = last * stride + last_plain + overhead;
        let actual = file.metadata()?.len();
        if actual != expected {
            return Err(StoreError::Internal(format!(
                "allocation {} is {actual} bytes, framing requires {expected}",
                allocation.hex()
            )));
        }
        let chunks = if partial {
            let commitment = self.resolve_commitment(identity, work)?.ok_or_else(|| {
                StoreError::Internal(format!(
                    "content {identity} has no epoch-committed chunk root"
                ))
            })?;
            if commitment.chunk_root() != chunk_root {
                return Err(StoreError::Internal(format!(
                    "row chunk root of {identity} disagrees with its epoch commitment"
                )));
            }
            work.charge(Dimension::Handles, 1)?;
            Some(ChunkList::open(
                &self.blob_root,
                allocation,
                identity,
                *chunk_size,
                *chunk_count,
                &commitment,
            )?)
        } else {
            None
        };
        Ok(ExternalSource {
            cipher: self.blob_encryptor.clone(),
            file,
            chunks,
            _pin: pin,
            chunk_size: *chunk_size,
            chunk_count: *chunk_count,
            stored_size: record.stored_size(),
            publication_id: *publication_id,
            overhead,
        })
    }
}

/// Positional, authenticated chunk access to one allocation, charged to
/// the caller's meter.
pub struct ExternalSource {
    cipher: Option<Arc<BlobEncryption>>,
    file: File,
    chunks: Option<ChunkList>,
    _pin: Pin,
    chunk_size: u32,
    pub(crate) chunk_count: u32,
    stored_size: u64,
    publication_id: [u8; 32],
    overhead: u64,
}

impl ExternalSource {
    /// Plaintext bytes of chunk `index`: the chunk size, the last chunk
    /// shorter.
    pub(crate) fn plain_len(&self, index: u32) -> u64 {
        let start = u64::from(index) * u64::from(self.chunk_size);
        self.stored_size
            .saturating_sub(start)
            .min(u64::from(self.chunk_size))
    }

    /// What [`Self::chunk`] of `index` charges, decided from the framing
    /// alone before the chunk is read: the stored frame's buffer and read
    /// and, in an encrypted store, the plaintext buffer and the decryption
    /// pass. A source opened for partial reads also verifies each chunk
    /// against its chunk list, which this bound does not cover: such a
    /// source is refused here, so no caller admits a chunk below its cost.
    pub(crate) fn unverified_chunk_cost(&self, index: u32) -> Result<Work, StoreError> {
        if self.chunks.is_some() {
            return Err(StoreError::Internal(
                "a chunk-verified source has no unverified chunk cost".into(),
            ));
        }
        let plain = self.plain_len(index);
        let framed = plain + self.overhead;
        let decrypted = if self.cipher.is_some() { plain } else { 0 };
        Work::total(&[
            (Dimension::BytesAllocated, framed),
            (Dimension::BytesRead, framed),
            (Dimension::BytesDecoded, decrypted),
            (Dimension::BytesAllocated, decrypted),
        ])
        .map_err(|_| StoreError::Internal("chunk cost exceeds u64".into()))
    }

    /// What [`Self::range`] of `[offset, offset + length)` charges, from
    /// the framing alone: its output buffer, every chunk it touches
    /// ([`Self::unverified_chunk_cost`]) and the bytes copied out of them.
    pub(crate) fn unverified_range_cost(
        &self,
        offset: u64,
        length: u64,
    ) -> Result<Work, StoreError> {
        let overflow = || StoreError::Internal("range cost exceeds u64".into());
        if offset >= self.stored_size {
            return Ok(Work::default());
        }
        let length = length.min(self.stored_size - offset);
        if length == 0 {
            return Ok(Work::default());
        }
        let size = u64::from(self.chunk_size);
        let first = u32::try_from(offset / size).map_err(|_| overflow())?;
        let last = u32::try_from((offset + length - 1) / size).map_err(|_| overflow())?;
        let mut cost = Work::default()
            .with(Dimension::BytesAllocated, length)
            .with(Dimension::BytesRead, length);
        for index in first..=last {
            cost.checked_add_assign(&self.unverified_chunk_cost(index)?)
                .map_err(|_| overflow())?;
        }
        Ok(cost)
    }

    /// Authenticated plaintext of chunk `index`. The stored frame's buffer
    /// and read, and its decryption into a buffer of its own, are charged
    /// before the read; verification charges its own work.
    pub(crate) fn chunk(
        &mut self,
        index: u32,
        work: &mut dyn Meter,
    ) -> Result<Vec<u8>, StoreError> {
        if index >= self.chunk_count {
            return Err(StoreError::Internal("blob chunk index out of range".into()));
        }
        let plain = self.plain_len(index);
        let framed = plain + self.overhead;
        let length = usize::try_from(framed)
            .map_err(|_| StoreError::Internal("chunk length exceeds address space".into()))?;
        work.charge_all(&[
            (Dimension::BytesAllocated, framed),
            (Dimension::BytesRead, framed),
        ])?;
        if self.cipher.is_some() {
            work.charge_all(&[
                (Dimension::BytesDecoded, plain),
                (Dimension::BytesAllocated, plain),
            ])?;
        }
        let stride = u64::from(self.chunk_size) + self.overhead;
        self.file.seek(SeekFrom::Start(u64::from(index) * stride))?;
        let mut stored = Vec::new();
        stored.try_reserve_exact(length).map_err(|_| {
            StoreError::CapacityExceeded(format!(
                "a chunk of {framed} bytes could not be allocated"
            ))
        })?;
        stored.resize(length, 0);
        self.file.read_exact(&mut stored)?;
        let plaintext = match &self.cipher {
            Some(cipher) => cipher.decrypt(&frame_context(&self.publication_id, index), &stored)?,
            None => stored,
        };
        if plaintext.len() as u64 != plain {
            return Err(StoreError::Internal(
                "blob chunk length disagrees with framing".into(),
            ));
        }
        if let Some(chunks) = &mut self.chunks {
            chunks.verify(index, &plaintext, work)?;
        }
        Ok(plaintext)
    }

    /// Bytes `[offset, offset + length)` of the stored representation, on
    /// `work`: the output buffer, then each chunk the range touches and the
    /// bytes copied out of it.
    pub(crate) fn range(
        &mut self,
        offset: u64,
        length: u64,
        work: &mut dyn Meter,
    ) -> Result<Vec<u8>, StoreError> {
        if offset >= self.stored_size {
            return Ok(Vec::new());
        }
        let length = length.min(self.stored_size - offset);
        if length == 0 {
            return Ok(Vec::new());
        }
        let size = u64::from(self.chunk_size);
        let first = u32::try_from(offset / size)
            .map_err(|_| StoreError::Internal("range chunk exceeds u32".into()))?;
        let last = u32::try_from((offset + length - 1) / size)
            .map_err(|_| StoreError::Internal("range chunk exceeds u32".into()))?;
        work.charge(Dimension::BytesAllocated, length)?;
        let mut out = ReadView::reserve(length)?;
        for index in first..=last {
            let chunk = self.chunk(index, work)?;
            let chunk_start = u64::from(index) * size;
            let from = usize::try_from(offset.saturating_sub(chunk_start))
                .map_err(|_| StoreError::Internal("range offset bound".into()))?;
            let to = usize::try_from((offset + length - chunk_start).min(chunk.len() as u64))
                .map_err(|_| StoreError::Internal("range end bound".into()))?;
            let part = chunk.get(from..to).ok_or_else(|| {
                StoreError::Internal("blob range disagrees with representation framing".into())
            })?;
            work.charge(Dimension::BytesRead, part.len() as u64)?;
            out.extend_from_slice(part);
        }
        Ok(out)
    }
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

/// `error` as the `io::Error` a reader returns, the `StoreError` kept as
/// its cause. A refused allowance is `Other`, distinguishable from the
/// reader's own failure kind (`kind`); a storage I/O error is itself.
fn stream_error(kind: std::io::ErrorKind, error: StoreError) -> std::io::Error {
    match error {
        StoreError::Io(error) => error,
        refused @ StoreError::WorkRefused(_) => std::io::Error::other(refused),
        other => std::io::Error::new(kind, other),
    }
}

/// The bytes delivered from `available` into `buf`, charged to `meter`
/// before they are copied.
fn deliver(available: &[u8], buf: &mut [u8], meter: &mut WorkMeter) -> std::io::Result<usize> {
    let count = available.len().min(buf.len());
    meter
        .charge(Dimension::BytesRead, count as u64)
        .map_err(|refused| stream_error(std::io::ErrorKind::Other, refused.into()))?;
    buf[..count].copy_from_slice(&available[..count]);
    Ok(count)
}

/// Streaming access to an external allocation, on the allowance of the
/// operation that opened it.
pub struct ExternalReader {
    source: ExternalSource,
    meter: WorkMeter,
    position: u64,
    loaded: Option<u32>,
    chunk: Vec<u8>,
}

impl Read for ExternalReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use zeroize::Zeroize;
        if buf.is_empty() || self.position >= self.source.stored_size {
            return Ok(0);
        }
        let size = u64::from(self.source.chunk_size);
        let index = u32::try_from(self.position / size).map_err(invalid)?;
        let offset = usize::try_from(self.position % size).map_err(invalid)?;
        if self.loaded != Some(index) {
            let chunk = self
                .source
                .chunk(index, &mut self.meter)
                .map_err(|error| stream_error(std::io::ErrorKind::PermissionDenied, error))?;
            self.chunk.zeroize();
            self.chunk = chunk;
            self.loaded = Some(index);
        }
        let mut delivery = |reader: &mut Self| -> std::io::Result<usize> {
            let available = reader
                .chunk
                .get(offset..)
                .ok_or_else(|| invalid("blob offset exceeds chunk"))?;
            let count = deliver(available, buf, &mut reader.meter)?;
            reader.position += count as u64;
            Ok(count)
        };
        match self.source.cipher.clone() {
            // Delivery of decrypted plaintext is admitted under the
            // encryption domain: erasure revokes retained readers too.
            Some(cipher) => match cipher.while_active(|| delivery(self)) {
                Ok(delivered) => delivered,
                Err(error) => {
                    self.chunk.zeroize();
                    self.loaded = None;
                    Err(stream_error(std::io::ErrorKind::PermissionDenied, error))
                }
            },
            None => delivery(self),
        }
    }
}

fn relative(base: u64, displacement: i64) -> std::io::Result<u64> {
    if displacement < 0 {
        base.checked_sub(displacement.unsigned_abs())
    } else {
        base.checked_add(displacement.unsigned_abs())
    }
    .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidInput, "seek outside blob"))
}

impl Seek for ExternalReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.position = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => relative(self.source.stored_size, offset)?,
            SeekFrom::Current(offset) => relative(self.position, offset)?,
        };
        Ok(self.position)
    }
}

impl Drop for ExternalReader {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.chunk.zeroize();
    }
}

/// Inline content an open located: the bytes its row held, zeroized when
/// dropped, whether or not a reader was made from them.
pub struct InlineSource {
    cipher: Option<Arc<BlobEncryption>>,
    bytes: Vec<u8>,
}

impl Drop for InlineSource {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

/// Streaming access to inline content. Delivery is admitted under the blob
/// encryption domain as an external reader's is: erasure revokes a retained
/// inline reader too, and its bytes are zeroized when it is revoked or
/// dropped.
pub struct InlineReader {
    source: InlineSource,
    meter: WorkMeter,
    position: u64,
}

impl Read for InlineReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut delivery = |reader: &mut Self| -> std::io::Result<usize> {
            let start = usize::try_from(reader.position).unwrap_or(usize::MAX);
            let available = reader.source.bytes.get(start..).unwrap_or_default();
            let count = deliver(available, buf, &mut reader.meter)?;
            reader.position += count as u64;
            Ok(count)
        };
        match self.source.cipher.clone() {
            Some(cipher) => match cipher.while_active(|| delivery(self)) {
                Ok(delivered) => delivered,
                Err(error) => {
                    use zeroize::Zeroize;
                    self.source.bytes.zeroize();
                    Err(stream_error(std::io::ErrorKind::PermissionDenied, error))
                }
            },
            None => delivery(self),
        }
    }
}

impl Seek for InlineReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.position = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => relative(self.source.bytes.len() as u64, offset)?,
            SeekFrom::Current(offset) => relative(self.position, offset)?,
        };
        Ok(self.position)
    }
}

/// A composite served range by range through the view, each range on the
/// reader's allowance, so no component is held open longer than one read.
pub struct CompositeReader {
    view: ReadView,
    identity: Kappa,
    size: u64,
    position: u64,
    meter: WorkMeter,
}

impl Read for CompositeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.position >= self.size {
            return Ok(0);
        }
        let bytes = self
            .view
            .range(
                &self.identity,
                self.position,
                buf.len() as u64,
                &mut self.meter,
            )
            .map_err(|error| stream_error(std::io::ErrorKind::InvalidData, error))?;
        let count = deliver(&bytes, buf, &mut self.meter)?;
        self.position += count as u64;
        Ok(count)
    }
}

impl Seek for CompositeReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.position = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => relative(self.size, offset)?,
            SeekFrom::Current(offset) => relative(self.position, offset)?,
        };
        Ok(self.position)
    }
}

/// What `ReadView::open` located for a stream, before a reader owns it.
pub(crate) enum Opened {
    Inline(InlineSource),
    External(ExternalSource),
    Composite {
        view: ReadView,
        identity: Kappa,
        size: u64,
    },
}

impl Opened {
    /// Inline content of `bytes`, delivered while `cipher`'s domain is
    /// active.
    pub(crate) const fn inline(bytes: Vec<u8>, cipher: Option<Arc<BlobEncryption>>) -> Self {
        Self::Inline(InlineSource { cipher, bytes })
    }

    /// The reader over what was located, owning `meter`: the remaining
    /// allowance of the operation that located it.
    pub(crate) fn reader(self, meter: WorkMeter) -> Box<dyn kappa_store::traits::blob::BlobReader> {
        match self {
            Self::Inline(source) => Box::new(InlineReader {
                source,
                meter,
                position: 0,
            }),
            Self::External(source) => Box::new(ExternalReader {
                source,
                meter,
                position: 0,
                loaded: None,
                chunk: Vec::new(),
            }),
            Self::Composite {
                view,
                identity,
                size,
            } => Box::new(CompositeReader {
                view,
                identity,
                size,
                position: 0,
                meter,
            }),
        }
    }
}
