//! Positional and streaming access to committed content.
//!
//! [`ExternalReader`] reads one allocation chunk by chunk: the allocation
//! is pinned for the reader's life, every chunk is decrypted under its
//! publication's frame context and, for partial reads, verified against
//! the epoch-committed chunk root (`ReadView::resolve_commitment`).
//! [`CompositeReader`] serves a composite range by range through the view,
//! so no component is held open longer than one read.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::sync::Arc;

use kappa_store::{Kappa, StoreError};

use crate::allocation::Pin;
use crate::chunk_integrity::ChunkList;
use crate::content_prepare::frame_context;
use crate::content_read::{ENVELOPE_OVERHEAD, ReadView};
use crate::representation::{BlobRecord, Representation};

impl ReadView {
    /// Open the external representation of `identity` for chunk reads. The
    /// allocation is pinned for the reader's life. With `partial`, every
    /// delivered chunk is verified against the epoch-committed root, which
    /// the identity must have; without it the caller verifies the whole
    /// content afterwards.
    pub(crate) fn open_external(
        &self,
        identity: &Kappa,
        record: &BlobRecord,
        partial: bool,
    ) -> Result<ExternalReader, StoreError> {
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
            let commitment = self.resolve_commitment(identity)?.ok_or_else(|| {
                StoreError::Internal(format!(
                    "content {identity} has no epoch-committed chunk root"
                ))
            })?;
            if commitment.chunk_root() != chunk_root {
                return Err(StoreError::Internal(format!(
                    "row chunk root of {identity} disagrees with its epoch commitment"
                )));
            }
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
        Ok(ExternalReader {
            cipher: self.blob_encryptor.clone(),
            file,
            chunks,
            _pin: pin,
            chunk_size: *chunk_size,
            chunk_count: *chunk_count,
            stored_size: record.stored_size(),
            publication_id: *publication_id,
            overhead,
            position: 0,
            loaded: None,
            chunk: Vec::new(),
        })
    }
}

/// Positional, authenticated chunk access to one allocation.
pub struct ExternalReader {
    cipher: Option<Arc<crate::blob_encryption::BlobEncryption>>,
    file: File,
    chunks: Option<ChunkList>,
    _pin: Pin,
    chunk_size: u32,
    pub(crate) chunk_count: u32,
    stored_size: u64,
    publication_id: [u8; 32],
    overhead: u64,
    position: u64,
    loaded: Option<u32>,
    chunk: Vec<u8>,
}

impl ExternalReader {
    fn plain_len(&self, index: u32) -> u64 {
        let start = u64::from(index) * u64::from(self.chunk_size);
        self.stored_size
            .saturating_sub(start)
            .min(u64::from(self.chunk_size))
    }

    /// Authenticated plaintext of chunk `index`.
    pub(crate) fn chunk(&mut self, index: u32) -> Result<Vec<u8>, StoreError> {
        if index >= self.chunk_count {
            return Err(StoreError::Internal("blob chunk index out of range".into()));
        }
        let plain = self.plain_len(index);
        let length = usize::try_from(plain + self.overhead)
            .map_err(|_| StoreError::Internal("chunk length exceeds address space".into()))?;
        let stride = u64::from(self.chunk_size) + self.overhead;
        self.file.seek(SeekFrom::Start(u64::from(index) * stride))?;
        let mut stored = vec![0u8; length];
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
            chunks.verify(index, &plaintext)?;
        }
        Ok(plaintext)
    }

    /// Bytes `[offset, offset + length)` of the stored representation.
    pub(crate) fn range(&mut self, offset: u64, length: u64) -> Result<Vec<u8>, StoreError> {
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
        let mut out = ReadView::reserve(length)?;
        for index in first..=last {
            let chunk = self.chunk(index)?;
            let chunk_start = u64::from(index) * size;
            let from = usize::try_from(offset.saturating_sub(chunk_start))
                .map_err(|_| StoreError::Internal("range offset bound".into()))?;
            let to = usize::try_from((offset + length - chunk_start).min(chunk.len() as u64))
                .map_err(|_| StoreError::Internal("range end bound".into()))?;
            out.extend_from_slice(chunk.get(from..to).ok_or_else(|| {
                StoreError::Internal("blob range disagrees with representation framing".into())
            })?);
        }
        Ok(out)
    }
}

fn invalid(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error)
}

impl Read for ExternalReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.position >= self.stored_size {
            return Ok(0);
        }
        let size = u64::from(self.chunk_size);
        let index = u32::try_from(self.position / size).map_err(invalid)?;
        let offset = usize::try_from(self.position % size).map_err(invalid)?;
        if self.loaded != Some(index) {
            self.chunk = self.chunk(index).map_err(|error| {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, error.to_string())
            })?;
            self.loaded = Some(index);
        }
        let mut deliver = |reader: &mut Self| -> std::io::Result<usize> {
            let available = reader
                .chunk
                .get(offset..)
                .ok_or_else(|| invalid("blob offset exceeds chunk"))?;
            let count = available.len().min(buf.len());
            buf[..count].copy_from_slice(&available[..count]);
            reader.position += count as u64;
            Ok(count)
        };
        match self.cipher.clone() {
            // Delivery of decrypted plaintext is admitted under the
            // encryption domain: erasure revokes retained readers too.
            Some(cipher) => match cipher.while_active(|| deliver(self)) {
                Ok(delivered) => delivered,
                Err(error) => {
                    use zeroize::Zeroize;
                    self.chunk.zeroize();
                    self.loaded = None;
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        error.to_string(),
                    ))
                }
            },
            None => deliver(self),
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
            SeekFrom::End(offset) => relative(self.stored_size, offset)?,
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

/// Streaming access to inline content, the bytes its row held. Delivery is
/// admitted under the blob encryption domain as an external reader's is:
/// erasure revokes a retained inline reader too, and its bytes are
/// zeroized when it is revoked or dropped.
pub struct InlineReader {
    cipher: Option<Arc<crate::blob_encryption::BlobEncryption>>,
    bytes: Vec<u8>,
    position: u64,
}

impl InlineReader {
    /// A reader over `bytes`, delivered while `cipher`'s domain is active.
    pub(crate) const fn new(
        bytes: Vec<u8>,
        cipher: Option<Arc<crate::blob_encryption::BlobEncryption>>,
    ) -> Self {
        Self {
            cipher,
            bytes,
            position: 0,
        }
    }
}

impl Read for InlineReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut deliver = |reader: &mut Self| -> std::io::Result<usize> {
            let start = usize::try_from(reader.position).unwrap_or(usize::MAX);
            let available = reader.bytes.get(start..).unwrap_or_default();
            let count = available.len().min(buf.len());
            buf[..count].copy_from_slice(&available[..count]);
            reader.position += count as u64;
            Ok(count)
        };
        match self.cipher.clone() {
            Some(cipher) => match cipher.while_active(|| deliver(self)) {
                Ok(delivered) => delivered,
                Err(error) => {
                    use zeroize::Zeroize;
                    self.bytes.zeroize();
                    Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        error.to_string(),
                    ))
                }
            },
            None => deliver(self),
        }
    }
}

impl Seek for InlineReader {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.position = match pos {
            SeekFrom::Start(offset) => offset,
            SeekFrom::End(offset) => relative(self.bytes.len() as u64, offset)?,
            SeekFrom::Current(offset) => relative(self.position, offset)?,
        };
        Ok(self.position)
    }
}

impl Drop for InlineReader {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.bytes.zeroize();
    }
}

/// A composite served range by range through the view, so no component
/// is held open longer than one read.
pub struct CompositeReader {
    view: ReadView,
    identity: Kappa,
    size: u64,
    position: u64,
}

impl CompositeReader {
    /// A reader over the composite `identity` of logical length `size`.
    pub(crate) const fn new(view: ReadView, identity: Kappa, size: u64) -> Self {
        Self {
            view,
            identity,
            size,
            position: 0,
        }
    }
}

impl Read for CompositeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() || self.position >= self.size {
            return Ok(0);
        }
        let bytes = self
            .view
            .range(&self.identity, self.position, buf.len() as u64)
            .map_err(|error| invalid(error.to_string()))?;
        let count = bytes.len().min(buf.len());
        buf[..count].copy_from_slice(&bytes[..count]);
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
