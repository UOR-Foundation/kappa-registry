//! Streaming frame-decrypting reader for encrypted blobs.
//!
//! Decrypts one 64KB frame at a time on demand. Memory usage is bounded
//! at one frame (64KB) plus one read buffer (64KB + 16 byte tag) = ~128KB
//! regardless of blob size. Plaintext never touches disk.

use std::io::{self, Read, Seek, SeekFrom};

use kappa_core::crypto::aead::{BlobEncryptor, FRAME_DISK_SIZE, FRAME_SIZE, FRAME_TAG_SIZE};
use kappa_core::store::BlobReader;

/// A reader that decrypts framed AEAD blobs on demand, one frame at a time.
///
/// Holds the raw file handle to the encrypted blob, an owned BlobEncryptor
/// for decryption, and the binding record metadata (base_nonce, sigma,
/// plaintext_size).
pub struct FrameDecryptingReader {
    /// File handle to the encrypted blob on disk. Seekable.
    file: std::fs::File,
    /// Owned encryptor for this namespace. Created via clone_for_reader().
    encryptor: BlobEncryptor,
    /// Per-blob random base nonce from the binding record.
    base_nonce: [u8; 8],
    /// Protocol-facing digest (hash of plaintext), used as AEAD AAD.
    sigma: String,
    /// Total plaintext size in bytes, from the binding record.
    plaintext_size: u64,
    /// Current logical read position in the plaintext stream.
    position: u64,
    /// Cached decrypted frame contents. Max FRAME_SIZE bytes.
    frame_buf: Vec<u8>,
    /// Which frame index is currently in frame_buf, or None if empty.
    cached_frame: Option<u32>,
    /// Reusable buffer for reading encrypted frame data from disk.
    read_buf: Vec<u8>,
}

impl FrameDecryptingReader {
    /// Create a new frame-decrypting reader.
    pub fn new(
        file: std::fs::File,
        encryptor: BlobEncryptor,
        base_nonce: [u8; 8],
        sigma: String,
        plaintext_size: u64,
    ) -> Self {
        Self {
            file,
            encryptor,
            base_nonce,
            sigma,
            plaintext_size,
            position: 0,
            frame_buf: Vec::with_capacity(FRAME_SIZE),
            cached_frame: None,
            read_buf: Vec::with_capacity(FRAME_DISK_SIZE),
        }
    }

    /// Ensure frame_buf contains the decrypted content of the given frame.
    /// No-op if the frame is already cached. Seeks the file, reads one
    /// frame, decrypts via the encryptor.
    fn ensure_frame(&mut self, frame_index: u32) -> io::Result<()> {
        if self.cached_frame == Some(frame_index) {
            return Ok(());
        }

        let pt_size = BlobEncryptor::frame_plaintext_size(self.plaintext_size, frame_index);
        let disk_frame_size = FRAME_TAG_SIZE + pt_size;
        let disk_offset = frame_index as u64 * FRAME_DISK_SIZE as u64;

        // Seek and read the encrypted frame from disk
        self.file.seek(SeekFrom::Start(disk_offset))?;
        self.read_buf.clear();
        self.read_buf.resize(disk_frame_size, 0);
        self.file.read_exact(&mut self.read_buf)?;

        // Decrypt via BlobEncryptor::decrypt_frame
        let plaintext = self.encryptor
            .decrypt_frame(&self.sigma, &self.base_nonce, frame_index, &self.read_buf)
            .map_err(|e| io::Error::other(format!("frame {} decrypt: {e}", frame_index)))?;

        self.frame_buf = plaintext;
        self.cached_frame = Some(frame_index);
        Ok(())
    }
}

impl Read for FrameDecryptingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.position >= self.plaintext_size {
            return Ok(0);
        }

        let frame_index = (self.position / FRAME_SIZE as u64) as u32;
        let offset_in_frame = (self.position % FRAME_SIZE as u64) as usize;

        self.ensure_frame(frame_index)?;

        let available = self.frame_buf.len() - offset_in_frame;
        let to_copy = std::cmp::min(available, buf.len());
        buf[..to_copy].copy_from_slice(&self.frame_buf[offset_in_frame..offset_in_frame + to_copy]);
        self.position += to_copy as u64;
        Ok(to_copy)
    }
}

impl Seek for FrameDecryptingReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = match pos {
            SeekFrom::Start(p) => p as i64,
            SeekFrom::End(p) => self.plaintext_size as i64 + p,
            SeekFrom::Current(p) => self.position as i64 + p,
        };
        if new_pos < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek to negative position",
            ));
        }
        let new_pos = new_pos as u64;

        // Invalidate frame cache if seeking to a different frame
        let new_frame = (new_pos / FRAME_SIZE as u64) as u32;
        if self.cached_frame != Some(new_frame) {
            self.cached_frame = None;
        }

        self.position = new_pos;
        Ok(new_pos)
    }
}

impl BlobReader for FrameDecryptingReader {}
