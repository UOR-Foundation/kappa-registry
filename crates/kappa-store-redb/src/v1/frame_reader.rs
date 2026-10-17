use std::cmp::min;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};

use kappa_crypto::aead::{BlobEncryptor, FRAME_DISK_SIZE, FRAME_SIZE, FRAME_TAG_SIZE};
use kappa_crypto::framing::FrameLayout;

pub struct FrameDecryptingReader {
    file: fs::File,
    encryptor: BlobEncryptor,
    base_nonce: [u8; 8],
    sigma: String,
    plaintext_size: u64,
    position: u64,
    frame_buf: Vec<u8>,
    cached_frame: Option<u32>,
    read_buf: Vec<u8>,
}

impl FrameDecryptingReader {
    pub fn new(
        file: fs::File,
        encryptor: BlobEncryptor,
        base_nonce: [u8; 8],
        sigma: String,
        plaintext_size: u64,
    ) -> io::Result<Self> {
        let encrypted_size = file.metadata()?.len();
        let layout = FrameLayout::new(plaintext_size)
            .and_then(|layout| layout.check_encrypted_size(encrypted_size))
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let mut reader = Self {
            file,
            encryptor,
            base_nonce,
            sigma,
            plaintext_size,
            position: 0,
            frame_buf: Vec::with_capacity(FRAME_SIZE),
            cached_frame: None,
            read_buf: Vec::with_capacity(FRAME_DISK_SIZE),
        };
        reader.ensure_frame(layout.final_index().get())?;
        Ok(reader)
    }

    fn ensure_frame(&mut self, frame_index: u32) -> io::Result<()> {
        if self.cached_frame == Some(frame_index) {
            return Ok(());
        }
        let pt_size = BlobEncryptor::frame_plaintext_size(self.plaintext_size, frame_index);
        let disk_frame_size = FRAME_TAG_SIZE + pt_size;
        let disk_offset = u64::from(frame_index) * FRAME_DISK_SIZE as u64;

        self.file.seek(SeekFrom::Start(disk_offset))?;
        self.read_buf.clear();
        self.read_buf.resize(disk_frame_size, 0);
        self.file.read_exact(&mut self.read_buf)?;

        let plaintext = self
            .encryptor
            .decrypt_frame(
                &self.sigma,
                &self.base_nonce,
                frame_index,
                &self.read_buf,
                self.plaintext_size,
            )
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

        self.frame_buf = plaintext;
        self.cached_frame = Some(frame_index);
        Ok(())
    }
}

impl Read for FrameDecryptingReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.position >= self.plaintext_size {
            return Ok(0);
        }
        let frame_index = u32::try_from(self.position / FRAME_SIZE as u64)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let offset_in_frame = usize::try_from(self.position % FRAME_SIZE as u64)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;

        self.ensure_frame(frame_index)?;

        let available = self
            .frame_buf
            .len()
            .checked_sub(offset_in_frame)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "frame offset exceeds plaintext")
            })?;
        let to_copy = min(available, buf.len());
        buf[..to_copy].copy_from_slice(&self.frame_buf[offset_in_frame..offset_in_frame + to_copy]);
        self.position += to_copy as u64;
        Ok(to_copy)
    }
}

impl Seek for FrameDecryptingReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let relative = |base: u64, displacement: i64| {
            if displacement < 0 {
                base.checked_sub(displacement.unsigned_abs())
            } else {
                base.checked_add(displacement.unsigned_abs())
            }
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "seek outside representable position",
                )
            })
        };
        let new_pos = match pos {
            SeekFrom::Start(p) => p,
            SeekFrom::End(p) => relative(self.plaintext_size, p)?,
            SeekFrom::Current(p) => relative(self.position, p)?,
        };
        self.position = new_pos;
        Ok(new_pos)
    }
}
