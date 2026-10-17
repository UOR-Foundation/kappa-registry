use std::cmp::min;
use std::io::{Read, Write};

use rekindle_aead::BulkAead;
use rekindle_aead::aes_gcm::AesGcmKey;
use zeroize::Zeroizing;

use super::CryptoError;
use super::kms::KeyManagementService;

pub const FRAME_SIZE: usize = 65536;
pub const FRAME_TAG_SIZE: usize = 16;
pub const FRAME_DISK_SIZE: usize = FRAME_SIZE + FRAME_TAG_SIZE;

/// Backend-specific errors for AEAD framed encryption.
enum AeadError {
    KeyDerivation {
        reason: String,
    },
    FrameDecrypt {
        frame: u32,
        reason: String,
    },
    FrameEncrypt {
        frame: u32,
        reason: String,
    },
    FrameTruncated {
        frame: u32,
        got: usize,
        expected: usize,
    },
    SizeMismatch {
        expected: u64,
        got: u64,
    },
    NonceGeneration {
        reason: String,
    },
    IoFailed {
        op: &'static str,
        reason: String,
    },
}

impl From<AeadError> for CryptoError {
    fn from(e: AeadError) -> Self {
        match e {
            AeadError::KeyDerivation { reason } => CryptoError::InvalidKey {
                reason: format!("aead key derivation: {}", reason),
            },
            AeadError::FrameDecrypt { frame, reason } => CryptoError::VerificationFailed {
                algorithm: "aes-256-gcm".into(),
                reason: format!("frame {} decrypt: {}", frame, reason),
            },
            AeadError::FrameEncrypt { frame, reason } => CryptoError::SigningFailed {
                algorithm: "aes-256-gcm".into(),
                reason: format!("frame {} encrypt: {}", frame, reason),
            },
            AeadError::FrameTruncated {
                frame,
                got,
                expected,
            } => CryptoError::VerificationFailed {
                algorithm: "aes-256-gcm".into(),
                reason: format!(
                    "frame {} truncated: {} bytes, expected {}",
                    frame, got, expected
                ),
            },
            AeadError::SizeMismatch { expected, got } => CryptoError::VerificationFailed {
                algorithm: "aes-256-gcm".into(),
                reason: format!("decrypted {} bytes, expected {}", got, expected),
            },
            AeadError::NonceGeneration { reason } => CryptoError::KeyGeneration {
                algorithm: "aes-256-gcm".into(),
                reason,
            },
            AeadError::IoFailed { op, reason } => CryptoError::SigningFailed {
                algorithm: "aes-256-gcm".into(),
                reason: format!("{}: {}", op, reason),
            },
        }
    }
}

pub struct BlobEncryptor {
    key: AesGcmKey,
    raw_key_bytes: Zeroizing<[u8; 32]>,
}

pub struct EncryptedBlob {
    pub disk_bytes: Vec<u8>,
    pub base_nonce: [u8; 8],
    pub plaintext_size: u64,
}

impl BlobEncryptor {
    /// Derive an independent envelope key from fresh publication entropy and
    /// the caller's domain-separated identity/representation context.
    pub fn derive_publication(&self, salt: &[u8; 32], context: &str) -> Result<Self, CryptoError> {
        let mut material = Zeroizing::new(Vec::with_capacity(72 + context.len()));
        material.extend_from_slice(self.raw_key_bytes.as_ref());
        material.extend_from_slice(salt);
        material.extend_from_slice(&(context.len() as u64).to_be_bytes());
        material.extend_from_slice(context.as_bytes());
        let key_bytes = Zeroizing::new(blake3::derive_key(
            "kappa-aead-publication-key-v1",
            &material,
        ));
        let key = AesGcmKey::new(&key_bytes).map_err(|_| AeadError::KeyDerivation {
            reason: "publication key construction failed".into(),
        })?;
        Ok(Self {
            key,
            raw_key_bytes: key_bytes,
        })
    }

    pub fn new(kms: &dyn KeyManagementService, namespace: &str) -> Result<Self, CryptoError> {
        let derived = Zeroizing::new(kms.derive_subject_key(namespace, "_blob_encryption")?);
        let key_bytes = Zeroizing::new(<[u8; 32]>::try_from(derived.as_slice()).map_err(|_| {
            AeadError::KeyDerivation {
                reason: format!("derived key is {} bytes, expected 32", derived.len()),
            }
        })?);
        let aes_key = AesGcmKey::new(&key_bytes).map_err(|_| AeadError::KeyDerivation {
            reason: "AesGcmKey construction failed".into(),
        })?;
        Ok(Self {
            key: aes_key,
            raw_key_bytes: key_bytes,
        })
    }

    /// Create a second encryptor sharing the same key material.
    /// Used by FrameDecryptingReader which needs its own AesGcmKey
    /// instance because AesGcmKey is not Clone.
    pub fn clone_for_reader(&self) -> Result<Self, CryptoError> {
        let aes_key =
            AesGcmKey::new(&self.raw_key_bytes).map_err(|_| AeadError::KeyDerivation {
                reason: "AesGcmKey re-construction failed".into(),
            })?;
        Ok(Self {
            key: aes_key,
            raw_key_bytes: self.raw_key_bytes.clone(),
        })
    }

    pub(crate) fn frame_nonce(base_nonce: &[u8; 8], frame_index: u32) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(base_nonce);
        nonce[8..12].copy_from_slice(&frame_index.to_be_bytes());
        nonce
    }

    pub fn frame_plaintext_size(plaintext_size: u64, frame_index: u32) -> usize {
        let frame_start = frame_index as u64 * FRAME_SIZE as u64;
        let remaining = plaintext_size.saturating_sub(frame_start);
        min(FRAME_SIZE as u64, remaining) as usize
    }

    pub fn decrypt_frame(
        &self,
        sigma: &str,
        base_nonce: &[u8; 8],
        frame_index: u32,
        frame_data: &[u8],
        plaintext_size: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        let last = plaintext_size.saturating_sub(1) / FRAME_SIZE as u64;
        if u64::from(frame_index) > last
            || frame_data.len()
                != FRAME_TAG_SIZE + Self::frame_plaintext_size(plaintext_size, frame_index)
        {
            return Err(AeadError::FrameDecrypt {
                frame: frame_index,
                reason: "frame disagrees with declared framing".into(),
            }
            .into());
        }
        if frame_data.len() < FRAME_TAG_SIZE {
            return Err(AeadError::FrameTruncated {
                frame: frame_index,
                got: frame_data.len(),
                expected: FRAME_TAG_SIZE,
            }
            .into());
        }
        let tag: [u8; 16] = frame_data[..16]
            .try_into()
            .map_err(|_| AeadError::FrameDecrypt {
                frame: frame_index,
                reason: "tag extraction failed".into(),
            })?;
        let ciphertext = &frame_data[16..];
        let nonce = Self::frame_nonce(base_nonce, frame_index);
        let mut plaintext = vec![0u8; ciphertext.len()];
        let aad = Self::frame_aad(sigma, frame_index, u64::from(frame_index) == last);
        self.key
            .open_detached(&nonce, &aad, ciphertext, &tag, &mut plaintext)
            .map_err(|e| AeadError::FrameDecrypt {
                frame: frame_index,
                reason: e.to_string(),
            })?;
        Ok(plaintext)
    }

    pub fn encrypt(&self, sigma: &str, plaintext: &[u8]) -> Result<EncryptedBlob, CryptoError> {
        let mut base_nonce = [0u8; 8];
        getrandom::fill(&mut base_nonce).map_err(|e| AeadError::NonceGeneration {
            reason: e.to_string(),
        })?;

        let frame_count = if plaintext.is_empty() {
            1
        } else {
            plaintext.len().div_ceil(FRAME_SIZE)
        };

        if frame_count as u64 > u64::from(u32::MAX) {
            return Err(AeadError::NonceGeneration {
                reason: "frame counter exhausted".into(),
            }
            .into());
        }
        let capacity = plaintext
            .len()
            .checked_add(frame_count * FRAME_TAG_SIZE)
            .ok_or_else(|| AeadError::NonceGeneration {
                reason: "encrypted length overflow".into(),
            })?;
        let mut disk_bytes = Vec::with_capacity(capacity);

        for i in 0..frame_count {
            let start = i * FRAME_SIZE;
            let end = min(start + FRAME_SIZE, plaintext.len());
            let frame_plaintext = &plaintext[start..end];
            let nonce = Self::frame_nonce(&base_nonce, i as u32);
            let aad = Self::frame_aad(sigma, i as u32, i + 1 == frame_count);
            let mut frame_ct = vec![0u8; frame_plaintext.len()];
            let mut tag = [0u8; 16];
            self.key
                .seal_detached(&nonce, &aad, frame_plaintext, &mut frame_ct, &mut tag)
                .map_err(|e| AeadError::FrameEncrypt {
                    frame: i as u32,
                    reason: e.to_string(),
                })?;
            disk_bytes.extend_from_slice(&tag);
            disk_bytes.extend_from_slice(&frame_ct);
        }

        Ok(EncryptedBlob {
            disk_bytes,
            base_nonce,
            plaintext_size: plaintext.len() as u64,
        })
    }

    pub fn encrypt_streaming(
        &self,
        sigma: &str,
        reader: &mut dyn Read,
        writer: &mut dyn Write,
    ) -> Result<([u8; 8], u64), CryptoError> {
        let mut base_nonce = [0u8; 8];
        getrandom::fill(&mut base_nonce).map_err(|e| AeadError::NonceGeneration {
            reason: e.to_string(),
        })?;
        let mut frame_index: u32 = 0;
        let mut plaintext_size: u64 = 0;
        // Age stream.go:307-350 retains one lookahead byte to authenticate
        // termination even when the final frame is exactly full.
        let mut frame_buf = vec![0u8; FRAME_SIZE + 1];
        let mut carried = 0;

        loop {
            let mut frame_len = carried;
            while frame_len < frame_buf.len() {
                match reader.read(&mut frame_buf[frame_len..]) {
                    Ok(0) => break,
                    Ok(n) => frame_len += n,
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(e) => {
                        return Err(AeadError::IoFailed {
                            op: "read plaintext",
                            reason: e.to_string(),
                        }
                        .into());
                    }
                }
            }
            let last = frame_len <= FRAME_SIZE;
            let frame_len = frame_len.min(FRAME_SIZE);
            if frame_index == u32::MAX {
                return Err(AeadError::NonceGeneration {
                    reason: "frame counter exhausted".into(),
                }
                .into());
            }
            let aad = Self::frame_aad(sigma, frame_index, last);
            let nonce = Self::frame_nonce(&base_nonce, frame_index);
            let mut frame_ct = vec![0u8; frame_len];
            let mut tag = [0u8; 16];
            self.key
                .seal_detached(
                    &nonce,
                    &aad,
                    &frame_buf[..frame_len],
                    &mut frame_ct,
                    &mut tag,
                )
                .map_err(|e| AeadError::FrameEncrypt {
                    frame: frame_index,
                    reason: e.to_string(),
                })?;
            writer.write_all(&tag).map_err(|e| AeadError::IoFailed {
                op: "write tag",
                reason: e.to_string(),
            })?;
            writer
                .write_all(&frame_ct)
                .map_err(|e| AeadError::IoFailed {
                    op: "write ciphertext",
                    reason: e.to_string(),
                })?;

            plaintext_size += frame_len as u64;
            frame_index += 1;
            if last {
                break;
            }
            frame_buf[0] = frame_buf[FRAME_SIZE];
            carried = 1;
        }
        Ok((base_nonce, plaintext_size))
    }

    pub fn decrypt_all(
        &self,
        sigma: &str,
        disk_bytes: &[u8],
        base_nonce: &[u8; 8],
        plaintext_size: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        let size = Self::validate_framing(disk_bytes.len(), plaintext_size)?;
        let mut plaintext = Vec::with_capacity(size);
        let mut pos = 0;
        let mut frame_index: u32 = 0;
        while pos < disk_bytes.len() {
            let remaining_pt = (plaintext_size as usize).saturating_sub(plaintext.len());
            let frame_ct_len = min(FRAME_SIZE, remaining_pt);
            let frame_disk_len = FRAME_TAG_SIZE + frame_ct_len;
            if pos + frame_disk_len > disk_bytes.len() {
                return Err(AeadError::FrameTruncated {
                    frame: frame_index,
                    got: disk_bytes.len() - pos,
                    expected: frame_disk_len,
                }
                .into());
            }
            let frame_pt = self.decrypt_frame(
                sigma,
                base_nonce,
                frame_index,
                &disk_bytes[pos..pos + frame_disk_len],
                plaintext_size,
            )?;
            plaintext.extend_from_slice(&frame_pt);
            pos += frame_disk_len;
            frame_index += 1;
        }
        if plaintext.len() != plaintext_size as usize {
            return Err(AeadError::SizeMismatch {
                expected: plaintext_size,
                got: plaintext.len() as u64,
            }
            .into());
        }
        Ok(plaintext)
    }

    pub fn decrypt_range(
        &self,
        sigma: &str,
        disk_bytes: &[u8],
        base_nonce: &[u8; 8],
        plaintext_size: u64,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        Self::validate_framing(disk_bytes.len(), plaintext_size)?;
        // Age stream.go:380-409 authenticates the final frame before trusting
        // random-access size. A length check alone accepts boundary truncation.
        let last = (plaintext_size.saturating_sub(1) / FRAME_SIZE as u64) as u32;
        let final_offset = last as usize * FRAME_DISK_SIZE;
        self.decrypt_frame(
            sigma,
            base_nonce,
            last,
            &disk_bytes[final_offset..],
            plaintext_size,
        )?;
        if offset >= plaintext_size {
            return Ok(Vec::new());
        }
        let actual_length = min(length, plaintext_size - offset);
        if actual_length == 0 {
            return Ok(Vec::new());
        }

        let start_frame = (offset / FRAME_SIZE as u64) as u32;
        let end_frame = ((offset + actual_length - 1) / FRAME_SIZE as u64) as u32;
        let mut decrypted_frames = Vec::new();

        for fi in start_frame..=end_frame {
            let frame_pt_len = Self::frame_plaintext_size(plaintext_size, fi);
            let frame_disk_len = FRAME_TAG_SIZE + frame_pt_len;
            let disk_offset = fi as usize * FRAME_DISK_SIZE;
            if disk_offset + frame_disk_len > disk_bytes.len() {
                return Err(AeadError::FrameTruncated {
                    frame: fi,
                    got: disk_bytes.len().saturating_sub(disk_offset),
                    expected: frame_disk_len,
                }
                .into());
            }
            let frame_pt = self.decrypt_frame(
                sigma,
                base_nonce,
                fi,
                &disk_bytes[disk_offset..disk_offset + frame_disk_len],
                plaintext_size,
            )?;
            decrypted_frames.extend_from_slice(&frame_pt);
        }

        let frames_start_offset = start_frame as u64 * FRAME_SIZE as u64;
        let slice_start = (offset - frames_start_offset) as usize;
        let slice_end = slice_start + actual_length as usize;
        Ok(decrypted_frames[slice_start..slice_end].to_vec())
    }

    fn validate_framing(disk_size: usize, plaintext_size: u64) -> Result<usize, CryptoError> {
        let size = usize::try_from(plaintext_size).map_err(|_| AeadError::SizeMismatch {
            expected: plaintext_size,
            got: disk_size as u64,
        })?;
        super::framing::FrameLayout::new(plaintext_size)?.check_encrypted_size(disk_size as u64)?;
        Ok(size)
    }

    fn frame_aad(identity: &str, index: u32, last: bool) -> Vec<u8> {
        // Rekindle FrameCipher binds presentation context in AAD; Age binds
        // finality cryptographically. Keep this framing protocol-neutral.
        let mut aad = Vec::with_capacity(identity.len() + 32);
        aad.extend_from_slice(b"kappa-aead-frame-v1");
        aad.extend_from_slice(&(identity.len() as u64).to_be_bytes());
        aad.extend_from_slice(identity.as_bytes());
        aad.extend_from_slice(&index.to_be_bytes());
        aad.push(u8::from(last));
        aad
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_encryptor() -> BlobEncryptor {
        let mut root = [0u8; 32];
        getrandom::fill(&mut root).expect("rng");
        let dir = tempfile::tempdir().expect("tempdir");
        let kms = super::super::kms::FileKms::new(root, dir.path().join("erased")).expect("kms");
        BlobEncryptor::new(&kms, "test-namespace").expect("encryptor")
    }

    #[test]
    fn small_blob_roundtrip() {
        let enc = test_encryptor();
        let plaintext = b"hello world";
        let encrypted = enc.encrypt("sigma:test", plaintext).expect("encrypt");
        assert_ne!(&encrypted.disk_bytes, plaintext.as_slice());
        let decrypted = enc
            .decrypt_all(
                "sigma:test",
                &encrypted.disk_bytes,
                &encrypted.base_nonce,
                encrypted.plaintext_size,
            )
            .expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn multiframe_roundtrip() {
        let enc = test_encryptor();
        let plaintext = vec![0xABu8; FRAME_SIZE * 3 + 100];
        let encrypted = enc.encrypt("sigma:multi", &plaintext).expect("encrypt");
        assert_eq!(encrypted.plaintext_size, plaintext.len() as u64);
        let decrypted = enc
            .decrypt_all(
                "sigma:multi",
                &encrypted.disk_bytes,
                &encrypted.base_nonce,
                encrypted.plaintext_size,
            )
            .expect("decrypt");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn empty_blob_roundtrip() {
        let enc = test_encryptor();
        let encrypted = enc.encrypt("sigma:empty", b"").expect("encrypt");
        assert_eq!(encrypted.plaintext_size, 0);
        let decrypted = enc
            .decrypt_all(
                "sigma:empty",
                &encrypted.disk_bytes,
                &encrypted.base_nonce,
                encrypted.plaintext_size,
            )
            .expect("decrypt");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn wrong_sigma_fails() {
        let enc = test_encryptor();
        let encrypted = enc.encrypt("sigma:correct", b"secret").expect("encrypt");
        let result = enc.decrypt_all(
            "sigma:wrong",
            &encrypted.disk_bytes,
            &encrypted.base_nonce,
            encrypted.plaintext_size,
        );
        assert!(result.is_err(), "wrong sigma must fail AEAD authentication");
    }

    #[test]
    fn tampered_frame_fails() {
        let enc = test_encryptor();
        let plaintext = b"tamper test data";
        let encrypted = enc.encrypt("sigma:tamper", plaintext).expect("encrypt");
        let mut tampered = encrypted.disk_bytes.clone();
        // Flip a byte in the ciphertext (after the 16-byte tag)
        if tampered.len() > 20 {
            tampered[20] ^= 0xFF;
        }
        let result = enc.decrypt_all(
            "sigma:tamper",
            &tampered,
            &encrypted.base_nonce,
            encrypted.plaintext_size,
        );
        assert!(result.is_err(), "tampered ciphertext must fail");
    }

    #[test]
    fn nondeterministic_encryption() {
        let enc = test_encryptor();
        let plaintext = b"same content";
        let a = enc.encrypt("sigma:nd", plaintext).expect("encrypt a");
        let b = enc.encrypt("sigma:nd", plaintext).expect("encrypt b");
        assert_ne!(
            a.base_nonce, b.base_nonce,
            "each encrypt uses a fresh random nonce"
        );
        assert_ne!(
            a.disk_bytes, b.disk_bytes,
            "different nonces produce different ciphertext"
        );
    }

    #[test]
    fn range_read_single_frame() {
        let enc = test_encryptor();
        let plaintext = b"0123456789abcdef";
        let encrypted = enc.encrypt("sigma:range", plaintext).expect("encrypt");
        let range = enc
            .decrypt_range(
                "sigma:range",
                &encrypted.disk_bytes,
                &encrypted.base_nonce,
                encrypted.plaintext_size,
                4,
                8,
            )
            .expect("range");
        assert_eq!(range, b"456789ab");
    }

    #[test]
    fn range_read_spanning_frames() {
        let enc = test_encryptor();
        let plaintext = vec![0x42u8; FRAME_SIZE + 100];
        let encrypted = enc.encrypt("sigma:span", &plaintext).expect("encrypt");
        // Read across the frame boundary
        let start = FRAME_SIZE as u64 - 10;
        let length = 20;
        let range = enc
            .decrypt_range(
                "sigma:span",
                &encrypted.disk_bytes,
                &encrypted.base_nonce,
                encrypted.plaintext_size,
                start,
                length,
            )
            .expect("range");
        assert_eq!(range.len(), 20);
        assert!(range.iter().all(|&b| b == 0x42));
    }

    #[test]
    fn range_past_end_returns_empty() {
        let enc = test_encryptor();
        let encrypted = enc.encrypt("sigma:past", b"short").expect("encrypt");
        let range = enc
            .decrypt_range(
                "sigma:past",
                &encrypted.disk_bytes,
                &encrypted.base_nonce,
                encrypted.plaintext_size,
                100,
                50,
            )
            .expect("range past end");
        assert!(range.is_empty());
    }

    #[test]
    fn clone_for_reader_produces_working_encryptor() {
        let enc = test_encryptor();
        let plaintext = b"clone test";
        let encrypted = enc.encrypt("sigma:clone", plaintext).expect("encrypt");
        let cloned = enc.clone_for_reader().expect("clone");
        let decrypted = cloned
            .decrypt_all(
                "sigma:clone",
                &encrypted.disk_bytes,
                &encrypted.base_nonce,
                encrypted.plaintext_size,
            )
            .expect("decrypt with clone");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn streaming_matches_in_memory() {
        let enc = test_encryptor();
        let plaintext = vec![0xCDu8; FRAME_SIZE * 2 + 500];
        let in_mem = enc.encrypt("sigma:stream", &plaintext).expect("in-memory");

        let mut reader = std::io::Cursor::new(&plaintext);
        let mut writer = Vec::new();
        let (stream_nonce, stream_size) = enc
            .encrypt_streaming("sigma:stream", &mut reader, &mut writer)
            .expect("streaming");

        assert_eq!(stream_size, plaintext.len() as u64);
        // Streaming produces different ciphertext (different nonce) but same plaintext size
        let decrypted = enc
            .decrypt_all("sigma:stream", &writer, &stream_nonce, stream_size)
            .expect("decrypt streaming");
        assert_eq!(decrypted, plaintext);

        // In-memory also decrypts correctly
        let decrypted_mem = enc
            .decrypt_all(
                "sigma:stream",
                &in_mem.disk_bytes,
                &in_mem.base_nonce,
                in_mem.plaintext_size,
            )
            .expect("decrypt in-memory");
        assert_eq!(decrypted_mem, plaintext);
    }

    #[test]
    fn frame_nonce_varies_by_index() {
        let base = [1u8; 8];
        let n0 = BlobEncryptor::frame_nonce(&base, 0);
        let n1 = BlobEncryptor::frame_nonce(&base, 1);
        assert_ne!(n0, n1);
        assert_eq!(&n0[..8], &base);
        assert_eq!(&n1[..8], &base);
        assert_eq!(&n0[8..], &0u32.to_be_bytes());
        assert_eq!(&n1[8..], &1u32.to_be_bytes());
    }

    #[test]
    fn frame_plaintext_size_last_frame() {
        assert_eq!(BlobEncryptor::frame_plaintext_size(100, 0), 100);
        assert_eq!(
            BlobEncryptor::frame_plaintext_size(FRAME_SIZE as u64 + 1, 0),
            FRAME_SIZE
        );
        assert_eq!(
            BlobEncryptor::frame_plaintext_size(FRAME_SIZE as u64 + 1, 1),
            1
        );
        assert_eq!(
            BlobEncryptor::frame_plaintext_size(FRAME_SIZE as u64, 0),
            FRAME_SIZE
        );
        assert_eq!(BlobEncryptor::frame_plaintext_size(FRAME_SIZE as u64, 1), 0);
    }
}
