//! Framed blob-at-rest AEAD encryption via rekindle-aead.
//!
//! Each blob is encrypted in fixed-size frames (64KB). Each frame is
//! independently encrypted with a nonce derived from a per-blob random
//! base nonce combined with the frame index. This enables:
//! - Range reads: decrypt only the frames overlapping the requested range.
//! - Verify-on-read: hash(bytes_on_disk) == kappa without the key.
//! - Parallel decryption of independent frames.
//!
//! On-disk format per frame: [tag:16][ciphertext:<=FRAME_SIZE]
//! Total disk overhead: 16 bytes per frame.
//!
//! The sigma (protocol digest, hash of plaintext) is used as AAD for
//! every frame, binding ciphertext to the protocol-facing content address.

use super::kms::KeyManagementService;
use super::CryptoError;

use rekindle_aead::aes_gcm::AesGcmKey;
use rekindle_aead::BulkAead;

/// Frame size for framed AEAD: 65536 bytes (64KB).
/// Matches STREAM_CHUNK_SIZE in the download path.
pub const FRAME_SIZE: usize = 65536;

/// Per-frame on-disk overhead: 16-byte AEAD tag.
pub const FRAME_TAG_SIZE: usize = 16;

/// Total on-disk size per frame: content + tag.
pub const FRAME_DISK_SIZE: usize = FRAME_SIZE + FRAME_TAG_SIZE;

/// Blob encryption context for a single namespace.
pub struct BlobEncryptor {
    key: AesGcmKey,
    /// Raw 32-byte AES key bytes. Stored so clone_for_reader() can
    /// construct an independent AesGcmKey (LessSafeKey is not Clone).
    raw_key_bytes: [u8; 32],
}

/// Result of encrypting a blob.
pub struct EncryptedBlob {
    /// The complete on-disk representation: concatenated
    /// [tag:16][ciphertext:<=FRAME_SIZE] frames.
    pub disk_bytes: Vec<u8>,
    /// The random base nonce. Store in the binding record.
    pub base_nonce: [u8; 8],
    /// Original plaintext size. Store in the binding record.
    pub plaintext_size: u64,
}

impl BlobEncryptor {
    /// Create an encryptor for a namespace using a KMS-derived key.
    pub fn new(
        kms: &dyn KeyManagementService,
        namespace: &str,
    ) -> Result<Self, CryptoError> {
        let derived = kms.derive_subject_key(namespace, "_blob_encryption")?;
        let key_bytes: [u8; 32] = derived
            .try_into()
            .map_err(|_| CryptoError::InvalidKey)?;
        let aes_key = AesGcmKey::new(&key_bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            key: aes_key,
            raw_key_bytes: key_bytes,
        })
    }

    /// Construct a new independent BlobEncryptor from the same raw key.
    /// Used by FrameDecryptingReader which needs to own its own encryptor.
    /// AesGcmKey wraps LessSafeKey which is not Clone, so we expand a
    /// new key schedule from the stored raw bytes.
    pub fn clone_for_reader(&self) -> Result<Self, CryptoError> {
        let aes_key = AesGcmKey::new(&self.raw_key_bytes)
            .map_err(|_| CryptoError::InvalidKey)?;
        Ok(Self {
            key: aes_key,
            raw_key_bytes: self.raw_key_bytes,
        })
    }

    /// Build a 12-byte nonce for a specific frame.
    /// nonce = [base_nonce:8][frame_index_be:4]
    pub(crate) fn frame_nonce(base_nonce: &[u8; 8], frame_index: u32) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(base_nonce);
        nonce[8..12].copy_from_slice(&frame_index.to_be_bytes());
        nonce
    }

    /// Compute the plaintext size of a specific frame given total plaintext size.
    pub fn frame_plaintext_size(plaintext_size: u64, frame_index: u32) -> usize {
        let frame_start = frame_index as u64 * FRAME_SIZE as u64;
        let remaining = plaintext_size.saturating_sub(frame_start);
        std::cmp::min(FRAME_SIZE as u64, remaining) as usize
    }

    /// Decrypt a single frame read from disk.
    ///
    /// `frame_data` is [tag:16][ciphertext:N] as read from disk.
    /// `base_nonce` and `frame_index` determine the frame nonce.
    /// `sigma` is used as AAD.
    /// Returns the decrypted plaintext for this frame.
    pub fn decrypt_frame(
        &self,
        sigma: &str,
        base_nonce: &[u8; 8],
        frame_index: u32,
        frame_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if frame_data.len() < FRAME_TAG_SIZE {
            return Err(CryptoError::SigningFailed("frame too short for tag".into()));
        }
        let tag: [u8; 16] = frame_data[..16].try_into().unwrap();
        let ciphertext = &frame_data[16..];

        let nonce = Self::frame_nonce(base_nonce, frame_index);
        let mut plaintext = vec![0u8; ciphertext.len()];
        self.key
            .open_detached(&nonce, sigma.as_bytes(), ciphertext, &tag, &mut plaintext)
            .map_err(|e| CryptoError::SigningFailed(format!("frame {} decrypt: {e}", frame_index)))?;
        Ok(plaintext)
    }

    /// Encrypt a blob in fixed-size frames.
    pub fn encrypt(
        &self,
        sigma: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedBlob, CryptoError> {
        let mut base_nonce = [0u8; 8];
        getrandom::fill(&mut base_nonce)
            .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;

        let frame_count = if plaintext.is_empty() {
            1
        } else {
            (plaintext.len() + FRAME_SIZE - 1) / FRAME_SIZE
        };

        let mut disk_bytes = Vec::with_capacity(frame_count * FRAME_DISK_SIZE);
        let aad = sigma.as_bytes();

        for i in 0..frame_count {
            let start = i * FRAME_SIZE;
            let end = std::cmp::min(start + FRAME_SIZE, plaintext.len());
            let frame_plaintext = &plaintext[start..end];

            let nonce = Self::frame_nonce(&base_nonce, i as u32);
            let mut frame_ct = vec![0u8; frame_plaintext.len()];
            let mut tag = [0u8; 16];

            self.key
                .seal_detached(&nonce, aad, frame_plaintext, &mut frame_ct, &mut tag)
                .map_err(|e| CryptoError::SigningFailed(format!("frame {i} seal: {e}")))?;

            disk_bytes.extend_from_slice(&tag);
            disk_bytes.extend_from_slice(&frame_ct);
        }

        Ok(EncryptedBlob {
            disk_bytes,
            base_nonce,
            plaintext_size: plaintext.len() as u64,
        })
    }

    /// Streaming framed encryption from a reader to a writer.
    ///
    /// Reads plaintext in FRAME_SIZE chunks, encrypts each frame, writes
    /// [tag:16][ciphertext:<=FRAME_SIZE] to the writer. Never holds more
    /// than one frame in memory (~128 KiB total: plaintext + ciphertext).
    ///
    /// Returns (base_nonce, plaintext_size). The caller hashes the writer's
    /// output to get kappa, then renames to the kappa path.
    pub fn encrypt_streaming(
        &self,
        sigma: &str,
        reader: &mut dyn std::io::Read,
        writer: &mut dyn std::io::Write,
    ) -> Result<(/*base_nonce*/ [u8; 8], /*plaintext_size*/ u64), CryptoError> {
        let mut base_nonce = [0u8; 8];
        getrandom::fill(&mut base_nonce)
            .map_err(|e| CryptoError::KeyGeneration(e.to_string()))?;

        let aad = sigma.as_bytes();
        let mut frame_index: u32 = 0;
        let mut plaintext_size: u64 = 0;
        let mut frame_buf = vec![0u8; FRAME_SIZE];

        loop {
            // Read up to FRAME_SIZE bytes
            let mut frame_len = 0;
            while frame_len < FRAME_SIZE {
                match reader.read(&mut frame_buf[frame_len..]) {
                    Ok(0) => break,
                    Ok(n) => frame_len += n,
                    Err(e) => return Err(CryptoError::SigningFailed(format!("read: {e}"))),
                }
            }

            if frame_len == 0 && frame_index > 0 {
                // EOF after at least one frame -- done
                break;
            }

            // Encrypt this frame
            let frame_plaintext = &frame_buf[..frame_len];
            let nonce = Self::frame_nonce(&base_nonce, frame_index);
            let mut frame_ct = vec![0u8; frame_len];
            let mut tag = [0u8; 16];
            self.key
                .seal_detached(&nonce, aad, frame_plaintext, &mut frame_ct, &mut tag)
                .map_err(|e| CryptoError::SigningFailed(format!("frame {frame_index} seal: {e}")))?;

            // Write [tag:16][ciphertext] to output
            writer.write_all(&tag)
                .map_err(|e| CryptoError::SigningFailed(format!("write tag: {e}")))?;
            writer.write_all(&frame_ct)
                .map_err(|e| CryptoError::SigningFailed(format!("write ct: {e}")))?;

            plaintext_size += frame_len as u64;
            frame_index += 1;

            if frame_len == 0 {
                // Empty blob: wrote one frame with tag only
                break;
            }
            if frame_len < FRAME_SIZE {
                // Last frame was short -- EOF
                break;
            }
        }

        Ok((base_nonce, plaintext_size))
    }

    /// Decrypt all frames of an encrypted blob.
    pub fn decrypt_all(
        &self,
        sigma: &str,
        disk_bytes: &[u8],
        base_nonce: &[u8; 8],
        plaintext_size: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut plaintext = Vec::with_capacity(plaintext_size as usize);
        let mut pos = 0;
        let mut frame_index: u32 = 0;

        while pos < disk_bytes.len() {
            let remaining_pt = (plaintext_size as usize).saturating_sub(plaintext.len());
            let frame_ct_len = std::cmp::min(FRAME_SIZE, remaining_pt);
            let frame_disk_len = FRAME_TAG_SIZE + frame_ct_len;

            if pos + frame_disk_len > disk_bytes.len() {
                return Err(CryptoError::SigningFailed("truncated frame".into()));
            }

            let frame_pt = self.decrypt_frame(
                sigma, base_nonce, frame_index, &disk_bytes[pos..pos + frame_disk_len],
            )?;
            plaintext.extend_from_slice(&frame_pt);
            pos += frame_disk_len;
            frame_index += 1;
        }

        if plaintext.len() != plaintext_size as usize {
            return Err(CryptoError::SigningFailed(format!(
                "decrypted {} bytes but expected {}",
                plaintext.len(), plaintext_size
            )));
        }
        Ok(plaintext)
    }

    /// Decrypt a range of frames overlapping [offset, offset+length).
    pub fn decrypt_range(
        &self,
        sigma: &str,
        disk_bytes: &[u8],
        base_nonce: &[u8; 8],
        plaintext_size: u64,
        offset: u64,
        length: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        if offset >= plaintext_size {
            return Ok(Vec::new());
        }
        let actual_length = std::cmp::min(length, plaintext_size - offset);
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
                return Err(CryptoError::SigningFailed(format!(
                    "frame {} beyond disk (offset={}, len={}, total={})",
                    fi, disk_offset, frame_disk_len, disk_bytes.len()
                )));
            }

            let frame_pt = self.decrypt_frame(
                sigma, base_nonce, fi,
                &disk_bytes[disk_offset..disk_offset + frame_disk_len],
            )?;
            decrypted_frames.extend_from_slice(&frame_pt);
        }

        let frames_start_offset = start_frame as u64 * FRAME_SIZE as u64;
        let slice_start = (offset - frames_start_offset) as usize;
        let slice_end = slice_start + actual_length as usize;
        Ok(decrypted_frames[slice_start..slice_end].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::kms::FileKms;

    fn test_kms() -> (FileKms, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let kms = FileKms::new([0x42u8; 32], dir.path().join("erased")).unwrap();
        (kms, dir)
    }

    #[test]
    fn encrypt_decrypt_roundtrip_small() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let plaintext = b"hello encrypted world";
        let sigma = "sha256:aabbccdd";
        let encrypted = enc.encrypt(sigma, plaintext).unwrap();
        assert_eq!(encrypted.disk_bytes.len(), 16 + plaintext.len());
        let pt = enc.decrypt_all(sigma, &encrypted.disk_bytes, &encrypted.base_nonce, encrypted.plaintext_size).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_multiframe() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let plaintext: Vec<u8> = (0..FRAME_SIZE * 2 + FRAME_SIZE / 2)
            .map(|i| (i % 251) as u8).collect();
        let sigma = "sha256:multiframe";
        let encrypted = enc.encrypt(sigma, &plaintext).unwrap();
        let expected_disk = 2 * FRAME_DISK_SIZE + 16 + FRAME_SIZE / 2;
        assert_eq!(encrypted.disk_bytes.len(), expected_disk);
        let pt = enc.decrypt_all(sigma, &encrypted.disk_bytes, &encrypted.base_nonce, encrypted.plaintext_size).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn wrong_sigma_fails() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let encrypted = enc.encrypt("sha256:aaa", b"secret").unwrap();
        assert!(enc.decrypt_all("sha256:bbb", &encrypted.disk_bytes, &encrypted.base_nonce, encrypted.plaintext_size).is_err());
    }

    #[test]
    fn nondeterministic_encryption() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let sigma = "sha256:nondet";
        let e1 = enc.encrypt(sigma, b"same content").unwrap();
        let e2 = enc.encrypt(sigma, b"same content").unwrap();
        assert_ne!(e1.base_nonce, e2.base_nonce);
        assert_ne!(e1.disk_bytes, e2.disk_bytes);
        let p1 = enc.decrypt_all(sigma, &e1.disk_bytes, &e1.base_nonce, e1.plaintext_size).unwrap();
        let p2 = enc.decrypt_all(sigma, &e2.disk_bytes, &e2.base_nonce, e2.plaintext_size).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn tampered_frame_fails() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let sigma = "sha256:tamper";
        let mut encrypted = enc.encrypt(sigma, b"original content here").unwrap();
        encrypted.disk_bytes[16] ^= 0xFF;
        assert!(enc.decrypt_all(sigma, &encrypted.disk_bytes, &encrypted.base_nonce, encrypted.plaintext_size).is_err());
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let sigma = "sha256:empty";
        let encrypted = enc.encrypt(sigma, b"").unwrap();
        assert_eq!(encrypted.plaintext_size, 0);
        assert_eq!(encrypted.disk_bytes.len(), 16);
        let pt = enc.decrypt_all(sigma, &encrypted.disk_bytes, &encrypted.base_nonce, encrypted.plaintext_size).unwrap();
        assert!(pt.is_empty());
    }

    #[test]
    fn range_read_within_single_frame() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let plaintext: Vec<u8> = (0..1024).map(|i| (i % 251) as u8).collect();
        let sigma = "sha256:range1";
        let encrypted = enc.encrypt(sigma, &plaintext).unwrap();
        let range = enc.decrypt_range(sigma, &encrypted.disk_bytes, &encrypted.base_nonce, encrypted.plaintext_size, 100, 200).unwrap();
        assert_eq!(range, &plaintext[100..300]);
    }

    #[test]
    fn range_read_spanning_frames() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let plaintext: Vec<u8> = (0..FRAME_SIZE * 3).map(|i| (i % 251) as u8).collect();
        let sigma = "sha256:range_span";
        let encrypted = enc.encrypt(sigma, &plaintext).unwrap();
        let offset = FRAME_SIZE as u64 - 100;
        let length = 200;
        let range = enc.decrypt_range(sigma, &encrypted.disk_bytes, &encrypted.base_nonce, encrypted.plaintext_size, offset, length).unwrap();
        assert_eq!(range.len(), 200);
        assert_eq!(range, &plaintext[offset as usize..(offset + length) as usize]);
    }

    #[test]
    fn range_read_past_end_returns_short() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let plaintext = b"short";
        let sigma = "sha256:range_past";
        let encrypted = enc.encrypt(sigma, plaintext).unwrap();
        let range = enc.decrypt_range(sigma, &encrypted.disk_bytes, &encrypted.base_nonce, encrypted.plaintext_size, 3, 100).unwrap();
        assert_eq!(range, b"rt");
    }

    #[test]
    fn range_read_at_end_returns_empty() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let plaintext = b"hello";
        let sigma = "sha256:range_end";
        let encrypted = enc.encrypt(sigma, plaintext).unwrap();
        let range = enc.decrypt_range(sigma, &encrypted.disk_bytes, &encrypted.base_nonce, encrypted.plaintext_size, 5, 10).unwrap();
        assert!(range.is_empty());
    }

    #[test]
    fn clone_for_reader_produces_working_encryptor() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let sigma = "sha256:clone_test";
        let encrypted = enc.encrypt(sigma, b"clone reader data").unwrap();
        let reader_enc = enc.clone_for_reader().unwrap();
        let pt = reader_enc.decrypt_all(sigma, &encrypted.disk_bytes, &encrypted.base_nonce, encrypted.plaintext_size).unwrap();
        assert_eq!(pt, b"clone reader data");
    }

    #[test]
    fn decrypt_frame_roundtrip() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let sigma = "sha256:single_frame";
        let encrypted = enc.encrypt(sigma, b"frame test").unwrap();
        let pt = enc.decrypt_frame(sigma, &encrypted.base_nonce, 0, &encrypted.disk_bytes).unwrap();
        assert_eq!(pt, b"frame test");
    }

    #[test]
    fn erased_key_prevents_new_encryptor() {
        let (kms, _dir) = test_kms();
        let _enc = BlobEncryptor::new(&kms, "erase-ns").unwrap();
        kms.erase_subject_key("erase-ns", "_blob_encryption").unwrap();
        assert!(BlobEncryptor::new(&kms, "erase-ns").is_err());
    }

    #[test]
    fn exactly_one_frame_boundary() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let plaintext: Vec<u8> = (0..FRAME_SIZE).map(|i| (i % 251) as u8).collect();
        let sigma = "sha256:exact_frame";
        let encrypted = enc.encrypt(sigma, &plaintext).unwrap();
        assert_eq!(encrypted.disk_bytes.len(), FRAME_DISK_SIZE);
        let pt = enc.decrypt_all(sigma, &encrypted.disk_bytes, &encrypted.base_nonce, encrypted.plaintext_size).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn frame_size_plus_one() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let plaintext: Vec<u8> = (0..FRAME_SIZE + 1).map(|i| (i % 251) as u8).collect();
        let sigma = "sha256:frame_plus_one";
        let encrypted = enc.encrypt(sigma, &plaintext).unwrap();
        assert_eq!(encrypted.disk_bytes.len(), FRAME_DISK_SIZE + 16 + 1);
        let pt = enc.decrypt_all(sigma, &encrypted.disk_bytes, &encrypted.base_nonce, encrypted.plaintext_size).unwrap();
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn encrypt_streaming_matches_encrypt() {
        let (kms, _dir) = test_kms();
        let enc = BlobEncryptor::new(&kms, "test-ns").unwrap();
        let plaintext: Vec<u8> = (0..FRAME_SIZE * 3 + 1000)
            .map(|i| (i % 251) as u8).collect();
        let sigma = "sha256:test_streaming_match";

        // In-memory encrypt
        let mem_result = enc.encrypt(sigma, &plaintext).unwrap();

        // Streaming encrypt
        let mut pt_cursor = std::io::Cursor::new(&plaintext);
        let mut ct_buf = Vec::new();
        let (stream_nonce, stream_pt_size) = enc
            .encrypt_streaming(sigma, &mut pt_cursor, &mut ct_buf)
            .unwrap();

        // Plaintext sizes match
        assert_eq!(mem_result.plaintext_size, stream_pt_size);
        assert_eq!(stream_pt_size, plaintext.len() as u64);

        // Both produce valid ciphertext that decrypts to the same plaintext
        let dec_mem = enc.decrypt_all(
            sigma, &mem_result.disk_bytes, &mem_result.base_nonce,
            mem_result.plaintext_size,
        ).unwrap();
        let dec_stream = enc.decrypt_all(
            sigma, &ct_buf, &stream_nonce, stream_pt_size,
        ).unwrap();
        assert_eq!(dec_mem, plaintext);
        assert_eq!(dec_stream, plaintext);

        // Same frame count
        let mem_frames = (mem_result.disk_bytes.len() + FRAME_DISK_SIZE - 1) / FRAME_DISK_SIZE;
        let stream_frames = (ct_buf.len() + FRAME_DISK_SIZE - 1) / FRAME_DISK_SIZE;
        assert_eq!(mem_frames, stream_frames);

        // Range read across frame boundary on streaming-encrypted output
        let mid_frame_offset = FRAME_SIZE as u64 + 100;
        let range_len = FRAME_SIZE as u64;
        let range_result = enc.decrypt_range(
            sigma, &ct_buf, &stream_nonce, stream_pt_size,
            mid_frame_offset, range_len,
        ).unwrap();
        assert_eq!(
            range_result,
            &plaintext[mid_frame_offset as usize..(mid_frame_offset + range_len) as usize],
        );

        // Partial last frame read
        let last_frame_start = (FRAME_SIZE * 3) as u64;
        let remaining = plaintext.len() as u64 - last_frame_start;
        let last_result = enc.decrypt_range(
            sigma, &ct_buf, &stream_nonce, stream_pt_size,
            last_frame_start, remaining,
        ).unwrap();
        assert_eq!(last_result, &plaintext[last_frame_start as usize..]);
    }
}
