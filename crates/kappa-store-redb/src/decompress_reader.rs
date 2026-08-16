//! Decompression utilities for compression-transparent blob storage.
//!
//! Supports zstd, xz, bzip2, and none (passthrough). Used by
//! blob_open_decompressed_impl to produce decompressed content
//! from compressed blobs on disk.

use kappa_core::types::StoreError;

/// Decompress bytes according to the compression algorithm name.
///
/// Returns the full decompressed content. For streaming decompression
/// with bounded memory, use blob_open_compressed and a protocol-specific
/// streaming decompressor instead.
pub fn decompress(data: &[u8], algorithm: &str) -> Result<Vec<u8>, StoreError> {
    match algorithm {
        "none" => Ok(data.to_vec()),
        "zstd" => zstd::decode_all(std::io::Cursor::new(data))
            .map_err(|e| StoreError::Io(std::io::Error::other(format!("zstd decompress: {e}")))),
        "xz" | "lzma" => {
            use std::io::Read;
            let mut decoder = xz2::read::XzDecoder::new(data);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)
                .map_err(|e| StoreError::Io(std::io::Error::other(format!("xz decompress: {e}"))))?;
            Ok(out)
        }
        "bzip2" => {
            use std::io::Read;
            let mut decoder = bzip2::read::BzDecoder::new(data);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out)
                .map_err(|e| StoreError::Io(std::io::Error::other(format!("bzip2 decompress: {e}"))))?;
            Ok(out)
        }
        other => Err(StoreError::Rejected(format!("unsupported compression algorithm: {other}"))),
    }
}
