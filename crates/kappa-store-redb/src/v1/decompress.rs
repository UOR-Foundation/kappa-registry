use kappa_store::error::StoreError;
use std::fs;
use std::io::{self, BufReader, Cursor, Read};

pub fn verify_compressed(
    data: &[u8],
    algorithm: &str,
    identity: &kappa_store::Kappa,
    expected_size: u64,
) -> Result<(), StoreError> {
    let mut decoded: Box<dyn Read + '_> = match algorithm {
        "none" => Box::new(Cursor::new(data)),
        "zstd" => Box::new(zstd::Decoder::new(Cursor::new(data))?),
        "xz" | "lzma" => Box::new(xz2::read::XzDecoder::new(data)),
        "bzip2" => Box::new(bzip2::read::BzDecoder::new(data)),
        other => {
            return Err(StoreError::Rejected(format!(
                "unsupported compression algorithm: {other}"
            )));
        }
    };
    kappa_store::blob_admission::verify_decoded(identity, expected_size, &mut decoded)
}

/// Decompress from a byte slice. Peak memory: compressed + uncompressed.
/// Use `decompress_file` when the source is on disk.
pub fn decompress(data: &[u8], algorithm: &str) -> Result<Vec<u8>, StoreError> {
    match algorithm {
        "none" => Ok(data.to_vec()),
        "zstd" => zstd::decode_all(Cursor::new(data))
            .map_err(|e| StoreError::Io(io::Error::other(format!("zstd: {e}")))),
        "xz" | "lzma" => {
            let mut decoder = xz2::read::XzDecoder::new(data);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| StoreError::Io(io::Error::other(format!("xz: {e}"))))?;
            Ok(out)
        }
        "bzip2" => {
            let mut decoder = bzip2::read::BzDecoder::new(data);
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| StoreError::Io(io::Error::other(format!("bzip2: {e}"))))?;
            Ok(out)
        }
        other => Err(StoreError::Rejected(format!(
            "unsupported compression algorithm: {other}"
        ))),
    }
}

/// Decompress from a file handle. Streams through the decoder so
/// the compressed content is never fully materialized in memory.
/// Peak memory: uncompressed size + decoder internal buffer (~128KB).
pub fn decompress_file(file: fs::File, algorithm: &str) -> Result<Vec<u8>, StoreError> {
    let reader = BufReader::new(file);
    match algorithm {
        "none" => {
            let mut out = Vec::new();
            let mut r = reader;
            r.read_to_end(&mut out).map_err(StoreError::Io)?;
            Ok(out)
        }
        "zstd" => {
            let mut decoder = zstd::Decoder::new(reader)
                .map_err(|e| StoreError::Io(io::Error::other(format!("zstd init: {e}"))))?;
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(StoreError::Io)?;
            Ok(out)
        }
        "xz" | "lzma" => {
            let mut decoder = xz2::read::XzDecoder::new(reader);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(StoreError::Io)?;
            Ok(out)
        }
        "bzip2" => {
            let mut decoder = bzip2::read::BzDecoder::new(reader);
            let mut out = Vec::new();
            decoder.read_to_end(&mut out).map_err(StoreError::Io)?;
            Ok(out)
        }
        other => Err(StoreError::Rejected(format!(
            "unsupported compression algorithm: {other}"
        ))),
    }
}
