//! Decoding of compressed representations, with bounded decoder memory:
//! the one decoder construction every store backend and protocol module
//! decodes through.
//!
//! Admission (`verify_compressed`), whole reads (`decompress`) and
//! streamed reads ([`Codec::decoder`]) build the same decoders, so content
//! admitted is decodable under the bounds every read applies. Each
//! decoder's working memory is capped at [`DECODER_WORKING_BYTES`], a store
//! policy limit, by the decoder's own control: the zstd window
//! (`Decoder::window_log_max`), the liblzma memory limit
//! (`Stream::new_stream_decoder`), and bzip2's small mode
//! (`Decompress::new(true)`, documented at about 2300k). Content whose
//! decoding would need more is refused at admission, never stored. A zstd
//! decoder decodes every concatenated frame of its input; an xz and a
//! bzip2 decoder decode one stream.

use std::io::{self, BufRead, Read};

use kappa_types::Kappa;
use kappa_types::error::StoreError;
use kappa_types::work::{Dimension, Meter};

/// The most working memory one decoder may use: a store policy limit,
/// charged to a read before its decoder is built.
pub const DECODER_WORKING_BYTES: u64 = 1 << ZSTD_WINDOW_LOG_MAX;

/// The largest zstd window a stored frame may declare: `2^26` bytes.
const ZSTD_WINDOW_LOG_MAX: u32 = 26;

/// Bytes of decoded output one whole read decodes into per step.
const DECODE_CHUNK: usize = 8192;

/// The compression a stored representation names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    Stored,
    Zstd,
    Xz,
    Bzip2,
}

impl Codec {
    /// The codec `algorithm` names; an algorithm no codec decodes is
    /// refused, naming it.
    pub fn of(algorithm: &str) -> Result<Self, StoreError> {
        match algorithm {
            "none" => Ok(Self::Stored),
            "zstd" => Ok(Self::Zstd),
            "xz" | "lzma" => Ok(Self::Xz),
            "bzip2" => Ok(Self::Bzip2),
            other => Err(StoreError::Rejected(format!(
                "unsupported compression algorithm: {other}"
            ))),
        }
    }

    /// The working memory this codec's decoder may use.
    pub const fn working_bytes(self) -> u64 {
        match self {
            Self::Stored => 0,
            Self::Zstd | Self::Xz | Self::Bzip2 => DECODER_WORKING_BYTES,
        }
    }

    /// A decoder of the one stream `input` holds, within
    /// [`DECODER_WORKING_BYTES`]. `input` supplies the decoder's input
    /// buffer; the caller sizes and charges it.
    pub fn decoder<'a, R: BufRead + Send + 'a>(
        self,
        input: R,
    ) -> Result<Box<dyn Read + Send + 'a>, StoreError> {
        Ok(match self {
            Self::Stored => Box::new(input),
            Self::Zstd => {
                let mut decoder = zstd::Decoder::with_buffer(input)?;
                decoder.window_log_max(ZSTD_WINDOW_LOG_MAX)?;
                Box::new(decoder)
            }
            Self::Xz => {
                let stream = xz2::stream::Stream::new_stream_decoder(DECODER_WORKING_BYTES, 0)
                    .map_err(io::Error::from)?;
                Box::new(xz2::bufread::XzDecoder::new_stream(input, stream))
            }
            Self::Bzip2 => Box::new(SmallBzip2 {
                input,
                stream: bzip2::Decompress::new(true),
                done: false,
            }),
        })
    }
}

/// One bzip2 stream of `input` decoded in bzip2's small mode, which the
/// crate's readers do not offer (`bufread::BzDecoder::new` decodes in full
/// mode). The read loop is the crate's `bufread::BzDecoder::read` for a
/// single stream.
struct SmallBzip2<R> {
    input: R,
    stream: bzip2::Decompress,
    done: bool,
}

impl<R: BufRead> Read for SmallBzip2<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.done || buf.is_empty() {
                return Ok(0);
            }
            let (read, consumed, remaining, status);
            {
                let input = self.input.fill_buf()?;
                let before_in = self.stream.total_in();
                let before_out = self.stream.total_out();
                status = self.stream.decompress(input, buf);
                consumed = usize::try_from(self.stream.total_in() - before_in)
                    .map_err(io::Error::other)?;
                read = usize::try_from(self.stream.total_out() - before_out)
                    .map_err(io::Error::other)?;
                remaining = input.len().checked_sub(consumed).ok_or_else(|| {
                    io::Error::other("bzip2 consumed more input than it was given")
                })?;
            }
            self.input.consume(consumed);
            let status =
                status.map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            if status == bzip2::Status::StreamEnd {
                self.done = true;
            } else if consumed == 0 && remaining == 0 && read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "bzip2 stream ends before its end marker",
                ));
            }
            if read > 0 || self.done {
                return Ok(read);
            }
        }
    }
}

/// Admission's check that `data` decodes, under `algorithm` and the decoder
/// bounds every read applies, to content of `expected_size` bytes hashing
/// to `identity`.
pub fn verify_compressed(
    data: &[u8],
    algorithm: &str,
    identity: &Kappa,
    expected_size: u64,
) -> Result<(), StoreError> {
    let mut decoded = Codec::of(algorithm)?.decoder(data)?;
    crate::blob_admission::verify_decoded(identity, expected_size, &mut decoded)
}

/// The decompression of `data` under `algorithm`, which the committed
/// record declares to be exactly `expected` bytes, on `work`. The input as
/// read, the decoder's working memory, and the output (allocated and
/// decoded) are charged before the decoder is built; the output is
/// reserved exactly and the decoder read at most one byte past it, so
/// output longer or shorter than declared is refused rather than
/// allocated.
pub fn decompress(
    data: &[u8],
    algorithm: &str,
    expected: u64,
    work: &mut dyn Meter,
) -> Result<Vec<u8>, StoreError> {
    let codec = Codec::of(algorithm)?;
    let length = usize::try_from(expected).map_err(|_| {
        StoreError::CapacityExceeded(format!(
            "a decompressed size of {expected} bytes exceeds the address space"
        ))
    })?;
    work.charge_all(&[
        (Dimension::BytesRead, data.len() as u64),
        (Dimension::BytesAllocated, codec.working_bytes()),
        (Dimension::BytesAllocated, expected),
        (Dimension::BytesDecoded, expected),
    ])?;
    let decoder = codec.decoder(data)?;
    let mut out = Vec::new();
    out.try_reserve_exact(length).map_err(|_| {
        StoreError::CapacityExceeded(format!(
            "a decompressed blob of {expected} bytes could not be allocated"
        ))
    })?;
    let mut bounded = decoder.take(expected.saturating_add(1));
    let mut chunk = [0u8; DECODE_CHUNK];
    loop {
        let read = match bounded.read(&mut chunk) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(StoreError::Io(io::Error::new(
                    error.kind(),
                    format!("{algorithm}: {error}"),
                )));
            }
        };
        if read == 0 {
            break;
        }
        if out.len() + read > length {
            return Err(StoreError::Rejected(format!(
                "{algorithm} content decompresses past its declared {expected} bytes"
            )));
        }
        out.extend_from_slice(&chunk[..read]);
    }
    if out.len() != length {
        return Err(StoreError::Rejected(format!(
            "{algorithm} content decompresses to {} of its declared {expected} bytes",
            out.len()
        )));
    }
    Ok(out)
}

#[cfg(test)]
#[path = "compression_tests.rs"]
mod tests;
