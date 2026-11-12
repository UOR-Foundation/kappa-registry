//! The shared decoders: their memory bound, exact sizes, and charges made
//! before any decoding.

use std::io::{Read, Write};

use kappa_types::Kappa;
use kappa_types::error::StoreError;
use kappa_types::work::{Dimension, Work, WorkLimit, WorkMeter};

use super::{Codec, DECODER_WORKING_BYTES, decompress, verify_compressed};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn content() -> Vec<u8> {
    (0..100_000u32).map(|i| (i % 251) as u8).collect()
}

fn zstd_encoded(bytes: &[u8], window_log: u32) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = zstd::stream::write::Encoder::new(Vec::new(), 3)?;
    encoder.window_log(window_log)?;
    encoder.write_all(bytes)?;
    encoder.finish()
}

fn xz_encoded(bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 6);
    encoder.write_all(bytes)?;
    encoder.finish()
}

fn bzip2_encoded(bytes: &[u8]) -> Result<Vec<u8>, std::io::Error> {
    let mut encoder = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::default());
    encoder.write_all(bytes)?;
    encoder.finish()
}

/// A frame declaring a window past the bound is refused by the shared
/// decoder, while zstd's default decoder (window limit `2^27`) decodes the
/// same frame: the bound, not the frame, refuses it.
#[test]
fn a_zstd_window_past_the_bound_is_refused() -> TestResult {
    let bytes = content();
    let encoded = zstd_encoded(&bytes, 27)?;
    let mut unbounded = Vec::new();
    zstd::Decoder::new(encoded.as_slice())?.read_to_end(&mut unbounded)?;
    assert_eq!(unbounded, bytes, "the frame itself is valid");
    let mut bounded = Vec::new();
    let refused = Codec::Zstd
        .decoder(encoded.as_slice())?
        .read_to_end(&mut bounded);
    assert!(
        refused.is_err(),
        "a 2^27 window decoded under a 2^26 bound into {} bytes",
        bounded.len()
    );
    assert!(matches!(
        verify_compressed(&encoded, "zstd", &Kappa::sha256(&bytes), bytes.len() as u64),
        Err(StoreError::Io(_))
    ));
    let within = zstd_encoded(&bytes, 26)?;
    verify_compressed(&within, "zstd", &Kappa::sha256(&bytes), bytes.len() as u64)?;
    Ok(())
}

/// Every codec decodes its stream to exactly the declared bytes, and the
/// work charged is exactly the input, the decoder memory and the output.
#[test]
fn every_codec_decompresses_exactly_and_charges_its_bound() -> TestResult {
    let bytes = content();
    let streams = [
        ("none", bytes.clone()),
        ("zstd", zstd_encoded(&bytes, 20)?),
        ("xz", xz_encoded(&bytes)?),
        ("bzip2", bzip2_encoded(&bytes)?),
    ];
    for (algorithm, encoded) in streams {
        let mut meter = WorkMeter::unbounded();
        let decoded = decompress(&encoded, algorithm, bytes.len() as u64, &mut meter)?;
        assert_eq!(decoded, bytes, "{algorithm}");
        let working = Codec::of(algorithm)?.working_bytes();
        assert_eq!(
            meter.used().get(Dimension::BytesAllocated),
            working + bytes.len() as u64,
            "{algorithm}"
        );
        assert_eq!(
            meter.used().get(Dimension::BytesRead),
            encoded.len() as u64,
            "{algorithm}"
        );
        assert_eq!(
            meter.used().get(Dimension::BytesDecoded),
            bytes.len() as u64,
            "{algorithm}"
        );
        verify_compressed(
            &encoded,
            algorithm,
            &Kappa::sha256(&bytes),
            bytes.len() as u64,
        )?;
    }
    assert_eq!(Codec::Stored.working_bytes(), 0);
    assert_eq!(Codec::Bzip2.working_bytes(), DECODER_WORKING_BYTES);
    Ok(())
}

/// Output longer or shorter than the record declares is refused.
#[test]
fn a_declared_size_other_than_the_decoded_size_is_refused() -> TestResult {
    let bytes = content();
    let encoded = zstd_encoded(&bytes, 20)?;
    let declared = bytes.len() as u64;
    for wrong in [declared - 1, declared + 1] {
        let outcome = decompress(&encoded, "zstd", wrong, &mut WorkMeter::unbounded());
        assert!(
            matches!(outcome, Err(StoreError::Rejected(_))),
            "declared {wrong} of {declared}: {outcome:?}"
        );
    }
    Ok(())
}

/// A meter one byte short of the decoder's bound refuses before the
/// decoder is built and charges nothing.
#[test]
fn decompression_is_refused_before_it_decodes() -> TestResult {
    let bytes = content();
    let encoded = xz_encoded(&bytes)?;
    let bound = DECODER_WORKING_BYTES + bytes.len() as u64;
    let mut meter =
        WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, bound - 1));
    let refused = decompress(&encoded, "xz", bytes.len() as u64, &mut meter);
    assert!(
        matches!(refused, Err(StoreError::WorkRefused(_))),
        "{refused:?}"
    );
    assert_eq!(meter.used(), &Work::default(), "a refusal charges nothing");
    let mut exact = WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, bound));
    assert_eq!(
        decompress(&encoded, "xz", bytes.len() as u64, &mut exact)?,
        bytes
    );
    Ok(())
}

/// A bzip2 stream cut before its end marker is refused, never delivered
/// as complete content.
#[test]
fn a_truncated_bzip2_stream_is_refused() -> TestResult {
    let bytes = content();
    let encoded = bzip2_encoded(&bytes)?;
    let truncated = &encoded[..encoded.len() - 8];
    let mut decoded = Vec::new();
    let outcome = Codec::Bzip2.decoder(truncated)?.read_to_end(&mut decoded);
    assert!(outcome.is_err(), "decoded {} bytes", decoded.len());
    Ok(())
}

#[test]
fn identity_mismatch_and_unknown_algorithms_are_rejected() -> TestResult {
    let bytes = content();
    let encoded = zstd_encoded(&bytes, 20)?;
    assert!(matches!(
        verify_compressed(
            &encoded,
            "zstd",
            &Kappa::sha256(b"other"),
            bytes.len() as u64
        ),
        Err(StoreError::Rejected(_))
    ));
    assert!(matches!(Codec::of("lz4"), Err(StoreError::Rejected(_))));
    Ok(())
}
