//! PERF-HSH-003: `streaming_compute_into` rejects a stream at limit + 1,
//! reads at most one byte past the limit, and its consumer sees exactly
//! the first `limit` bytes, never the excess byte.
//! PERF-HSH-004: complement involution and `from_key` domain separation.

use std::io::Cursor;

use kappa_types::axis::Axis;
use kappa_types::kappa::{Kappa, KappaParseError};
use kappa_types::kappa_streaming::streaming_compute_into;

use crate::common::TestResult;

const ALL_AXES: [Axis; 6] = [
    Axis::Sha256,
    Axis::Sha512,
    Axis::Blake3,
    Axis::Sha1,
    Axis::Sha3_256,
    Axis::Keccak256,
];

/// Content of `len` bytes, distinct at every position.
fn content(len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| u8::try_from(index % 251).unwrap_or(0))
        .collect()
}

struct Outcome {
    accepted: Option<(Kappa, u64)>,
    chunks: Vec<Vec<u8>>,
    position: u64,
}

fn stream(axes: &[Axis], data: &[u8], buffer_len: usize, limit: u64) -> Outcome {
    let mut reader = Cursor::new(data);
    let mut buffer = vec![0u8; buffer_len];
    let mut chunks = Vec::new();
    let result =
        streaming_compute_into::<KappaParseError>(axes, &mut reader, &mut buffer, limit, |chunk| {
            chunks.push(chunk.to_vec());
            Ok(())
        });
    Outcome {
        accepted: result
            .ok()
            .map(|(proof, total)| (proof.kappa().clone(), total)),
        chunks,
        position: reader.position(),
    }
}

#[test]
fn over_limit_streams_deliver_exactly_limit_bytes_then_reject() -> TestResult {
    let data = content(16);
    for buffer_len in [1, 3, 4, 5, 9, 10, 11, 64] {
        for limit in [0u64, 1, 4, 10, 15] {
            let outcome = stream(&[Axis::Sha256], &data, buffer_len, limit);
            let context = format!("buffer {buffer_len}, limit {limit}");
            assert!(
                outcome.accepted.is_none(),
                "{context}: over-limit stream accepted"
            );
            let limit_len = usize::try_from(limit)?;
            assert_eq!(
                outcome.chunks.concat(),
                &data[..limit_len],
                "{context}: consumer bytes"
            );
            // Every chunk but the last is a full buffer.
            if let Some((_, full)) = outcome.chunks.split_last() {
                assert!(
                    full.iter().all(|chunk| chunk.len() == buffer_len),
                    "{context}: chunking"
                );
            }
            assert!(
                outcome.chunks.iter().all(|chunk| !chunk.is_empty()),
                "{context}: empty chunk"
            );
            assert_eq!(
                outcome.position,
                limit + 1,
                "{context}: read past limit + 1"
            );
        }
    }
    Ok(())
}

#[test]
fn buffer_four_limit_ten_is_two_full_chunks_and_a_partial() {
    let data = content(16);
    let outcome = stream(&[Axis::Sha256], &data, 4, 10);
    let lengths: Vec<usize> = outcome.chunks.iter().map(Vec::len).collect();
    assert_eq!(lengths, [4, 4, 2]);
    assert_eq!(outcome.position, 11);
}

#[test]
fn streams_at_or_under_the_limit_hash_identically_on_every_axis() -> TestResult {
    for len in [0usize, 1, 9, 10] {
        let data = content(len);
        for buffer_len in [1, 4, 10, 64] {
            let outcome = stream(&ALL_AXES, &data, buffer_len, 10);
            let (kappa, total) = outcome
                .accepted
                .ok_or_else(|| format!("{len} bytes rejected under limit 10"))?;
            assert_eq!(total, u64::try_from(len)?);
            assert_eq!(kappa, Kappa::sha256(&data), "primary axis");
            assert_eq!(outcome.chunks.concat(), data);
        }
        for axis in ALL_AXES {
            let outcome = stream(&[axis], &data, 3, 10);
            let (kappa, _) = outcome.accepted.ok_or("rejected")?;
            assert_eq!(kappa, Kappa::compute(axis, &data)?, "{axis} at {len} bytes");
        }
    }
    Ok(())
}

#[test]
fn every_axis_rejects_at_limit_plus_one() {
    let data = content(11);
    for axis in ALL_AXES {
        let outcome = stream(&[axis], &data, 4, 10);
        assert!(
            outcome.accepted.is_none(),
            "{axis} accepted 11 bytes under limit 10"
        );
        assert_eq!(outcome.chunks.concat(), &data[..10], "{axis}");
        assert_eq!(outcome.position, 11, "{axis}");
    }
}

#[test]
fn sink_failure_stops_the_stream_with_no_evidence() {
    let data = content(64);
    let mut reader = Cursor::new(data.as_slice());
    let mut buffer = [0u8; 8];
    let mut delivered = 0;
    let result = streaming_compute_into::<KappaParseError>(
        &[Axis::Sha256],
        &mut reader,
        &mut buffer,
        64,
        |_| {
            delivered += 1;
            if delivered == 2 {
                Err(std::io::Error::other("sink full").into())
            } else {
                Ok(())
            }
        },
    );
    assert!(result.is_err());
    assert_eq!(delivered, 2);
    assert_eq!(reader.position(), 16);
}

#[test]
fn empty_axes_and_empty_buffers_are_refused() {
    let data = content(4);
    assert!(stream(&[], &data, 4, 10).accepted.is_none());
    assert!(stream(&[Axis::Sha256], &data, 0, 10).accepted.is_none());
}

// -- PERF-HSH-004: complement involution --

#[test]
fn complement_is_involution() {
    for seed in [&b"alpha"[..], b"beta", b"gamma", b"delta", b""] {
        let k = Kappa::sha256(seed);
        let comp = k.complement();
        assert_ne!(k, comp, "complement must differ from original");
        assert_eq!(
            k,
            comp.complement(),
            "double complement must restore original"
        );
        for (original, flipped) in k.digest_bytes().iter().zip(comp.digest_bytes()) {
            assert_eq!(*original, !flipped);
        }
    }
}

#[test]
fn complement_preserves_axis_on_every_axis() -> TestResult {
    for axis in ALL_AXES {
        let k = Kappa::compute(axis, b"axis-test")?;
        let comp = k.complement();
        assert_eq!(comp.axis(), axis);
        assert_eq!(comp.digest_bytes().len(), k.digest_bytes().len());
        assert_eq!(comp.complement(), k);
    }
    Ok(())
}

// -- PERF-HSH-004: from_key domain separation --

#[test]
fn from_key_separates_algorithms_keys_and_content() -> TestResult {
    let key = [42u8; 32];
    let ed = Kappa::from_key("ed25519", &key)?;
    assert_eq!(ed, Kappa::from_key("ed25519", &key)?, "deterministic");
    assert_ne!(ed, Kappa::from_key("p256", &key)?, "algorithm separation");
    assert_ne!(
        ed,
        Kappa::from_key("ed25519", &[43u8; 32])?,
        "key separation"
    );
    assert_ne!(ed, Kappa::sha256(&key), "content separation");
    Ok(())
}

#[test]
fn from_key_framing_prevents_boundary_shifts() -> TestResult {
    // Without length framing, ("ed2", "5519" + key) and ("ed25519", key)
    // would hash the same concatenation.
    let key = [7u8; 32];
    let mut shifted = b"5519".to_vec();
    shifted.extend_from_slice(&key);
    assert_ne!(
        Kappa::from_key("ed25519", &key)?,
        Kappa::from_key("ed2", &shifted)?
    );
    assert_ne!(Kappa::from_key("", &key)?, Kappa::from_key("ed25519", &[])?);
    Ok(())
}

#[test]
fn from_key_rejects_unframeable_fields() {
    let oversized = vec![0u8; usize::from(u16::MAX) + 1];
    assert!(matches!(
        Kappa::from_key("ed25519", &oversized),
        Err(KappaParseError::KeyFramingLength {
            field: "public_key",
            ..
        })
    ));
    let long_algorithm = "a".repeat(usize::from(u16::MAX) + 1);
    assert!(matches!(
        Kappa::from_key(&long_algorithm, &[1]),
        Err(KappaParseError::KeyFramingLength {
            field: "algorithm",
            ..
        })
    ));
}
