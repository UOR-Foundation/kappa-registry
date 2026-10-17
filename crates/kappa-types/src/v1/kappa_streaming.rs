//! Incremental hashing for chunked blob storage and streaming kappa
//! computation.
//!
//! `IncrementalHasher` provides a stateful update/finalize interface
//! for interleaving hashing with chunk storage inside a redb transaction.
//!
//! The free functions `streaming_compute_kappa` and `streaming_compute_multi`
//! consume a reader in one pass and return a `StreamingVerificationProof`.
//! `streaming_compute_into` is the bounded form both delegate to: it forwards
//! every chunk to a sink and rejects a stream longer than its byte limit after
//! reading at most one byte past it.

use crate::axis::Axis;
use crate::kappa::{Kappa, KappaParseError};
use crate::verified::StreamingVerificationProof;

// -- IncrementalHasher --------------------------------------------------------

/// Stateful incremental hasher that produces a `Kappa` on finalize.
///
/// Used by `PersistentStore`'s chunked blob write to interleave hashing
/// with chunk encryption and redb insertion. The caller calls `update()`
/// with each chunk, then `finalize()` to get the computed `Kappa`.
///
/// An object of at most [`INLINE`] bytes never builds hasher state: its
/// bytes are held inline and hashed in one call at finalize, as
/// `Kappa::compute` hashes them. Building state costs a heap allocation for
/// the BLAKE3 and SHA-1 states and a digest-context setup for SHA-256, which
/// for a small object exceeds hashing it. A longer object switches to
/// streaming state at the first update past the limit, fed the held prefix
/// first, so every input hashes to the same digest either way.
///
/// Memory: [`INLINE`] bytes, plus one hasher state once streaming.
pub struct IncrementalHasher {
    state: State,
    axis: Axis,
}

/// Bytes an object may have and still be hashed in one call at finalize.
pub const INLINE: usize = 256;

enum State {
    Inline { held: [u8; INLINE], len: usize },
    Streaming(HasherInner),
}

enum HasherInner {
    Sha256(crate::sha256::Hasher),
    Sha512(crate::sha512::Hasher),
    Blake3(Box<blake3::Hasher>),
    Sha1(Box<sha1_checked::Sha1>),
    Sha3_256(crate::sha3_256::Hasher),
    Keccak256(sha3::Keccak256),
}

impl IncrementalHasher {
    /// Create a new hasher for the given axis.
    pub const fn new(axis: Axis) -> Self {
        Self {
            state: State::Inline {
                held: [0; INLINE],
                len: 0,
            },
            axis,
        }
    }

    /// Feed bytes into the hasher.
    pub fn update(&mut self, data: &[u8]) {
        match &mut self.state {
            State::Inline { held, len } => {
                if let Some(rest) = held.get_mut(*len..*len + data.len()) {
                    rest.copy_from_slice(data);
                    *len += data.len();
                    return;
                }
                let mut inner = HasherInner::new(self.axis);
                inner.update(&held[..*len]);
                inner.update(data);
                self.state = State::Streaming(inner);
            }
            State::Streaming(inner) => inner.update(data),
        }
    }

    /// Consume the hasher and return the computed Kappa.
    ///
    /// For SHA-1: returns Err(CollisionDetected) if a collision is found.
    /// All other axes are infallible.
    pub fn finalize(self) -> Result<Kappa, KappaParseError> {
        match self.state {
            State::Inline { held, len } => Kappa::compute(self.axis, &held[..len]),
            State::Streaming(inner) => inner.finalize(self.axis),
        }
    }

    /// The axis this hasher was created for.
    pub const fn axis(&self) -> Axis {
        self.axis
    }
}

impl HasherInner {
    fn new(axis: Axis) -> Self {
        match axis {
            Axis::Sha256 => Self::Sha256(crate::sha256::Hasher::new()),
            Axis::Sha512 => Self::Sha512(crate::sha512::Hasher::new()),
            Axis::Blake3 => Self::Blake3(Box::new(blake3::Hasher::new())),
            Axis::Sha1 => Self::Sha1(Box::new(sha1_checked::Sha1::new())),
            Axis::Sha3_256 => Self::Sha3_256(crate::sha3_256::Hasher::new()),
            Axis::Keccak256 => {
                use sha3::Digest as _;
                Self::Keccak256(sha3::Keccak256::new())
            }
        }
    }

    fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
            Self::Blake3(h) => {
                h.update(data);
            }
            Self::Sha1(h) => sha1_checked::Digest::update(h.as_mut(), data),
            Self::Sha3_256(h) => h.update(data),
            Self::Keccak256(h) => sha3::Digest::update(h, data),
        }
    }

    /// For SHA-1: `Err(CollisionDetected)` if a collision is found.
    fn finalize(self, axis: Axis) -> Result<Kappa, KappaParseError> {
        match self {
            Self::Sha256(h) => Ok(Kappa::from_raw(axis, &h.finalize())),
            Self::Sha512(h) => Ok(Kappa::from_raw(axis, &h.finalize())),
            Self::Blake3(h) => Ok(Kappa::from_raw(axis, h.finalize().as_bytes())),
            Self::Sha1(h) => {
                let result = h.try_finalize();
                if result.has_collision() {
                    return Err(KappaParseError::CollisionDetected);
                }
                Ok(Kappa::from_raw(axis, result.hash()))
            }
            Self::Sha3_256(h) => Ok(Kappa::from_raw(axis, &h.finalize())),
            Self::Keccak256(h) => Ok(Kappa::from_raw(axis, &sha3::Digest::finalize(h))),
        }
    }
}

// -- Free functions: streaming from a reader ----------------------------------

/// Read all bytes from a reader, hashing incrementally. Returns a
/// `StreamingVerificationProof` carrying the computed kappa.
///
/// Memory: one 16 KiB buffer + one hasher state.
pub fn streaming_compute_kappa(
    axis: Axis,
    reader: &mut dyn std::io::Read,
) -> Result<StreamingVerificationProof, KappaParseError> {
    let mut buf = [0u8; 16384];
    streaming_compute_into(&[axis], reader, &mut buf, u64::MAX, |_| Ok(())).map(|(proof, _)| proof)
}

/// Multi-axis streaming hash. One read pass, N hashers in parallel.
///
/// The first axis is the primary. Additional axes produce additional
/// verified kappas carried inside the proof.
pub fn streaming_compute_multi(
    axes: &[Axis],
    reader: &mut dyn std::io::Read,
) -> Result<StreamingVerificationProof, KappaParseError> {
    let mut buf = [0u8; 16384];
    streaming_compute_into(axes, reader, &mut buf, u64::MAX, |_| Ok(())).map(|(proof, _)| proof)
}

/// Shared bounded stream execution.
///
/// The sink receives complete buffer-sized
/// chunks followed by at most one short chunk. It must keep writes private
/// until the returned verification evidence has been admitted for publication.
/// Sink failures preserve their typed error; no proof is returned on failure.
///
/// A stream longer than `maximum` is rejected after reading exactly one
/// byte past it. Before the rejection the sink has received exactly the
/// first `maximum` bytes; the excess byte is never delivered.
pub fn streaming_compute_into<E>(
    axes: &[Axis],
    reader: &mut dyn std::io::Read,
    buffer: &mut [u8],
    maximum: u64,
    mut consume: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<(StreamingVerificationProof, u64), E>
where
    E: From<KappaParseError> + From<std::io::Error>,
{
    if axes.is_empty() {
        return Err(KappaParseError::UnknownAxis("empty axes list".into()).into());
    }
    if buffer.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "empty streaming buffer",
        )
        .into());
    }

    let mut hashers: Vec<IncrementalHasher> =
        axes.iter().map(|&a| IncrementalHasher::new(a)).collect();

    let mut total = 0u64;
    loop {
        let mut filled = 0;
        while filled < buffer.len() {
            let remaining = maximum.saturating_sub(total).saturating_sub(filled as u64);
            let bound = buffer
                .len()
                .saturating_sub(filled)
                .min(usize::try_from(remaining.saturating_add(1)).unwrap_or(usize::MAX));
            let count = match reader.read(&mut buffer[filled..filled + bound]) {
                Ok(count) => count,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            };
            if count == 0 {
                break;
            }
            filled += count;
            let allowed = maximum.saturating_sub(total);
            if filled as u64 > allowed {
                // The excess byte is the only byte read past the limit. The
                // bytes before it are within the limit and complete the
                // consumer's view of exactly `maximum` bytes; the excess byte
                // never reaches it. `allowed < filled`, so it fits in usize.
                let within = usize::try_from(allowed).unwrap_or(filled);
                if within > 0 {
                    consume(&buffer[..within])?;
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "stream exceeds byte limit",
                )
                .into());
            }
        }
        if filled == 0 {
            break;
        }
        total = total.checked_add(filled as u64).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "stream byte count overflow",
            )
        })?;
        for h in &mut hashers {
            h.update(&buffer[..filled]);
        }
        consume(&buffer[..filled])?;
    }

    let mut results: Vec<(Axis, Kappa)> = Vec::with_capacity(hashers.len());
    for h in hashers {
        let a = h.axis();
        results.push((a, h.finalize()?));
    }

    let (_, primary) = results.remove(0);
    let proof = if results.is_empty() {
        StreamingVerificationProof::single(primary)
    } else {
        StreamingVerificationProof::multi(primary, results)
    };
    Ok((proof, total))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn bounded_sink_retries_interruptions_and_preserves_multi_axis_evidence()
    -> Result<(), KappaParseError> {
        struct Interrupted<'a> {
            bytes: &'a [u8],
            interrupt: bool,
        }
        impl std::io::Read for Interrupted<'_> {
            fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
                self.interrupt = !self.interrupt;
                if self.interrupt {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                let count = output.len().min(self.bytes.len()).min(3);
                output[..count].copy_from_slice(&self.bytes[..count]);
                self.bytes = &self.bytes[count..];
                Ok(count)
            }
        }
        let bytes = b"interrupted multi-axis stream";
        let mut reader = Interrupted {
            bytes,
            interrupt: false,
        };
        let mut buffer = [0; 7];
        let mut chunks = Vec::new();
        let (proof, size) = streaming_compute_into::<KappaParseError>(
            &[Axis::Sha256, Axis::Sha1, Axis::Blake3],
            &mut reader,
            &mut buffer,
            bytes.len() as u64,
            |chunk| {
                chunks.push(chunk.to_vec());
                Ok(())
            },
        )?;
        assert_eq!(size, bytes.len() as u64);
        assert_eq!(proof.kappa(), &Kappa::sha256(bytes));
        assert_eq!(chunks.concat(), bytes);
        assert!(
            chunks[..chunks.len() - 1]
                .iter()
                .all(|chunk| chunk.len() == 7)
        );
        assert_eq!(proof.additional().len(), 2);
        Ok(())
    }

    #[test]
    fn byte_limit_reads_only_one_excess_byte_and_never_sends_it_to_sink() {
        let mut reader = Cursor::new(b"over-limit-stream");
        let mut buffer = [0; 64];
        let mut received = Vec::new();
        let result = streaming_compute_into::<KappaParseError>(
            &[Axis::Sha256],
            &mut reader,
            &mut buffer,
            4,
            |chunk| {
                received.push(chunk.to_vec());
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(reader.position(), 5);
        // Exactly the limit, in one chunk; the excess byte '-' is withheld.
        assert_eq!(received, [b"over".to_vec()]);
    }

    #[test]
    fn byte_limit_completes_a_partial_final_chunk() {
        let mut reader = Cursor::new(b"0123456789abcdef");
        let mut buffer = [0; 4];
        let mut received = Vec::new();
        let result = streaming_compute_into::<KappaParseError>(
            &[Axis::Sha256],
            &mut reader,
            &mut buffer,
            10,
            |chunk| {
                received.push(chunk.to_vec());
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(reader.position(), 11);
        assert_eq!(received.concat(), b"0123456789");
        assert_eq!(received.iter().map(Vec::len).collect::<Vec<_>>(), [4, 4, 2]);
    }

    #[test]
    fn zero_limit_delivers_nothing() {
        let mut reader = Cursor::new(b"x");
        let mut buffer = [0; 4];
        let mut calls = 0;
        let result = streaming_compute_into::<KappaParseError>(
            &[Axis::Sha256],
            &mut reader,
            &mut buffer,
            0,
            |_| {
                calls += 1;
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!(reader.position(), 1);
        assert_eq!(calls, 0);
    }

    #[test]
    fn sink_failure_returns_no_completion_evidence() {
        let mut reader = Cursor::new(b"unpublished");
        let mut buffer = [0; 4];
        let result = streaming_compute_into::<KappaParseError>(
            &[Axis::Sha256],
            &mut reader,
            &mut buffer,
            100,
            |_| Err(std::io::Error::other("sink failed").into()),
        );
        assert!(result.is_err());
        assert_eq!(reader.position(), 4);
    }

    #[test]
    fn incremental_matches_oneshot_sha256() -> Result<(), KappaParseError> {
        let data = b"incremental hashing test data";
        let oneshot = Kappa::sha256(data);

        let mut hasher = IncrementalHasher::new(Axis::Sha256);
        hasher.update(&data[..10]);
        hasher.update(&data[10..]);
        let incremental = hasher.finalize()?;

        assert_eq!(oneshot, incremental);
        Ok(())
    }

    #[test]
    fn incremental_matches_oneshot_blake3() -> Result<(), KappaParseError> {
        let data = b"blake3 incremental test";
        let oneshot = Kappa::blake3(data);

        let mut hasher = IncrementalHasher::new(Axis::Blake3);
        hasher.update(data);
        let incremental = hasher.finalize()?;

        assert_eq!(oneshot, incremental);
        Ok(())
    }

    #[test]
    fn incremental_matches_oneshot_sha512() -> Result<(), KappaParseError> {
        let data = b"sha512 incremental test";
        let oneshot = Kappa::sha512(data);

        let mut hasher = IncrementalHasher::new(Axis::Sha512);
        hasher.update(data);
        let incremental = hasher.finalize()?;

        assert_eq!(oneshot, incremental);
        Ok(())
    }

    #[test]
    fn incremental_matches_oneshot_sha1() -> Result<(), KappaParseError> {
        let data = b"sha1 incremental test";
        let oneshot = Kappa::sha1(data)?;

        let mut hasher = IncrementalHasher::new(Axis::Sha1);
        hasher.update(data);
        let incremental = hasher.finalize()?;

        assert_eq!(oneshot, incremental);
        Ok(())
    }

    #[test]
    fn incremental_matches_oneshot_sha3_256() -> Result<(), KappaParseError> {
        let data = b"sha3-256 incremental test";
        let oneshot = Kappa::sha3_256(data);

        let mut hasher = IncrementalHasher::new(Axis::Sha3_256);
        hasher.update(data);
        let incremental = hasher.finalize()?;

        assert_eq!(oneshot, incremental);
        Ok(())
    }

    #[test]
    fn incremental_matches_oneshot_keccak256() -> Result<(), KappaParseError> {
        let data = b"keccak256 incremental test";
        let oneshot = Kappa::keccak256(data);

        let mut hasher = IncrementalHasher::new(Axis::Keccak256);
        hasher.update(data);
        let incremental = hasher.finalize()?;

        assert_eq!(oneshot, incremental);
        Ok(())
    }

    #[test]
    fn incremental_empty_content() -> Result<(), KappaParseError> {
        let oneshot = Kappa::sha256(b"");

        let mut hasher = IncrementalHasher::new(Axis::Sha256);
        hasher.update(&[]);
        let incremental = hasher.finalize()?;

        assert_eq!(oneshot, incremental);
        Ok(())
    }

    #[test]
    fn incremental_many_small_updates() -> Result<(), KappaParseError> {
        let data = b"many small updates produce the same hash as one big update";
        let oneshot = Kappa::sha256(data);

        let mut hasher = IncrementalHasher::new(Axis::Sha256);
        for byte in data {
            hasher.update(&[*byte]);
        }
        let incremental = hasher.finalize()?;

        assert_eq!(oneshot, incremental);
        Ok(())
    }

    #[test]
    fn streaming_compute_matches_oneshot() -> Result<(), KappaParseError> {
        let data = b"streaming compute test data";
        let oneshot = Kappa::sha256(data);

        let mut reader = Cursor::new(data.as_slice());
        let proof = streaming_compute_kappa(Axis::Sha256, &mut reader)?;
        let streaming = proof.kappa().clone();

        assert_eq!(oneshot, streaming);
        Ok(())
    }

    #[test]
    fn streaming_compute_empty_reader() -> Result<(), KappaParseError> {
        let oneshot = Kappa::sha256(b"");

        let mut reader = Cursor::new(&[] as &[u8]);
        let proof = streaming_compute_kappa(Axis::Sha256, &mut reader)?;

        assert_eq!(oneshot, *proof.kappa());
        Ok(())
    }

    #[test]
    fn streaming_compute_multi_primary_and_additional() -> Result<(), KappaParseError> {
        let data = b"multi axis test";

        let mut reader = Cursor::new(data.as_slice());
        let proof = streaming_compute_multi(&[Axis::Sha256, Axis::Blake3], &mut reader)?;

        assert_eq!(*proof.kappa(), Kappa::sha256(data));
        Ok(())
    }

    #[test]
    fn streaming_compute_multi_single_axis() -> Result<(), KappaParseError> {
        let data = b"single axis multi";

        let mut reader = Cursor::new(data.as_slice());
        let proof = streaming_compute_multi(&[Axis::Blake3], &mut reader)?;

        assert_eq!(*proof.kappa(), Kappa::blake3(data));
        Ok(())
    }

    #[test]
    fn streaming_compute_multi_empty_axes_fails() {
        let mut reader = Cursor::new(&[] as &[u8]);
        let result = streaming_compute_multi(&[], &mut reader);
        assert!(result.is_err());
    }

    /// Inline and streaming states hash to the one-shot digest on every
    /// axis, for objects below, at and above the inline limit, fed whole or
    /// split at every position around the limit.
    #[test]
    fn inline_and_streaming_states_match_one_shot_on_every_axis() -> Result<(), KappaParseError> {
        let data: Vec<u8> = (0..=u8::MAX).cycle().take(INLINE * 3).collect();
        for axis in [
            Axis::Sha256,
            Axis::Sha512,
            Axis::Blake3,
            Axis::Sha1,
            Axis::Sha3_256,
            Axis::Keccak256,
        ] {
            for length in [0, 1, INLINE - 1, INLINE, INLINE + 1, INLINE * 3] {
                let message = &data[..length];
                let expected = Kappa::compute(axis, message)?;
                let mut whole = IncrementalHasher::new(axis);
                whole.update(message);
                assert_eq!(whole.finalize()?, expected, "{axis} whole at {length}");
                for split in [0, 1, INLINE.min(length), length / 2, length] {
                    let (head, tail) = message.split_at(split.min(length));
                    let mut hasher = IncrementalHasher::new(axis);
                    hasher.update(head);
                    hasher.update(tail);
                    assert_eq!(
                        hasher.finalize()?,
                        expected,
                        "{axis} split {split} at {length}"
                    );
                }
            }
        }
        Ok(())
    }

    #[test]
    fn hasher_axis_returns_construction_axis() {
        let h = IncrementalHasher::new(Axis::Blake3);
        assert_eq!(h.axis(), Axis::Blake3);
    }
}
