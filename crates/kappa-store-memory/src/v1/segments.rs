//! Segment digests of a leaf's bytes.
//!
//! Every allocation and every compressed representation carries the BLAKE3
//! digest of each [`SEGMENT`]-byte segment of the bytes it serves, the last
//! segment shorter. The digests are computed from the same bytes, in the
//! same pass, that were proven to be their identity (preparation, or the
//! verified bytes a record is published from), and they live in the
//! process's memory beside the leaf, never in the content cache. A read
//! delivers a byte only after the whole segment holding it has been read
//! and checked, so a read at any offset, after any seek, delivers only
//! bytes that hashed to their identity, without hashing from offset 0.

use std::io;
use std::sync::Arc;

/// Bytes per segment.
pub const SEGMENT: u64 = 64 * 1024;

/// The segment digests of one leaf's bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Segments {
    digests: Arc<[[u8; 32]]>,
    length: u64,
}

impl std::fmt::Debug for Segments {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Segments")
            .field("segments", &self.digests.len())
            .field("length", &self.length)
            .finish()
    }
}

impl Segments {
    /// The digests of `bytes`, which the caller verified.
    pub fn of(bytes: &[u8]) -> Self {
        let mut hasher = SegmentHasher::default();
        hasher.update(bytes);
        hasher.finish()
    }

    /// Length of the bytes the digests cover.
    pub const fn length(&self) -> u64 {
        self.length
    }

    /// Offset and length of the segment holding byte `within`.
    pub fn bounds(&self, within: u64) -> (u64, u64) {
        let start = within - within % SEGMENT;
        (start, SEGMENT.min(self.length.saturating_sub(start)))
    }

    /// Check `bytes` as the segment starting at `start`.
    pub fn check(&self, start: u64, bytes: &[u8]) -> io::Result<()> {
        let index = usize::try_from(start / SEGMENT).map_err(|_| invalid(start))?;
        let expected = self.digests.get(index).ok_or_else(|| invalid(start))?;
        if !start.is_multiple_of(SEGMENT) || bytes.len() as u64 != self.bounds(start).1 {
            return Err(invalid(start));
        }
        if blake3::hash(bytes).as_bytes() != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("segment at {start} does not hold the bytes its identity was proven from"),
            ));
        }
        Ok(())
    }
}

fn invalid(start: u64) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("no segment of the admitted length starts at {start}"),
    )
}

/// Segment digests computed as bytes stream past.
pub struct SegmentHasher {
    digests: Vec<[u8; 32]>,
    current: blake3::Hasher,
    filled: u64,
    length: u64,
}

impl Default for SegmentHasher {
    fn default() -> Self {
        Self {
            digests: Vec::new(),
            current: blake3::Hasher::new(),
            filled: 0,
            length: 0,
        }
    }
}

impl SegmentHasher {
    pub fn update(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let room = usize::try_from(SEGMENT - self.filled).unwrap_or(usize::MAX);
            let (head, rest) = bytes.split_at(room.min(bytes.len()));
            self.current.update(head);
            self.filled += head.len() as u64;
            self.length += head.len() as u64;
            if self.filled == SEGMENT {
                let full = std::mem::replace(&mut self.current, blake3::Hasher::new());
                self.digests.push(*full.finalize().as_bytes());
                self.filled = 0;
            }
            bytes = rest;
        }
    }

    pub fn finish(mut self) -> Segments {
        if self.filled > 0 {
            self.digests.push(*self.current.finalize().as_bytes());
        }
        Segments {
            digests: Arc::from(self.digests),
            length: self.length,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{SEGMENT, SegmentHasher, Segments};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn streamed_and_whole_digests_agree_and_check_every_segment() -> TestResult {
        let length = usize::try_from(SEGMENT * 2 + 17)?;
        let bytes = (0..length)
            .map(|i| u8::try_from(i % 253))
            .collect::<Result<Vec<u8>, _>>()?;
        let mut streamed = SegmentHasher::default();
        for piece in bytes.chunks(1000) {
            streamed.update(piece);
        }
        let streamed = streamed.finish();
        assert_eq!(streamed, Segments::of(&bytes));
        assert_eq!(streamed.length(), bytes.len() as u64);
        assert_eq!(streamed.bounds(SEGMENT * 2 + 3), (SEGMENT * 2, 17));
        let segment = usize::try_from(SEGMENT)?;
        streamed.check(0, &bytes[..segment])?;
        streamed.check(SEGMENT, &bytes[segment..segment * 2])?;
        streamed.check(SEGMENT * 2, &bytes[segment * 2..])?;
        let mut altered = bytes[segment..segment * 2].to_vec();
        altered[9] ^= 1;
        let error = streamed
            .check(SEGMENT, &altered)
            .err()
            .ok_or("an altered segment checked")?;
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let error = streamed
            .check(SEGMENT * 2, &bytes[segment * 2..length - 1])
            .err()
            .ok_or("a short segment checked")?;
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        Ok(())
    }

    #[test]
    fn empty_bytes_have_no_segment() -> TestResult {
        let empty = Segments::of(&[]);
        assert_eq!(empty.length(), 0);
        let error = empty
            .check(0, &[])
            .err()
            .ok_or("empty bytes held a segment")?;
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        Ok(())
    }
}
