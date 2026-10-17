//! TID (Timestamp ID) generation for atproto.
//!
//! A TID is a 13-character string encoding a microsecond timestamp
//! and a clock ID using the s32 (sort-ordered base32) alphabet:
//!   `234567abcdefghijklmnopqrstuvwxyz`
//!
//! Layout: [timestamp:11chars][clockid:2chars]
//!   - timestamp: microseconds since Unix epoch (53 bits)
//!   - clockid: 0-31 (5 bits), identifies the generator instance
//!
//! TIDs are lexicographically sortable: newer TIDs sort after older ones.
//!
//! Source: bluesky-social/atproto packages/common-web/src/tid.ts

use std::sync::atomic::{AtomicU64, Ordering};

use sha2::Digest;

use kappa_store::clock::ClockMs;

/// The s32 encoding alphabet. Lexicographic sort order matches numeric order.
const S32_CHAR: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

/// TID string length (always 13 characters).
const TID_LEN: usize = 13;

/// A Timestamp ID generator.
///
/// Each generator has a fixed clock ID derived from the node anchor hash.
/// Serializes local TID issuance. A five-bit clock ID does not guarantee
/// collision resistance across independent instances serving the same DID.
pub struct TidGenerator {
    clock_id: u8,
    last_timestamp: AtomicU64,
}

impl TidGenerator {
    /// Creates a generator with a clock ID derived from a node anchor.
    /// The clock ID is the bottom 5 bits of SHA-256(anchor).
    pub fn new(node_anchor: &str) -> Self {
        let hash = sha2::Sha256::digest(node_anchor.as_bytes());
        let clock_id = hash[0] & 0x1F;
        Self {
            clock_id,
            last_timestamp: AtomicU64::new(0),
        }
    }

    /// Creates a generator with an explicit clock ID (0-31).
    pub fn with_clock_id(clock_id: u8) -> Self {
        Self {
            clock_id: clock_id & 0x1F,
            last_timestamp: AtomicU64::new(0),
        }
    }

    /// Generates the next TID from a Clock-sourced timestamp.
    ///
    /// Monotonically increasing: if the clock hasn't advanced since
    /// the last call, the timestamp increments by 1 microsecond.
    pub fn next(&self, now: ClockMs) -> Result<String, TidError> {
        let now_us = now
            .physical_ms()
            .checked_mul(1000)
            .ok_or(TidError::Exhausted)?;

        let ts = loop {
            let prev = self.last_timestamp.load(Ordering::Acquire);
            let candidate = if now_us > prev {
                now_us
            } else {
                prev.checked_add(1).ok_or(TidError::Exhausted)?
            };
            if candidate > (1u64 << 53) - 1 {
                return Err(TidError::Exhausted);
            }
            match self.last_timestamp.compare_exchange_weak(
                prev,
                candidate,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => break candidate,
                Err(_) => continue,
            }
        };

        Ok(tid_from_parts(ts, self.clock_id))
    }

    /// The clock ID of this generator.
    pub fn clock_id(&self) -> u8 {
        self.clock_id
    }
}

/// Constructs a TID string from a microsecond timestamp and clock ID.
fn tid_from_parts(timestamp: u64, clock_id: u8) -> String {
    let ts_str = s32_encode(timestamp);
    let ck_str = s32_encode(clock_id as u64);

    let mut out = String::with_capacity(TID_LEN);
    for _ in 0..(11usize.saturating_sub(ts_str.len())) {
        out.push(S32_CHAR[0] as char);
    }
    out.push_str(&ts_str);
    for _ in 0..(2usize.saturating_sub(ck_str.len())) {
        out.push(S32_CHAR[0] as char);
    }
    out.push_str(&ck_str);
    out
}

/// Encodes a number in s32 (sort-ordered base32).
/// Returns "2" for zero (the s32 digit for 0), not an empty string.
fn s32_encode(n: u64) -> String {
    if n == 0 {
        return String::from("2");
    }
    let mut s = Vec::new();
    let mut rem = n;
    while rem > 0 {
        let c = (rem % 32) as usize;
        rem /= 32;
        s.push(S32_CHAR[c]);
    }
    s.reverse();
    // SAFETY: all bytes in s come from S32_CHAR which contains only ASCII
    // lowercase letters and digits '2'-'7'. Valid UTF-8 by construction.
    String::from_utf8(s).expect("s32 alphabet is ASCII")
}

/// Decodes an s32-encoded string to a number.
/// Returns Err on invalid characters instead of silently decoding as 0.
fn s32_decode(s: &str) -> Result<u64, TidError> {
    let mut n: u64 = 0;
    for b in s.bytes() {
        let val = match b {
            b'2'..=b'7' => (b - b'2') as u64,
            b'a'..=b'z' => (b - b'a' + 6) as u64,
            _ => return Err(TidError::InvalidCharacter(b as char)),
        };
        n = n * 32 + val;
    }
    Ok(n)
}

/// Parses a TID string into its (timestamp, clock_id) components.
/// Validates character set before decoding.
pub fn parse_tid(s: &str) -> Result<(u64, u8), TidError> {
    let clean = s.replace('-', "");
    if clean.len() != TID_LEN {
        return Err(TidError::InvalidLength(clean.len()));
    }
    if !clean
        .bytes()
        .all(|b| matches!(b, b'2'..=b'7' | b'a'..=b'z'))
    {
        return Err(TidError::InvalidCharacter(
            clean
                .chars()
                .find(|c| !matches!(*c as u8, b'2'..=b'7' | b'a'..=b'z'))
                .unwrap_or('?'),
        ));
    }
    let timestamp = s32_decode(&clean[..11])?;
    let clock_id = s32_decode(&clean[11..13])? as u8;
    Ok((timestamp, clock_id))
}

/// Validates that a string is a well-formed TID.
pub fn is_valid_tid(s: &str) -> bool {
    let clean = s.replace('-', "");
    if clean.len() != TID_LEN {
        return false;
    }
    clean
        .bytes()
        .all(|b| matches!(b, b'2'..=b'7' | b'a'..=b'z'))
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TidError {
    #[error("TID timestamp range exhausted")]
    Exhausted,
    #[error("TID must be {TID_LEN} characters, got {0}")]
    InvalidLength(usize),
    #[error("invalid s32 character: '{0}'")]
    InvalidCharacter(char),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_now() -> ClockMs {
        ClockMs::from_raw((1_700_000_000_000u64 << 16) as i64)
    }

    #[test]
    fn tid_is_13_chars() {
        let generator = TidGenerator::with_clock_id(0);
        let tid = generator.next(test_now()).expect("TID");
        assert_eq!(tid.len(), 13);
    }

    #[test]
    fn tid_monotonic() {
        let generator = TidGenerator::with_clock_id(5);
        let now = test_now();
        let a = generator.next(now).expect("TID");
        let b = generator.next(now).expect("TID");
        let c = generator.next(now).expect("TID");
        assert!(b > a, "b={} should be > a={}", b, a);
        assert!(c > b, "c={} should be > b={}", c, b);
    }

    #[test]
    fn tid_parse_roundtrip() {
        let generator = TidGenerator::with_clock_id(17);
        let tid = generator.next(test_now()).expect("TID");
        let (ts, ck) = parse_tid(&tid).unwrap();
        assert_eq!(ck, 17);
        assert!(ts > 0);
    }

    #[test]
    fn tid_different_clock_ids() {
        let gen_a = TidGenerator::new("anchor-a");
        let gen_b = TidGenerator::new("anchor-b");
        let now = test_now();
        let a = gen_a.next(now).expect("TID");
        let b = gen_b.next(now).expect("TID");
        assert!(is_valid_tid(&a));
        assert!(is_valid_tid(&b));
    }

    #[test]
    fn tid_valid_chars() {
        let generator = TidGenerator::with_clock_id(31);
        let tid = generator.next(test_now()).expect("TID");
        assert!(is_valid_tid(&tid));
        assert!(tid.bytes().all(|b| matches!(b, b'2'..=b'7' | b'a'..=b'z')));
    }

    #[test]
    fn s32_encode_decode_roundtrip() {
        for n in [0u64, 1, 31, 32, 1000, 1_000_000, u64::MAX / 2] {
            let encoded = s32_encode(n);
            let decoded = s32_decode(&encoded).unwrap();
            assert_eq!(decoded, n, "roundtrip failed for {}", n);
        }
    }

    #[test]
    fn s32_zero_encodes_to_digit() {
        let encoded = s32_encode(0);
        assert_eq!(encoded, "2");
        assert_eq!(s32_decode("2").unwrap(), 0);
    }

    #[test]
    fn s32_sort_order() {
        let a = format!("{:>11}", s32_encode(100)).replace(' ', "2");
        let b = format!("{:>11}", s32_encode(200)).replace(' ', "2");
        assert!(a < b, "a={} should be < b={}", a, b);
    }

    #[test]
    fn invalid_tid_rejected() {
        assert!(!is_valid_tid("short"));
        assert!(!is_valid_tid("0000000000000"));
        assert!(!is_valid_tid("AAAAAAAAAAAAA"));
    }

    #[test]
    fn parse_tid_rejects_invalid_chars() {
        assert!(parse_tid("0000000000022").is_err());
        assert!(parse_tid("AAAAAAAAAAAAA").is_err());
    }

    #[test]
    fn s32_decode_rejects_invalid() {
        assert!(s32_decode("0").is_err());
        assert!(s32_decode("A").is_err());
        assert!(s32_decode("!").is_err());
    }
}
