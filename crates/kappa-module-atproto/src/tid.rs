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
//! The s32 alphabet was chosen specifically so that string comparison
//! preserves temporal ordering.
//!
//! Source: bluesky-social/atproto packages/common-web/src/tid.ts

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The s32 encoding alphabet. Chosen for lexicographic sort order
/// matching numeric order.
const S32_CHAR: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

/// TID string length (always 13 characters).
const TID_LEN: usize = 13;

/// A Timestamp ID generator.
///
/// Each generator has a fixed clock ID derived from the node anchor hash.
/// This prevents TID collisions when multiple kappa-registry instances
/// serve the same DID during migration or failover.
pub struct TidGenerator {
    clock_id: u8,
    last_timestamp: AtomicU64,
}

impl TidGenerator {
    /// Create a generator with a clock ID derived from a node anchor.
    ///
    /// The clock ID is the first 5 bits of SHA-256(anchor), giving
    /// a value 0-31. Different nodes with different anchors get
    /// different clock IDs with high probability.
    pub fn new(node_anchor: &str) -> Self {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(node_anchor.as_bytes());
        let clock_id = hash[0] & 0x1F; // bottom 5 bits -> 0..31
        Self {
            clock_id,
            last_timestamp: AtomicU64::new(0),
        }
    }

    /// Create a generator with an explicit clock ID (0-31).
    pub fn with_clock_id(clock_id: u8) -> Self {
        Self {
            clock_id: clock_id & 0x1F,
            last_timestamp: AtomicU64::new(0),
        }
    }

    /// Generate the next TID.
    ///
    /// Monotonically increasing: if the system clock hasn't advanced
    /// since the last call, the timestamp is incremented by 1 microsecond.
    /// This ensures TIDs from the same generator never collide.
    pub fn next(&self) -> String {
        let now_us = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;

        // CAS loop to ensure monotonicity
        let ts = loop {
            let prev = self.last_timestamp.load(Ordering::Acquire);
            let candidate = if now_us > prev { now_us } else { prev + 1 };
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

        tid_from_parts(ts, self.clock_id)
    }

    /// The clock ID of this generator.
    pub fn clock_id(&self) -> u8 {
        self.clock_id
    }
}

/// Construct a TID string from a microsecond timestamp and clock ID.
fn tid_from_parts(timestamp: u64, clock_id: u8) -> String {
    let ts_str = s32_encode(timestamp);
    let ck_str = s32_encode(clock_id as u64);

    // Pad timestamp to 11 chars, clock ID to 2 chars
    let mut out = String::with_capacity(TID_LEN);
    for _ in 0..(11usize.saturating_sub(ts_str.len())) {
        out.push(S32_CHAR[0] as char); // '2' is s32 for 0
    }
    out.push_str(&ts_str);
    for _ in 0..(2usize.saturating_sub(ck_str.len())) {
        out.push(S32_CHAR[0] as char);
    }
    out.push_str(&ck_str);
    out
}

/// Encode a number in s32 (sort-ordered base32).
fn s32_encode(mut n: u64) -> String {
    if n == 0 {
        return String::new();
    }
    let mut s = Vec::new();
    while n > 0 {
        let c = (n % 32) as usize;
        n /= 32;
        s.push(S32_CHAR[c]);
    }
    s.reverse();
    String::from_utf8(s).unwrap()
}

/// Decode an s32-encoded string to a number.
fn s32_decode(s: &str) -> u64 {
    let mut n: u64 = 0;
    for b in s.bytes() {
        let val = match b {
            b'2'..=b'7' => (b - b'2') as u64,
            b'a'..=b'z' => (b - b'a' + 6) as u64,
            _ => 0,
        };
        n = n * 32 + val;
    }
    n
}

/// Parse a TID string into its (timestamp, clock_id) components.
pub fn parse_tid(s: &str) -> Result<(u64, u8), TidError> {
    let clean = s.replace('-', "");
    if clean.len() != TID_LEN {
        return Err(TidError::InvalidLength(clean.len()));
    }
    let timestamp = s32_decode(&clean[..11]);
    let clock_id = s32_decode(&clean[11..13]) as u8;
    Ok((timestamp, clock_id))
}

/// Validate that a string is a well-formed TID.
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
pub enum TidError {
    #[error("TID must be {TID_LEN} characters, got {0}")]
    InvalidLength(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tid_is_13_chars() {
        let gen = TidGenerator::with_clock_id(0);
        let tid = gen.next();
        assert_eq!(tid.len(), 13);
    }

    #[test]
    fn tid_monotonic() {
        let gen = TidGenerator::with_clock_id(5);
        let a = gen.next();
        let b = gen.next();
        let c = gen.next();
        assert!(b > a, "b={} should be > a={}", b, a);
        assert!(c > b, "c={} should be > b={}", c, b);
    }

    #[test]
    fn tid_parse_roundtrip() {
        let gen = TidGenerator::with_clock_id(17);
        let tid = gen.next();
        let (ts, ck) = parse_tid(&tid).unwrap();
        assert_eq!(ck, 17);
        assert!(ts > 0);
    }

    #[test]
    fn tid_different_clock_ids() {
        let gen_a = TidGenerator::new("anchor-a");
        let gen_b = TidGenerator::new("anchor-b");
        // Different anchors should (almost certainly) produce different clock IDs
        // but we can't guarantee it with only 5 bits. Just verify they produce valid TIDs.
        let a = gen_a.next();
        let b = gen_b.next();
        assert!(is_valid_tid(&a));
        assert!(is_valid_tid(&b));
    }

    #[test]
    fn tid_valid_chars() {
        let gen = TidGenerator::with_clock_id(31);
        let tid = gen.next();
        assert!(is_valid_tid(&tid));
        assert!(tid.bytes().all(|b| matches!(b, b'2'..=b'7' | b'a'..=b'z')));
    }

    #[test]
    fn s32_encode_decode_roundtrip() {
        for n in [0u64, 1, 31, 32, 1000, 1_000_000, u64::MAX / 2] {
            if n == 0 {
                continue; // s32_encode(0) returns empty string by design
            }
            let encoded = s32_encode(n);
            let decoded = s32_decode(&encoded);
            assert_eq!(decoded, n, "roundtrip failed for {}", n);
        }
    }

    #[test]
    fn s32_sort_order() {
        // Smaller numbers should produce lexicographically smaller strings
        // when padded to the same length
        let a = format!("{:>11}", s32_encode(100)).replace(' ', "2");
        let b = format!("{:>11}", s32_encode(200)).replace(' ', "2");
        assert!(a < b, "a={} should be < b={}", a, b);
    }

    #[test]
    fn invalid_tid_rejected() {
        assert!(!is_valid_tid("short"));
        assert!(!is_valid_tid("0000000000000")); // '0' not in s32 alphabet
        assert!(!is_valid_tid("AAAAAAAAAAAAA")); // uppercase not in s32
    }
}
