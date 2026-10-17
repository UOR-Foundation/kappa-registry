//! Git pack delta framing over the shared delta codec.
//!
//! The delta instruction stream itself (base and result sizes, copy and
//! insert instructions, bounded decoding, bounded matching) is
//! `kappa_types::delta`, shared with bundles; this module adds only what
//! the pack format wraps around it.

pub use kappa_types::delta::{
    DeltaBudget, DeltaError, DeltaReservation, DeltaStats, apply_delta, compute_delta,
    compute_delta_with_stats,
};

/// Encode an OFS_DELTA negative offset header.
///
/// Variable-length encoding: big-endian, MSB continuation, with +1 bias
/// on continuation bytes matching Git's pack format.
pub fn encode_ofs_delta_header(mut distance: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10);
    buf.push((distance & 127) as u8);
    while {
        distance >>= 7;
        distance > 0
    } {
        distance -= 1;
        buf.push(128 | (distance & 127) as u8);
    }
    buf.reverse();
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_ofs_delta_header_small() {
        let encoded = encode_ofs_delta_header(10);
        assert_eq!(encoded, [10]);
    }

    #[test]
    fn encode_ofs_delta_header_needs_continuation() {
        let encoded = encode_ofs_delta_header(128);
        assert!(encoded.len() >= 2);
        assert!(encoded[0] & 0x80 != 0);
        assert!(encoded[encoded.len() - 1] & 0x80 == 0);
    }

    /// Decode the OFS_DELTA header the way a pack reader does.
    fn decode_ofs(bytes: &[u8]) -> u64 {
        let mut value = u64::from(bytes[0] & 127);
        for &byte in &bytes[1..] {
            value = ((value + 1) << 7) | u64::from(byte & 127);
        }
        value
    }

    #[test]
    fn ofs_delta_header_round_trips_across_continuation_boundaries() {
        for distance in [
            0u64,
            1,
            127,
            128,
            16_511,
            16_512,
            2_113_663,
            2_113_664,
            u32::MAX as u64,
        ] {
            let encoded = encode_ofs_delta_header(distance);
            assert_eq!(decode_ofs(&encoded), distance, "{distance}");
        }
    }
}
