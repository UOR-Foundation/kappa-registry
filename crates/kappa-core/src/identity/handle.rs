//! Handle registry: human-readable names bound to anchors.
//!
//! A handle is a (handle_string, protocol) pair bound to an asserter anchor.
//! One handle per (handle, protocol) pair. Multiple handles per anchor
//! across protocols.

use dcbor::prelude::*;

/// Liveness state of a handle binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub enum HandleLiveness {
    /// Verified within TTL, both directions confirm.
    #[cbor(n = 0)]
    Active,
    /// Was verified, TTL elapsed, needs re-verification.
    #[cbor(n = 1)]
    Expired,
    /// Claimed but never verified, or verification failed.
    #[cbor(n = 2)]
    Unverified,
}

impl HandleLiveness {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expired => "expired",
            Self::Unverified => "unverified",
        }
    }
}

/// A handle record binding a human-readable name to an anchor.
#[derive(Debug, Clone, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct HandleRecord {
    #[cbor(n = 0)]
    pub anchor: String,
    #[cbor(n = 1)]
    pub handle: String,
    #[cbor(n = 2)]
    pub protocol: String,
    #[cbor(n = 3)]
    pub claimed_at_ms: u64,
    #[cbor(n = 4)]
    pub verified_at_ms: Option<u64>,
    #[cbor(n = 5)]
    pub verification_method: String,
    #[cbor(n = 6)]
    pub liveness: HandleLiveness,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    #[test]
    fn handle_record_roundtrip() {
        let record = HandleRecord {
            anchor: "sha256:abc".into(),
            handle: "alice.bsky.social".into(),
            protocol: "atproto".into(),
            claimed_at_ms: 1000,
            verified_at_ms: Some(2000),
            verification_method: "dns_txt".into(),
            liveness: HandleLiveness::Active,
        };
        let bytes = canonical_bytes(&record);
        let decoded: HandleRecord = from_canonical(&bytes).unwrap();
        assert_eq!(decoded.anchor, record.anchor);
        assert_eq!(decoded.handle, record.handle);
        assert_eq!(decoded.liveness, record.liveness);
    }

    #[test]
    fn liveness_roundtrip() {
        for liveness in [
            HandleLiveness::Active,
            HandleLiveness::Expired,
            HandleLiveness::Unverified,
        ] {
            let bytes = canonical_bytes(&liveness);
            let decoded: HandleLiveness = from_canonical(&bytes).unwrap();
            assert_eq!(decoded, liveness);
        }
    }
}
