//! Trust position: runtime state of a node's trust assessment.
//!
//! Trust is not persisted (I-7). It is computed at runtime from
//! accumulated assertions. Absence is not failure (I-3):
//! no peers = Standalone, not Degraded.

use std::num::NonZeroUsize;

use dcbor::prelude::*;

#[derive(Debug, Clone, CBORCodable)]
pub enum TrustPosition {
    /// No probing has occurred. Initial state.
    #[cbor(n = 0)]
    Unprobed,
    /// This node operates alone. No peers discovered.
    /// This is a valid operational state, not an error.
    #[cbor(n = 1)]
    Standalone,
    /// Federation active with verified peers.
    #[cbor(n = 2)]
    Federated {
        #[cbor(n = 0)]
        verified_peers: u64,
    },
    /// Fault detected. Something is wrong.
    #[cbor(n = 3)]
    Degraded {
        #[cbor(n = 0)]
        reason: DegradeReason,
        #[cbor(n = 1)]
        reachable: u64,
        #[cbor(n = 2)]
        verified: u64,
    },
}

impl TrustPosition {
    pub fn as_str(&self) -> &'static str {
        match self {
            TrustPosition::Unprobed => "unprobed",
            TrustPosition::Standalone => "standalone",
            TrustPosition::Federated { .. } => "federated",
            TrustPosition::Degraded { .. } => "degraded",
        }
    }

    pub fn is_faulted(&self) -> bool {
        matches!(self, TrustPosition::Degraded { .. })
    }

    pub fn federated(verified_peers: NonZeroUsize) -> Self {
        TrustPosition::Federated {
            verified_peers: verified_peers.get() as u64,
        }
    }
}

#[derive(Debug, Clone, CBORCodable)]
pub enum DegradeReason {
    #[cbor(n = 0)]
    SignatureInvalid,
    #[cbor(n = 1)]
    AnchorMismatch,
    #[cbor(n = 2)]
    Equivocation,
    #[cbor(n = 3)]
    MalformedResponse,
}

impl DegradeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            DegradeReason::SignatureInvalid => "signature-invalid",
            DegradeReason::AnchorMismatch => "anchor-mismatch",
            DegradeReason::Equivocation => "equivocation",
            DegradeReason::MalformedResponse => "malformed-response",
        }
    }

    pub fn detail(&self) -> &'static str {
        match self {
            DegradeReason::SignatureInvalid => {
                "A peer's signature failed verification"
            }
            DegradeReason::AnchorMismatch => {
                "A peer's anchor does not match its signing key"
            }
            DegradeReason::Equivocation => {
                "A peer signed two conflicting epoch roots"
            }
            DegradeReason::MalformedResponse => {
                "A peer returned an unparseable response"
            }
        }
    }
}

/// Record of a known peer for trust tracking.
#[derive(Debug, Clone, CBORCodable)]
pub struct PeerRecord {
    #[cbor(n = 0)]
    pub endpoint: String,
    #[cbor(n = 1)]
    pub asserter_anchor: String,
    #[cbor(n = 2)]
    pub last_epoch: u64,
    #[cbor(n = 3)]
    pub state_root: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    #[test]
    fn trust_position_unprobed() {
        let pos = TrustPosition::Unprobed;
        assert_eq!(pos.as_str(), "unprobed");
        assert!(!pos.is_faulted());
    }

    #[test]
    fn trust_position_standalone() {
        let pos = TrustPosition::Standalone;
        assert_eq!(pos.as_str(), "standalone");
        assert!(!pos.is_faulted());
    }

    #[test]
    fn trust_position_federated() {
        let pos = TrustPosition::federated(NonZeroUsize::new(3).unwrap());
        assert_eq!(pos.as_str(), "federated");
        assert!(!pos.is_faulted());
    }

    #[test]
    fn trust_position_degraded() {
        let pos = TrustPosition::Degraded {
            reason: DegradeReason::Equivocation,
            reachable: 5,
            verified: 2,
        };
        assert_eq!(pos.as_str(), "degraded");
        assert!(pos.is_faulted());
    }

    #[test]
    fn degrade_reason_roundtrip() {
        let reason = DegradeReason::SignatureInvalid;
        let bytes = canonical_bytes(&reason);
        let decoded: DegradeReason = from_canonical(&bytes).unwrap();
        assert_eq!(decoded.as_str(), reason.as_str());
    }

    #[test]
    fn peer_record_roundtrip() {
        let pr = PeerRecord {
            endpoint: "https://peer.example.com".into(),
            asserter_anchor: "sha256:abc".into(),
            last_epoch: 42,
            state_root: "sha256:def".into(),
        };
        let bytes = canonical_bytes(&pr);
        let decoded: PeerRecord = from_canonical(&bytes).unwrap();
        assert_eq!(decoded.endpoint, pr.endpoint);
        assert_eq!(decoded.last_epoch, pr.last_epoch);
    }
}
