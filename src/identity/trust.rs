//! Node trust position -- runtime-discovered, never configured.
//!
//! TrustPosition distinguishes absence from fault:
//! - Unprobed: bootstrap complete, probe not yet run
//! - Standalone: probed, no peers reachable (NORMAL, not degraded)
//! - Federated: probed, peers verified
//! - Degraded: probed, peers reachable but verification FAILED (fault)
//!
//! No computed trust value is ever persisted (I-7). Trust is evaluated
//! at read time by local policy. The store holds evidence only.

use std::num::NonZeroUsize;

use serde::{Deserialize, Serialize};

use crate::identity::anchor::AsserterAnchor;

/// What the node found when it looked. Never configured -- always discovered.
///
/// Exhaustive matching required: no `_ =>` arm anywhere. Adding a variant
/// must break every consumer so they decide what to do about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustPosition {
    /// Bootstrap complete, probe not yet run.
    Unprobed,

    /// Probed; no peers configured or none reachable.
    /// Fully functional. Minimally trusted. This is NORMAL.
    Standalone,

    /// Probed; at least one peer verified.
    Federated { verified_peers: NonZeroUsize },

    /// Probed; peers were reachable but something FAILED.
    /// This is a fault, not an absence. Must be louder than Standalone.
    Degraded {
        reason: DegradeReason,
        reachable: usize,
        verified: usize,
    },
}

impl TrustPosition {
    /// Machine-readable, stable across versions. Used as the
    /// `trust/position` assertion value. Do not localize.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unprobed => "unprobed",
            Self::Standalone => "standalone",
            Self::Federated { .. } => "federated",
            Self::Degraded { .. } => "degraded",
        }
    }

    /// True when a fault was observed. Callers SHOULD emit at
    /// WARN or above and surface this in health output.
    pub fn is_faulted(&self) -> bool {
        matches!(self, Self::Degraded { .. })
    }
}

/// Why a probe degraded. `#[non_exhaustive]` because new fault kinds
/// are expected; downstream must handle unknown ones.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DegradeReason {
    /// Peer served an epoch root whose signature did not verify.
    SignatureInvalid { peer: String },
    /// Peer's advertised anchor did not match the key that signed.
    AnchorMismatch {
        peer: String,
        claimed: String,
        derived: String,
    },
    /// Two epoch roots at the same epoch with different state roots.
    Equivocation { peer: String, epoch: u64 },
    /// Peer reachable, response malformed.
    MalformedResponse { peer: String },
}

impl DegradeReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SignatureInvalid { .. } => "signature_invalid",
            Self::AnchorMismatch { .. } => "anchor_mismatch",
            Self::Equivocation { .. } => "equivocation",
            Self::MalformedResponse { .. } => "malformed_response",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::SignatureInvalid { peer } => format!("peer {peer}: signature invalid"),
            Self::AnchorMismatch {
                peer,
                claimed,
                derived,
            } => format!("peer {peer}: claimed {claimed}, derived {derived}"),
            Self::Equivocation { peer, epoch } => {
                format!("peer {peer}: equivocation at epoch {epoch}")
            }
            Self::MalformedResponse { peer } => format!("peer {peer}: malformed response"),
        }
    }
}

/// A verified peer record. Retains attribution (I-4).
///
/// Epochs are per-asserter Lamport counters. NEVER compare across peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub endpoint: String,
    pub anchor: AsserterAnchor,
    /// Peer-local Lamport counter. NEVER compare across peers.
    pub epoch: u64,
    pub state_root: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_position_as_str() {
        assert_eq!(TrustPosition::Unprobed.as_str(), "unprobed");
        assert_eq!(TrustPosition::Standalone.as_str(), "standalone");
        assert_eq!(
            TrustPosition::Federated {
                verified_peers: NonZeroUsize::new(2).unwrap()
            }
            .as_str(),
            "federated"
        );
        assert_eq!(
            TrustPosition::Degraded {
                reason: DegradeReason::SignatureInvalid {
                    peer: "x".to_owned()
                },
                reachable: 1,
                verified: 0,
            }
            .as_str(),
            "degraded"
        );
    }

    #[test]
    fn only_degraded_is_faulted() {
        assert!(!TrustPosition::Unprobed.is_faulted());
        assert!(!TrustPosition::Standalone.is_faulted());
        assert!(!TrustPosition::Federated {
            verified_peers: NonZeroUsize::new(1).unwrap()
        }
        .is_faulted());
        assert!(TrustPosition::Degraded {
            reason: DegradeReason::Equivocation {
                peer: "y".to_owned(),
                epoch: 5,
            },
            reachable: 2,
            verified: 1,
        }
        .is_faulted());
    }

    #[test]
    fn degrade_reason_detail() {
        let r = DegradeReason::SignatureInvalid {
            peer: "https://peer-a".to_owned(),
        };
        assert!(r.detail().contains("peer-a"));
        assert_eq!(r.as_str(), "signature_invalid");
    }
}
