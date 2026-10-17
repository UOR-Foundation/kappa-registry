use std::num::NonZeroUsize;

use dcbor::prelude::*;

use crate::kappa::Kappa;
use crate::namespace::ProtocolId;
use crate::signed::SignedPayload;

// ---------------------------------------------------------------------------
// Identity Binding
// ---------------------------------------------------------------------------

/// Verification method used to establish a binding.
/// CBOR discriminants (PERMANENT): 0-6
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum BindingMethod {
    #[cbor(n = 0)]
    SelfDeclared,
    #[cbor(n = 1)]
    DnsChallenge,
    #[cbor(n = 2)]
    HttpChallenge,
    #[cbor(n = 3)]
    KeyChallenge,
    #[cbor(n = 4)]
    Delegation,
    #[cbor(n = 5)]
    PeerAttestation,
    #[cbor(n = 6)]
    DeviceAttestation,
}

impl BindingMethod {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SelfDeclared => "self-declared",
            Self::DnsChallenge => "dns-challenge",
            Self::HttpChallenge => "http-challenge",
            Self::KeyChallenge => "key-challenge",
            Self::Delegation => "delegation",
            Self::PeerAttestation => "peer-attestation",
            Self::DeviceAttestation => "device-attestation",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "self-declared" | "self-asserted" => Some(Self::SelfDeclared),
            "dns-challenge" | "dns-txt" => Some(Self::DnsChallenge),
            "http-challenge" | "http-well-known" => Some(Self::HttpChallenge),
            "key-challenge" => Some(Self::KeyChallenge),
            "delegation" => Some(Self::Delegation),
            "peer-attestation" => Some(Self::PeerAttestation),
            "device-attestation" => Some(Self::DeviceAttestation),
            _ => None,
        }
    }
}

/// Trust level of a binding.
/// CBOR discriminants (PERMANENT): 0-3
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    CBORCodable,
    serde::Serialize,
    serde::Deserialize,
)]
#[non_exhaustive]
pub enum TrustLevel {
    #[cbor(n = 0)]
    Unverified,
    #[cbor(n = 1)]
    Verified,
    #[cbor(n = 2)]
    ServerCustodial,
    #[cbor(n = 3)]
    SelfSovereign,
}

impl TrustLevel {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Verified => "verified",
            Self::ServerCustodial => "server-custodial",
            Self::SelfSovereign => "self-sovereign",
        }
    }
}

/// A binding between an external identifier and a cryptographic anchor.
/// CBOR key assignments (PERMANENT): 0-5
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct IdentityBinding {
    pub source: String,
    pub target: Kappa,
    pub method: BindingMethod,
    pub trust_level: TrustLevel,
    pub verified_at_ms: Option<i64>,
    pub metadata: Option<Vec<u8>>,
}

crate::wire_map::wire_map!(IdentityBinding {
    source: value = 0,
    target: value = 1,
    method: value = 2,
    trust_level: value = 3,
    verified_at_ms: optional = 4,
    metadata: optional_bytes = 5,
});

// ---------------------------------------------------------------------------
// Assertion
// ---------------------------------------------------------------------------

/// A signed claim by an asserter about a subject.
/// CBOR key assignments (PERMANENT): 0-7
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityAssertion {
    pub asserter: Kappa,
    pub subject: String,
    pub facet: String,
    pub value: Vec<u8>,
    pub basis: String,
    pub valid_from_ms: i64,
    pub valid_until_ms: Option<i64>,
    pub cose_signature: SignedPayload,
}

crate::wire_map::wire_map!(IdentityAssertion {
    asserter: value = 0,
    subject: value = 1,
    facet: value = 2,
    value: bytes = 3,
    basis: value = 4,
    valid_from_ms: value = 5,
    valid_until_ms: optional = 6,
    cose_signature: value = 7,
});

#[derive(Clone)]
struct SignableAssertion {
    asserter: Kappa,
    subject: String,
    facet: String,
    value: Vec<u8>,
    basis: String,
    valid_from_ms: i64,
    valid_until_ms: Option<i64>,
}

crate::wire_map::wire_map!(SignableAssertion {
    asserter: value = 0,
    subject: value = 1,
    facet: value = 2,
    value: bytes = 3,
    basis: value = 4,
    valid_from_ms: value = 5,
    valid_until_ms: optional = 6,
});

impl IdentityAssertion {
    /// Canonical dCBOR bytes of the unsigned fields (keys 0-6).
    /// This is the payload that `COSE_Sign1` signs.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let signable = SignableAssertion {
            asserter: self.asserter.clone(),
            subject: self.subject.clone(),
            facet: self.facet.clone(),
            value: self.value.clone(),
            basis: self.basis.clone(),
            valid_from_ms: self.valid_from_ms,
            valid_until_ms: self.valid_until_ms,
        };
        crate::canonical::canonical_bytes(&signable)
    }
}

// ---------------------------------------------------------------------------
// Succession
// ---------------------------------------------------------------------------

/// Why a key succession occurred.
/// CBOR discriminants (PERMANENT): 0-2
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum SuccessionReason {
    #[cbor(n = 0)]
    Rotation,
    #[cbor(n = 1)]
    KeyCompromise,
    #[cbor(n = 2)]
    Administrative,
}

impl SuccessionReason {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Rotation => "rotation",
            Self::KeyCompromise => "key-compromise",
            Self::Administrative => "administrative",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "rotation" => Some(Self::Rotation),
            "key-compromise" => Some(Self::KeyCompromise),
            "administrative" => Some(Self::Administrative),
            _ => None,
        }
    }
}

/// A key succession record linking an old anchor to a new one.
/// Dual `COSE_Sign1`: both old and new keys sign the same payload.
/// CBOR key assignments (PERMANENT): 0-7
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct Succession {
    #[cbor(n = 0)]
    pub old_anchor: Kappa,
    #[cbor(n = 1)]
    pub new_anchor: Kappa,
    #[cbor(n = 2)]
    pub reason: SuccessionReason,
    #[cbor(n = 3)]
    pub effective_at_ms: i64,
    #[cbor(n = 4)]
    pub chain_anchor: Option<Kappa>,
    #[cbor(n = 5)]
    pub prev_identifier: Option<Kappa>,
    #[cbor(n = 6)]
    pub old_cose_signature: SignedPayload,
    #[cbor(n = 7)]
    pub new_cose_signature: SignedPayload,
}

#[derive(Clone, CBORCodable)]
struct SignableSuccession {
    #[cbor(n = 0)]
    old_anchor: Kappa,
    #[cbor(n = 1)]
    new_anchor: Kappa,
    #[cbor(n = 2)]
    reason: SuccessionReason,
    #[cbor(n = 3)]
    effective_at_ms: i64,
    #[cbor(n = 4)]
    chain_anchor: Option<Kappa>,
    #[cbor(n = 5)]
    prev_identifier: Option<Kappa>,
}

impl Succession {
    /// Both anchors sign the same canonical keys 0-5.
    pub fn signable_bytes(&self) -> Vec<u8> {
        crate::canonical::canonical_bytes(&SignableSuccession {
            old_anchor: self.old_anchor.clone(),
            new_anchor: self.new_anchor.clone(),
            reason: self.reason,
            effective_at_ms: self.effective_at_ms,
            chain_anchor: self.chain_anchor.clone(),
            prev_identifier: self.prev_identifier.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

/// Why an assertion was revoked.
/// CBOR discriminants (PERMANENT): 0-4
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
#[non_exhaustive]
pub enum RevocationReason {
    #[cbor(n = 0)]
    KeyCompromise,
    #[cbor(n = 1)]
    Superseded,
    #[cbor(n = 2)]
    Erroneous,
    #[cbor(n = 3)]
    PrivilegeWithdrawn,
    #[cbor(n = 4)]
    CessationOfOperation,
}

impl RevocationReason {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::KeyCompromise => "key-compromise",
            Self::Superseded => "superseded",
            Self::Erroneous => "erroneous",
            Self::PrivilegeWithdrawn => "privilege-withdrawn",
            Self::CessationOfOperation => "cessation-of-operation",
        }
    }
}

/// A revocation voiding a previously published assertion.
/// CBOR key assignments (PERMANENT): 0-4
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct Revocation {
    #[cbor(n = 0)]
    pub assertion_kappa: Kappa,
    #[cbor(n = 1)]
    pub asserter: Kappa,
    #[cbor(n = 2)]
    pub reason: RevocationReason,
    #[cbor(n = 3)]
    pub revoked_at_ms: i64,
    #[cbor(n = 4)]
    pub cose_signature: SignedPayload,
}

#[derive(Clone, CBORCodable)]
struct SignableRevocation {
    #[cbor(n = 0)]
    assertion_kappa: Kappa,
    #[cbor(n = 1)]
    asserter: Kappa,
    #[cbor(n = 2)]
    reason: RevocationReason,
    #[cbor(n = 3)]
    revoked_at_ms: i64,
}

impl Revocation {
    /// Canonical dCBOR bytes of the unsigned fields (keys 0-3).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let signable = SignableRevocation {
            assertion_kappa: self.assertion_kappa.clone(),
            asserter: self.asserter.clone(),
            reason: self.reason,
            revoked_at_ms: self.revoked_at_ms,
        };
        crate::canonical::canonical_bytes(&signable)
    }
}

// ---------------------------------------------------------------------------
// Watermark
// ---------------------------------------------------------------------------

/// Why a watermark was set.
/// CBOR discriminants (PERMANENT): 0-3
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum WatermarkReason {
    #[cbor(n = 0)]
    Rotation,
    #[cbor(n = 1)]
    KeyCompromise,
    #[cbor(n = 2)]
    Administrative,
    #[cbor(n = 3)]
    Policy,
}

impl WatermarkReason {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Rotation => "rotation",
            Self::KeyCompromise => "key-compromise",
            Self::Administrative => "administrative",
            Self::Policy => "policy",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "rotation" | "rotation-succession" => Some(Self::Rotation),
            "key-compromise" | "key-compromise-succession" => Some(Self::KeyCompromise),
            "administrative" => Some(Self::Administrative),
            "policy" | "policy-engine" => Some(Self::Policy),
            _ => None,
        }
    }
}

/// O(1) bulk invalidation of assertions before a timestamp.
/// CBOR key assignments (PERMANENT): 0-4
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct Watermark {
    #[cbor(n = 0)]
    pub asserter: Kappa,
    #[cbor(n = 1)]
    pub invalidate_before_ms: i64,
    #[cbor(n = 2)]
    pub reason: WatermarkReason,
    #[cbor(n = 3)]
    pub set_at_ms: i64,
    #[cbor(n = 4)]
    pub cose_signature: SignedPayload,
}

#[derive(Clone, CBORCodable)]
struct SignableWatermark {
    #[cbor(n = 0)]
    asserter: Kappa,
    #[cbor(n = 1)]
    invalidate_before_ms: i64,
    #[cbor(n = 2)]
    reason: WatermarkReason,
    #[cbor(n = 3)]
    set_at_ms: i64,
}

impl Watermark {
    pub const fn invalidates(&self, valid_from_ms: i64) -> bool {
        valid_from_ms < self.invalidate_before_ms
    }

    /// Canonical dCBOR bytes of the unsigned fields (keys 0-3).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let signable = SignableWatermark {
            asserter: self.asserter.clone(),
            invalidate_before_ms: self.invalidate_before_ms,
            reason: self.reason,
            set_at_ms: self.set_at_ms,
        };
        crate::canonical::canonical_bytes(&signable)
    }
}

// ---------------------------------------------------------------------------
// Handle
// ---------------------------------------------------------------------------

/// A handle record binding a human-readable name to an anchor.
///
/// The protocol field is a `ProtocolId` -- the canonical protocol surface
/// identifier. Each protocol module defines its own `ProtocolId` constant.
/// The substrate stores and retrieves by it without interpreting it.
///
/// The registry records WHEN a third-party attestation was collected.
/// The registry does NOT classify the attestation as fresh or stale.
/// The consumer computes currency from `attested_at_ms` and their
/// own TTL policy.
///
/// CBOR key assignments (PERMANENT): 0-4
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct HandleRecord {
    #[cbor(n = 0)]
    pub anchor: Kappa,
    #[cbor(n = 1)]
    pub handle: String,
    #[cbor(n = 2)]
    pub protocol: ProtocolId,
    /// Encoded `ClockMs` (`as_i64`) of the claim: physical milliseconds in
    /// the upper 48 bits. Grace windows apply to the physical component.
    #[cbor(n = 3)]
    pub claimed_at_ms: i64,
    /// When a third-party attestation was last collected, as an encoded
    /// `ClockMs`. None = never probed. Some(t) = probed at time t.
    /// The consumer decides what "fresh enough" means.
    #[cbor(n = 4)]
    pub attested_at_ms: Option<i64>,
}

// ---------------------------------------------------------------------------
// Absence Proof
// ---------------------------------------------------------------------------

/// Proof system used for absence proofs.
/// CBOR discriminants (PERMANENT): 0-2
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
#[non_exhaustive]
pub enum ProofSystem {
    #[cbor(n = 0)]
    AkdNonMembership,
    #[cbor(n = 1)]
    MerkleExclusion,
    #[cbor(n = 2)]
    TrieAbsence,
}

/// Cryptographic evidence that no assertion exists for a subject on a facet.
/// CBOR key assignments (PERMANENT): 0-5
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbsenceProof {
    pub subject: String,
    pub facet: String,
    pub epoch: u64,
    pub proof_bytes: Vec<u8>,
    pub epoch_root_kappa: Kappa,
    pub algorithm: ProofSystem,
}

crate::wire_map::wire_map!(AbsenceProof {
    subject: value = 0,
    facet: value = 1,
    epoch: value = 2,
    proof_bytes: bytes = 3,
    epoch_root_kappa: value = 4,
    algorithm: value = 5,
});

// ---------------------------------------------------------------------------
// Time Attestation Source Protocol
// ---------------------------------------------------------------------------

/// Protocol used by a time attestation source.
/// CBOR discriminants (PERMANENT): 0-5
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum TimeSourceProtocol {
    #[cbor(n = 0)]
    Local,
    #[cbor(n = 1)]
    Roughtime,
    #[cbor(n = 2)]
    Nts,
    #[cbor(n = 3)]
    Ptp,
    #[cbor(n = 4)]
    Gps,
    #[cbor(n = 5)]
    Peer,
}

impl TimeSourceProtocol {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Roughtime => "roughtime",
            Self::Nts => "nts",
            Self::Ptp => "ptp",
            Self::Gps => "gps",
            Self::Peer => "peer",
        }
    }
}

// ---------------------------------------------------------------------------
// Trust Position (runtime, not a wire type)
// ---------------------------------------------------------------------------

/// Runtime trust assessment of this node's federation state.
/// CBOR discriminants (PERMANENT): 0-3
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub enum TrustPosition {
    #[cbor(n = 0)]
    Unprobed,
    #[cbor(n = 1)]
    Standalone,
    #[cbor(n = 2)]
    Federated {
        #[cbor(n = 0)]
        verified_peers: u64,
    },
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
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Unprobed => "unprobed",
            Self::Standalone => "standalone",
            Self::Federated { .. } => "federated",
            Self::Degraded { .. } => "degraded",
        }
    }

    pub const fn is_faulted(&self) -> bool {
        matches!(self, Self::Degraded { .. })
    }

    pub const fn federated(verified_peers: NonZeroUsize) -> Self {
        Self::Federated {
            verified_peers: verified_peers.get() as u64,
        }
    }
}

/// Why a node's trust position degraded.
/// CBOR discriminants (PERMANENT): 0-3
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
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
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::SignatureInvalid => "signature-invalid",
            Self::AnchorMismatch => "anchor-mismatch",
            Self::Equivocation => "equivocation",
            Self::MalformedResponse => "malformed-response",
        }
    }
}

/// Record of a known peer for trust tracking.
/// CBOR key assignments (PERMANENT): 0-3
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct PeerRecord {
    #[cbor(n = 0)]
    pub endpoint: String,
    #[cbor(n = 1)]
    pub asserter_anchor: Kappa,
    #[cbor(n = 2)]
    pub last_epoch: u64,
    #[cbor(n = 3)]
    pub state_root: Kappa,
}

/// Probe result from a federation peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    Verified(PeerRecord),
    Unreachable(String),
    SignatureInvalid(String),
    Equivocation {
        peer: Kappa,
        epoch: u64,
        local_root: Kappa,
        remote_root: Kappa,
    },
}

// ---------------------------------------------------------------------------
// Trust State Machine
// ---------------------------------------------------------------------------

/// The state of a peer's identity from our perspective.
///
/// Four states with a `previously_verified` latch. The latch is set
/// when `VerificationSucceeded` fires and cleared only by
/// `VerificationWithdrawn`. All other transitions preserve the latch.
///
/// The transition table is exhaustive. Any transition not listed in
/// the `transition()` function is a defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum TrustState {
    /// First contact, or user acknowledged an identity change.
    Pinned,
    /// Identity changed since it was pinned. User must acknowledge.
    PinViolation,
    /// Interactive verification completed. Highest trust.
    Verified,
    /// Identity changed AFTER verification. Serious warning.
    VerificationViolation,
}

/// Events that trigger trust state transitions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustEvent {
    /// First observation of a root or re-observation after acknowledgment.
    RootObserved,
    /// Root changed without a valid rotation proof.
    UnexplainedRootChange,
    /// Valid rotation proof chain observed.
    RotationProofVerified,
    /// Interactive verification succeeded.
    VerificationSucceeded,
    /// User acknowledges a new root after `PinViolation`.
    UserAcknowledged,
    /// User withdraws verification, drops to Pinned, clears latch.
    VerificationWithdrawn,
    /// Verified `RevocationCommitment` received.
    RevocationReceived,
    /// Verified death notice received.
    TombstoneReceived,
}

/// Compute the next trust state given current state, latch, and event.
///
/// Returns (`new_state`, `new_latch`). The latch is true if it was
/// already set OR if this transition sets it. It is NEVER cleared
/// except by `VerificationWithdrawn`.
pub const fn trust_transition(
    current: TrustState,
    previously_verified: bool,
    event: TrustEvent,
) -> (TrustState, bool) {
    match (current, event) {
        (
            _,
            TrustEvent::UnexplainedRootChange
            | TrustEvent::RevocationReceived
            | TrustEvent::TombstoneReceived,
        ) => {
            if previously_verified {
                (TrustState::VerificationViolation, true)
            } else {
                (TrustState::PinViolation, false)
            }
        }

        (_, TrustEvent::VerificationSucceeded) => (TrustState::Verified, true),

        (_, TrustEvent::RootObserved)
        | (
            TrustState::PinViolation | TrustState::VerificationViolation,
            TrustEvent::UserAcknowledged,
        ) => (TrustState::Pinned, previously_verified),
        (
            TrustState::VerificationViolation | TrustState::Verified,
            TrustEvent::VerificationWithdrawn,
        ) => (TrustState::Pinned, false),
        (
            state,
            TrustEvent::RotationProofVerified
            | TrustEvent::UserAcknowledged
            | TrustEvent::VerificationWithdrawn,
        ) => (state, previously_verified),
    }
}

// ---------------------------------------------------------------------------
// Succession Chain
// ---------------------------------------------------------------------------

/// Maximum number of links in a presented succession chain.
pub const SUCCESSION_CHAIN_MAX: usize = 64;

/// A verified succession chain from a known anchor to a claimed head.
///
/// Construction verifies contiguity, dual signatures, and monotone
/// epoch ordering. Not a wire type. Constructed at verification time
/// from a sequence of Succession records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessionChain {
    links: Vec<Succession>,
    anchor: Kappa,
    head: Kappa,
    head_epoch: u64,
}

impl SuccessionChain {
    /// The anchor the chain was verified against.
    pub const fn anchor(&self) -> &Kappa {
        &self.anchor
    }
    /// The head of the verified chain.
    pub const fn head(&self) -> &Kappa {
        &self.head
    }
    /// The epoch at the head.
    pub const fn head_epoch(&self) -> u64 {
        self.head_epoch
    }
    /// Number of links.
    pub const fn len(&self) -> usize {
        self.links.len()
    }
    /// Whether the chain is empty.
    pub const fn is_empty(&self) -> bool {
        self.links.is_empty()
    }
    /// The individual succession links.
    pub fn links(&self) -> &[Succession] {
        &self.links
    }

    /// Construct a chain from verified links. This is a construction
    /// helper, not a verifier. Verification of signatures and
    /// contiguity is the caller's responsibility. The business logic
    /// function `verify_succession_chain` in kappa-store's `succession_ops`
    /// performs the
    /// full verification and calls this constructor on success.
    pub fn from_verified_links(anchor: Kappa, links: Vec<Succession>) -> Self {
        if links.is_empty() {
            return Self {
                anchor: anchor.clone(),
                head: anchor,
                head_epoch: 0,
                links,
            };
        }
        let last = &links[links.len() - 1];
        Self {
            anchor,
            head: last.new_anchor.clone(),
            head_epoch: links.len() as u64,
            links,
        }
    }
}

// ---------------------------------------------------------------------------
// Revocation Commitment
// ---------------------------------------------------------------------------

/// Pre-committed revocation created at anchor origination.
///
/// Signed by the anchor's key at origination time. Stored in the
/// vault or namespace metadata. Usable to revoke the anchor even
/// when the signing key is lost, because the signature was created
/// before the key was lost.
///
/// CBOR key assignments (PERMANENT): 10-13
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct RevocationCommitment {
    #[cbor(n = 10)]
    pub anchor: Kappa,
    #[cbor(n = 11)]
    pub epoch_at_issue: u64,
    #[cbor(n = 12)]
    pub created_at_ms: i64,
    #[cbor(n = 13)]
    pub cose_signature: SignedPayload,
}

// ---------------------------------------------------------------------------
// Scoped Projection
// ---------------------------------------------------------------------------

/// A deterministic per-scope projection of an anchor.
///
/// Given an anchor and a scope key, the projected kappa is always
/// the same. Two projections with different scope keys from the same
/// anchor are unlinkable by third parties who do not know the anchor.
///
/// CBOR key assignments (PERMANENT): 20-23
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct ScopedProjection {
    #[cbor(n = 20)]
    pub anchor: Kappa,
    #[cbor(n = 21)]
    pub scope_key: Kappa,
    #[cbor(n = 22)]
    pub projected: Kappa,
    #[cbor(n = 23)]
    pub proof: ProjectionProof,
}

/// Bidirectional linkage proof between anchor and projected kappa.
///
/// Both signatures must verify. The anchor signs the projected kappa
/// and the projected kappa signs the anchor. Cross-direction forgery
/// is rejected because a forger who knows only one key cannot produce
/// both signatures.
///
/// CBOR key assignments (PERMANENT): 25-26
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct ProjectionProof {
    #[cbor(n = 25)]
    pub anchor_signs_projected: SignedPayload,
    #[cbor(n = 26)]
    pub projected_signs_anchor: SignedPayload,
}

/// Derive a scoped projection deterministically.
///
/// BLAKE3 keyed hash of anchor `key_bytes` using `scope_key` `key_bytes` as
/// the key. The result is a SHA-256 Kappa of the BLAKE3 output. Same
/// inputs always produce the same projected kappa. Different scope keys
/// produce different projections from the same anchor.
pub fn derive_scoped_projection(anchor: &Kappa, scope_key: &Kappa) -> Kappa {
    let key_material = scope_key.key_bytes();
    let mut blake3_key = [0u8; 32];
    blake3_key[..key_material.len().min(32)]
        .copy_from_slice(&key_material[..key_material.len().min(32)]);
    let hash = blake3::keyed_hash(&blake3_key, &anchor.key_bytes());
    Kappa::sha256(hash.as_bytes())
}

// ---------------------------------------------------------------------------
// Device Binding
// ---------------------------------------------------------------------------

/// Binding of a device signing key to an identity anchor.
///
/// The anchor signs the device key so the device can sign on behalf
/// of the anchor. Revocable per device without affecting other devices
/// bound to the same anchor.
///
/// CBOR key assignments (PERMANENT): 30-34
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DeviceBinding {
    pub anchor: Kappa,
    pub device_key: Vec<u8>,
    pub algorithm: String,
    pub bound_at_ms: i64,
    pub cose_signature: SignedPayload,
}

crate::wire_map::wire_map!(DeviceBinding {
    anchor: value = 30,
    device_key: bytes = 31,
    algorithm: value = 32,
    bound_at_ms: value = 33,
    cose_signature: value = 34,
});

// ---------------------------------------------------------------------------
// Prekey Binding
// ---------------------------------------------------------------------------

/// Binding of a prekey bundle hash to an identity anchor.
///
/// The anchor signs the BLAKE3 hash of the prekey bundle. Epoch-bound:
/// a prekey binding from an old epoch is stale and should be rejected
/// in favor of a binding from the current epoch.
///
/// CBOR key assignments (PERMANENT): 35-39
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PrekeyBinding {
    pub anchor: Kappa,
    pub bundle_hash: Vec<u8>,
    pub epoch: u64,
    pub bound_at_ms: i64,
    pub cose_signature: SignedPayload,
}

crate::wire_map::wire_map!(PrekeyBinding {
    anchor: value = 35,
    bundle_hash: bytes = 36,
    epoch: value = 37,
    bound_at_ms: value = 38,
    cose_signature: value = 39,
});

// ---------------------------------------------------------------------------
// Locator Record
// ---------------------------------------------------------------------------

/// Network addressing record with monotone epoch protection.
///
/// The `locator_epoch` increments on every address change. Updates with
/// a lower epoch than the stored value are stale and rejected. This
/// prevents replay of old address records that may route to an
/// attacker-controlled endpoint.
///
/// CBOR key assignments (PERMANENT): 40-44
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct LocatorRecord {
    #[cbor(n = 40)]
    pub anchor: Kappa,
    #[cbor(n = 41)]
    pub locator_epoch: u64,
    #[cbor(n = 42)]
    pub entries: Vec<LocatorEntry>,
    #[cbor(n = 43)]
    pub updated_at_ms: i64,
    #[cbor(n = 44)]
    pub cose_signature: SignedPayload,
}

/// A single entry in a locator record.
///
/// CBOR key assignments (PERMANENT): 45-47
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct LocatorEntry {
    #[cbor(n = 45)]
    pub kind: LocatorKind,
    #[cbor(n = 46)]
    pub value: String,
    #[cbor(n = 47)]
    pub substrate: String,
}

/// Kind of network locator.
///
/// CBOR discriminants (PERMANENT): 0-4
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum LocatorKind {
    #[cbor(n = 0)]
    Profile,
    #[cbor(n = 1)]
    Mailbox,
    #[cbor(n = 2)]
    Inbox,
    #[cbor(n = 3)]
    Route,
    #[cbor(n = 4)]
    Custom,
}

impl LocatorKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::Mailbox => "mailbox",
            Self::Inbox => "inbox",
            Self::Route => "route",
            Self::Custom => "custom",
        }
    }
}

// ---------------------------------------------------------------------------
// Entity Kind
// ---------------------------------------------------------------------------

/// Classification of the entity behind an identity anchor.
///
/// Stored as an assertion with facet "entity-kind" on the anchor.
/// Applications use this to enforce policy: a bot anchor cannot
/// moderate a human-only channel, a service anchor cannot cast a
/// governance vote.
///
/// CBOR discriminants (PERMANENT): 0-3
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum EntityKind {
    #[cbor(n = 0)]
    Human,
    #[cbor(n = 1)]
    ModelDriven,
    #[cbor(n = 2)]
    Service,
    #[cbor(n = 3)]
    Automation,
}

impl EntityKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::ModelDriven => "model-driven",
            Self::Service => "service",
            Self::Automation => "automation",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "human" => Some(Self::Human),
            "model-driven" | "model_driven" | "ai" | "llm" => Some(Self::ModelDriven),
            "service" | "svc" => Some(Self::Service),
            "automation" | "bot" => Some(Self::Automation),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Anchor Kappa
// ---------------------------------------------------------------------------

/// A Kappa that is known to be derived from a signing key via
/// `Kappa::from_key`. Distinguishes identity anchors from content
/// addresses at the type level.
///
/// No From<Kappa>, no parse from arbitrary string. The only
/// constructor is `from_key` which produces a SHA-256 digest of
/// the algorithm-tagged public key bytes.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AnchorKappa(Kappa);

impl AnchorKappa {
    /// Derive an anchor from a signing key.
    pub fn from_key(
        algorithm: &str,
        public_key: &[u8],
    ) -> Result<Self, crate::kappa::KappaParseError> {
        Kappa::from_key(algorithm, public_key).map(Self)
    }

    /// Access the underlying Kappa.
    pub const fn as_kappa(&self) -> &Kappa {
        &self.0
    }

    /// Consume the wrapper, returning the Kappa.
    pub const fn into_kappa(self) -> Kappa {
        self.0
    }
}

impl std::fmt::Display for AnchorKappa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl serde::Serialize for AnchorKappa {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for AnchorKappa {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let kappa = Kappa::deserialize(deserializer)?;
        if kappa.axis() != crate::axis::Axis::Sha256 || kappa.digest_bytes().len() != 32 {
            return Err(serde::de::Error::custom(
                "AnchorKappa must be a SHA-256 digest",
            ));
        }
        Ok(Self(kappa))
    }
}

// ---------------------------------------------------------------------------
// Rotation Epoch
// ---------------------------------------------------------------------------

/// Monotonic rotation epoch counter. Newtypes u64 to prevent bare
/// arithmetic errors. ORIGIN is 0. `next()` increments by 1.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct RotationEpoch(pub u64);

impl From<RotationEpoch> for CBOR {
    fn from(epoch: RotationEpoch) -> Self {
        epoch.0.into()
    }
}

impl TryFrom<CBOR> for RotationEpoch {
    type Error = dcbor::Error;

    fn try_from(value: CBOR) -> Result<Self, Self::Error> {
        match value.into_case() {
            CBORCase::Unsigned(value) => Ok(Self(value)),
            _ => Err(dcbor::Error::msg(
                "rotation epoch must be an unsigned integer",
            )),
        }
    }
}

impl RotationEpoch {
    pub const ORIGIN: Self = Self(0);

    pub fn next(self) -> Result<Self, crate::StoreError> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| crate::StoreError::CapacityExceeded("rotation epoch exhausted".into()))
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

impl std::fmt::Display for RotationEpoch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "epoch:{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Identity Tombstone
// ---------------------------------------------------------------------------

/// Voluntary identity termination signed by the anchor.
///
/// When a death notice is verified, the identity is permanently removed
/// from the trust store. All sessions are torn down. All watches are
/// cancelled. The anchor is added to a dead set that blocks
/// re-observation.
///
/// CBOR key assignments (PERMANENT): 50-54
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct IdentityTombstone {
    #[cbor(n = 50)]
    pub anchor: Kappa,
    #[cbor(n = 51)]
    pub epoch: RotationEpoch,
    #[cbor(n = 52)]
    pub issued_at_ms: i64,
    #[cbor(n = 53)]
    pub cose_signature: SignedPayload,
}

// ---------------------------------------------------------------------------
// Rotation Grace
// ---------------------------------------------------------------------------

/// Duration in milliseconds after a verified succession where old-anchor
/// signed material is still accepted. After this window, old-anchor
/// signatures are rejected.
///
/// Default: 14 days. Configurable per deployment.
pub const DEFAULT_ROTATION_GRACE_MS: i64 = 14 * 24 * 3600 * 1000;

/// Rotation grace configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RotationGrace {
    pub grace_ms: i64,
}

impl Default for RotationGrace {
    fn default() -> Self {
        Self {
            grace_ms: DEFAULT_ROTATION_GRACE_MS,
        }
    }
}

impl RotationGrace {
    /// Whether old-anchor material is still within the grace window.
    /// `rotation_at_ms` is the timestamp of the succession.
    /// `now_ms` is the current time.
    pub const fn is_within_grace(&self, rotation_at_ms: i64, now_ms: i64) -> bool {
        now_ms < rotation_at_ms.saturating_add(self.grace_ms)
    }
}

// ---------------------------------------------------------------------------
// Identity Status Change
// ---------------------------------------------------------------------------

/// Event emitted when a trust state transition is significant enough
/// to notify the UI or audit log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityStatusChange {
    pub anchor: Kappa,
    pub old_state: TrustState,
    pub new_state: TrustState,
    pub event: TrustEvent,
    pub timestamp_ms: i64,
}

// ---------------------------------------------------------------------------
// Session Anchor
// ---------------------------------------------------------------------------

/// Deterministic symmetric session identifier derived from two anchors.
///
/// Both sides compute the same value regardless of who initiated.
/// BLAKE3 `derive_key` with domain separation and lexicographic ordering
/// of the two anchor `key_bytes`.
///
/// Self-sessions are rejected at the type level: the derive function
/// returns an error when both anchors are equal.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionAnchor([u8; 32]);

impl SessionAnchor {
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Debug for SessionAnchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let h = self.to_hex();
        write!(f, "SessionAnchor({}...{})", &h[..8], &h[56..])
    }
}

const SESSION_ANCHOR_DOMAIN: &str = "kappa identity session anchor v1";

/// Derive the canonical session anchor between two identity anchors.
///
/// Lexicographically orders the two anchor `key_bytes`, concatenates
/// their complete binary identities, and applies BLAKE3 `derive_key` with
/// domain separation. Same inputs always produce the same output.
/// Rejects self-sessions where both anchors are equal.
pub fn derive_session_anchor(
    a: &Kappa,
    b: &Kappa,
) -> Result<SessionAnchor, crate::error::StoreError> {
    if a == b {
        return Err(crate::error::StoreError::Rejected(
            "cannot derive session anchor between an anchor and itself".into(),
        ));
    }

    let a_bytes = a.key_bytes();
    let b_bytes = b.key_bytes();

    let (lo, hi) = if a_bytes < b_bytes {
        (a_bytes.as_slice(), b_bytes.as_slice())
    } else {
        (b_bytes.as_slice(), a_bytes.as_slice())
    };

    let mut ikm = Vec::with_capacity(lo.len() + hi.len());
    ikm.extend_from_slice(lo);
    ikm.extend_from_slice(hi);

    let derived = blake3::derive_key(SESSION_ANCHOR_DOMAIN, &ikm);
    Ok(SessionAnchor(derived))
}

// ---------------------------------------------------------------------------
// Tests for new types
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_wire_bytes(
        value: impl Into<CBOR>,
        key: u64,
        expected: &[u8],
    ) -> Result<(), dcbor::Error> {
        let CBORCase::Map(map) = value.into().into_case() else {
            panic!("identity wire type must encode as a map");
        };
        let field: CBOR = map.extract(key)?;
        assert_eq!(field.to_cbor_data(), expected);
        Ok(())
    }

    #[test]
    fn identity_assertion_value_is_binary_in_both_signing_and_wire_forms()
    -> Result<(), dcbor::Error> {
        let assertion = IdentityAssertion {
            asserter: Kappa::sha256(b"asserter"),
            subject: "subject".into(),
            facet: "facet".into(),
            value: vec![1, 2],
            basis: "basis".into(),
            valid_from_ms: 1,
            valid_until_ms: None,
            cose_signature: SignedPayload::from_cose_bytes(vec![3, 4]),
        };
        assert_wire_bytes(assertion.clone(), 3, &[0x42, 1, 2])?;
        assert_wire_bytes(assertion.clone(), 7, &[0x42, 3, 4])?;
        let signable = CBOR::try_from_data(assertion.signable_bytes())?;
        assert_wire_bytes(signable, 3, &[0x42, 1, 2])?;
        let recovered = IdentityAssertion::try_from(CBOR::from(assertion))?;
        assert_eq!(recovered.value, [1, 2]);
        Ok(())
    }

    #[test]
    fn binding_proof_and_key_material_use_byte_strings() -> Result<(), dcbor::Error> {
        let anchor = Kappa::sha256(b"anchor");
        assert_wire_bytes(
            IdentityBinding {
                source: "source".into(),
                target: anchor.clone(),
                method: BindingMethod::KeyChallenge,
                trust_level: TrustLevel::Verified,
                verified_at_ms: Some(1),
                metadata: Some(vec![1, 2]),
            },
            5,
            &[0x42, 1, 2],
        )?;
        assert_wire_bytes(
            AbsenceProof {
                subject: "subject".into(),
                facet: "facet".into(),
                epoch: 1,
                proof_bytes: vec![1, 2],
                epoch_root_kappa: anchor.clone(),
                algorithm: ProofSystem::TrieAbsence,
            },
            3,
            &[0x42, 1, 2],
        )?;
        assert_wire_bytes(
            DeviceBinding {
                anchor: anchor.clone(),
                device_key: vec![1, 2],
                algorithm: "ed25519".into(),
                bound_at_ms: 1,
                cose_signature: SignedPayload::empty(),
            },
            31,
            &[0x42, 1, 2],
        )?;
        assert_wire_bytes(
            PrekeyBinding {
                anchor,
                bundle_hash: vec![1, 2],
                epoch: 1,
                bound_at_ms: 1,
                cose_signature: SignedPayload::empty(),
            },
            36,
            &[0x42, 1, 2],
        )?;
        Ok(())
    }

    #[test]
    fn succession_signatures_are_independent_byte_strings() -> Result<(), dcbor::Error> {
        let succession = Succession {
            old_anchor: Kappa::sha256(b"old"),
            new_anchor: Kappa::sha256(b"new"),
            reason: SuccessionReason::Rotation,
            effective_at_ms: 1,
            chain_anchor: None,
            prev_identifier: None,
            old_cose_signature: SignedPayload::from_cose_bytes(vec![1, 2]),
            new_cose_signature: SignedPayload::from_cose_bytes(vec![3, 4]),
        };
        assert_wire_bytes(succession.clone(), 6, &[0x42, 1, 2])?;
        assert_wire_bytes(succession, 7, &[0x42, 3, 4])?;
        Ok(())
    }

    #[test]
    fn trust_first_contact_pinned() {
        let (state, latch) = trust_transition(TrustState::Pinned, false, TrustEvent::RootObserved);
        assert_eq!(state, TrustState::Pinned);
        assert!(!latch);
    }

    #[test]
    fn trust_unexplained_change_without_latch() {
        let (state, latch) =
            trust_transition(TrustState::Pinned, false, TrustEvent::UnexplainedRootChange);
        assert_eq!(state, TrustState::PinViolation);
        assert!(!latch);
    }

    #[test]
    fn trust_unexplained_change_with_latch() {
        let (state, latch) =
            trust_transition(TrustState::Pinned, true, TrustEvent::UnexplainedRootChange);
        assert_eq!(state, TrustState::VerificationViolation);
        assert!(latch);
    }

    #[test]
    fn trust_verification_sets_latch() {
        let (state, latch) =
            trust_transition(TrustState::Pinned, false, TrustEvent::VerificationSucceeded);
        assert_eq!(state, TrustState::Verified);
        assert!(latch);
    }

    #[test]
    fn trust_rotation_preserves_state() {
        let (state, _) = trust_transition(
            TrustState::Verified,
            true,
            TrustEvent::RotationProofVerified,
        );
        assert_eq!(state, TrustState::Verified);
        let (state, _) =
            trust_transition(TrustState::Pinned, false, TrustEvent::RotationProofVerified);
        assert_eq!(state, TrustState::Pinned);
    }

    #[test]
    fn trust_acknowledge_pin_violation() {
        let (state, _) = trust_transition(
            TrustState::PinViolation,
            false,
            TrustEvent::UserAcknowledged,
        );
        assert_eq!(state, TrustState::Pinned);
    }

    #[test]
    fn trust_acknowledge_verification_violation() {
        let (state, latch) = trust_transition(
            TrustState::VerificationViolation,
            true,
            TrustEvent::UserAcknowledged,
        );
        assert_eq!(state, TrustState::Pinned);
        assert!(latch);
    }

    #[test]
    fn trust_withdraw_clears_latch() {
        let (state, latch) = trust_transition(
            TrustState::Verified,
            true,
            TrustEvent::VerificationWithdrawn,
        );
        assert_eq!(state, TrustState::Pinned);
        assert!(!latch);
    }

    #[test]
    fn trust_withdraw_from_violation_clears_latch() {
        let (state, latch) = trust_transition(
            TrustState::VerificationViolation,
            true,
            TrustEvent::VerificationWithdrawn,
        );
        assert_eq!(state, TrustState::Pinned);
        assert!(!latch);
    }

    #[test]
    fn trust_latch_survives_rotation() {
        let (_, latch) = trust_transition(
            TrustState::Verified,
            true,
            TrustEvent::RotationProofVerified,
        );
        assert!(latch);
    }

    #[test]
    fn trust_latch_survives_acknowledgment() {
        let (_, latch) =
            trust_transition(TrustState::PinViolation, true, TrustEvent::UserAcknowledged);
        assert!(latch);
    }

    #[test]
    fn trust_revocation_with_latch() {
        let (state, latch) =
            trust_transition(TrustState::Verified, true, TrustEvent::RevocationReceived);
        assert_eq!(state, TrustState::VerificationViolation);
        assert!(latch);
    }

    #[test]
    fn trust_revocation_without_latch() {
        let (state, latch) =
            trust_transition(TrustState::Pinned, false, TrustEvent::RevocationReceived);
        assert_eq!(state, TrustState::PinViolation);
        assert!(!latch);
    }

    #[test]
    fn trust_death_with_latch() {
        let (state, latch) =
            trust_transition(TrustState::Verified, true, TrustEvent::TombstoneReceived);
        assert_eq!(state, TrustState::VerificationViolation);
        assert!(latch);
    }

    #[test]
    fn trust_full_lifecycle() {
        let (state, latch) = trust_transition(TrustState::Pinned, false, TrustEvent::RootObserved);
        assert_eq!(state, TrustState::Pinned);
        assert!(!latch);

        let (state, latch) = trust_transition(state, latch, TrustEvent::VerificationSucceeded);
        assert_eq!(state, TrustState::Verified);
        assert!(latch);

        let (state, latch) = trust_transition(state, latch, TrustEvent::RotationProofVerified);
        assert_eq!(state, TrustState::Verified);
        assert!(latch);

        let (state, latch) = trust_transition(state, latch, TrustEvent::UnexplainedRootChange);
        assert_eq!(state, TrustState::VerificationViolation);
        assert!(latch);

        let (state, latch) = trust_transition(state, latch, TrustEvent::UserAcknowledged);
        assert_eq!(state, TrustState::Pinned);
        assert!(latch);
    }

    #[test]
    fn scoped_projection_deterministic() -> Result<(), crate::kappa::KappaParseError> {
        let anchor = Kappa::from_key("ed25519", b"test-key")?;
        let scope = Kappa::sha256(b"community-governance-key");
        let a = derive_scoped_projection(&anchor, &scope);
        let b = derive_scoped_projection(&anchor, &scope);
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn scoped_projection_different_scopes_differ() -> Result<(), crate::kappa::KappaParseError> {
        let anchor = Kappa::from_key("ed25519", b"test-key")?;
        let scope_a = Kappa::sha256(b"community-a");
        let scope_b = Kappa::sha256(b"community-b");
        let proj_a = derive_scoped_projection(&anchor, &scope_a);
        let proj_b = derive_scoped_projection(&anchor, &scope_b);
        assert_ne!(proj_a, proj_b);
        Ok(())
    }

    #[test]
    fn anchor_kappa_from_key_deterministic() -> Result<(), crate::kappa::KappaParseError> {
        let a = AnchorKappa::from_key("ed25519", b"pubkey")?;
        let b = AnchorKappa::from_key("ed25519", b"pubkey")?;
        assert_eq!(a, b);
        Ok(())
    }

    #[test]
    fn anchor_kappa_different_keys_differ() -> Result<(), crate::kappa::KappaParseError> {
        let a = AnchorKappa::from_key("ed25519", b"key-a")?;
        let b = AnchorKappa::from_key("ed25519", b"key-b")?;
        assert_ne!(a, b);
        Ok(())
    }

    #[test]
    fn anchor_kappa_serde_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let anchor = AnchorKappa::from_key("ed25519", b"serde-test")?;
        let json = serde_json::to_string(&anchor)?;
        let parsed: AnchorKappa = serde_json::from_str(&json)?;
        assert_eq!(anchor, parsed);
        Ok(())
    }

    #[test]
    fn anchor_kappa_rejects_non_sha256() -> Result<(), serde_json::Error> {
        let blake3_kappa = Kappa::blake3(b"not an anchor");
        let json = serde_json::to_string(&blake3_kappa)?;
        let result: Result<AnchorKappa, _> = serde_json::from_str(&json);
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn succession_chain_empty() -> Result<(), crate::kappa::KappaParseError> {
        let anchor = Kappa::from_key("ed25519", b"anchor")?;
        let chain = SuccessionChain::from_verified_links(anchor.clone(), vec![]);
        assert_eq!(*chain.anchor(), anchor);
        assert_eq!(*chain.head(), anchor);
        assert!(chain.is_empty());
        assert_eq!(chain.len(), 0);
        Ok(())
    }

    #[test]
    fn entity_kind_parse() {
        assert_eq!(EntityKind::parse("human"), Some(EntityKind::Human));
        assert_eq!(EntityKind::parse("bot"), Some(EntityKind::Automation));
        assert_eq!(EntityKind::parse("ai"), Some(EntityKind::ModelDriven));
        assert_eq!(EntityKind::parse("service"), Some(EntityKind::Service));
        assert_eq!(EntityKind::parse("unknown"), None);
    }

    #[test]
    fn entity_kind_as_str() {
        assert_eq!(EntityKind::Human.as_str(), "human");
        assert_eq!(EntityKind::ModelDriven.as_str(), "model-driven");
        assert_eq!(EntityKind::Service.as_str(), "service");
        assert_eq!(EntityKind::Automation.as_str(), "automation");
    }

    #[test]
    fn locator_kind_as_str() {
        assert_eq!(LocatorKind::Profile.as_str(), "profile");
        assert_eq!(LocatorKind::Route.as_str(), "route");
        assert_eq!(LocatorKind::Custom.as_str(), "custom");
    }

    #[test]
    fn rotation_epoch_origin() {
        assert_eq!(RotationEpoch::ORIGIN.value(), 0);
    }

    #[test]
    fn rotation_epoch_exhaustion_is_a_typed_error() {
        let result = RotationEpoch(u64::MAX).next();
        assert!(matches!(
            result,
            Err(crate::StoreError::CapacityExceeded(_))
        ));
    }

    #[test]
    fn rotation_epoch_wire_is_an_unsigned_integer() -> Result<(), dcbor::Error> {
        let encoded = CBOR::from(RotationEpoch(24));
        assert_eq!(encoded.to_cbor_data(), [0x18, 0x18]);
        assert_eq!(RotationEpoch::try_from(encoded)?, RotationEpoch(24));
        assert!(RotationEpoch::try_from(CBOR::from(-1i64)).is_err());
        assert!(RotationEpoch::try_from(CBOR::from("24")).is_err());
        Ok(())
    }

    #[test]
    fn rotation_epoch_next() -> Result<(), crate::StoreError> {
        let e = RotationEpoch::ORIGIN;
        assert_eq!(e.next()?.value(), 1);
        assert_eq!(e.next()?.next()?.value(), 2);
        Ok(())
    }

    #[test]
    fn rotation_epoch_ordering() {
        let a = RotationEpoch(5);
        let b = RotationEpoch(10);
        assert!(a < b);
    }

    #[test]
    fn rotation_epoch_display() {
        assert_eq!(RotationEpoch(42).to_string(), "epoch:42");
    }

    #[test]
    fn rotation_grace_within_window() {
        let grace = RotationGrace::default();
        let rotation_at = 1_000_000i64;
        let within = rotation_at + DEFAULT_ROTATION_GRACE_MS - 1;
        let outside = rotation_at + DEFAULT_ROTATION_GRACE_MS + 1;
        assert!(grace.is_within_grace(rotation_at, within));
        assert!(!grace.is_within_grace(rotation_at, outside));
    }

    #[test]
    fn rotation_grace_exact_boundary() {
        let grace = RotationGrace { grace_ms: 1000 };
        assert!(grace.is_within_grace(100, 1099));
        assert!(!grace.is_within_grace(100, 1100));
    }

    #[test]
    fn session_anchor_symmetric() -> Result<(), crate::StoreError> {
        let a = Kappa::from_key("ed25519", b"key-a")?;
        let b = Kappa::from_key("ed25519", b"key-b")?;
        let ab = derive_session_anchor(&a, &b)?;
        let ba = derive_session_anchor(&b, &a)?;
        assert_eq!(ab, ba);
        Ok(())
    }

    #[test]
    fn session_anchor_distinct_pairs() -> Result<(), crate::StoreError> {
        let a = Kappa::from_key("ed25519", b"key-a")?;
        let b = Kappa::from_key("ed25519", b"key-b")?;
        let c = Kappa::from_key("ed25519", b"key-c")?;
        let ab = derive_session_anchor(&a, &b)?;
        let ac = derive_session_anchor(&a, &c)?;
        let bc = derive_session_anchor(&b, &c)?;
        assert_ne!(ab, ac);
        assert_ne!(ab, bc);
        assert_ne!(ac, bc);
        Ok(())
    }

    #[test]
    fn session_anchor_self_rejected() -> Result<(), crate::kappa::KappaParseError> {
        let a = Kappa::from_key("ed25519", b"key-a")?;
        assert!(derive_session_anchor(&a, &a).is_err());
        Ok(())
    }

    #[test]
    fn session_anchor_deterministic() -> Result<(), crate::StoreError> {
        let a = Kappa::from_key("ed25519", b"key-a")?;
        let b = Kappa::from_key("ed25519", b"key-b")?;
        let s1 = derive_session_anchor(&a, &b)?;
        let s2 = derive_session_anchor(&a, &b)?;
        assert_eq!(s1, s2);
        Ok(())
    }

    #[test]
    fn session_anchor_is_32_bytes() -> Result<(), crate::StoreError> {
        let a = Kappa::from_key("ed25519", b"key-a")?;
        let b = Kappa::from_key("ed25519", b"key-b")?;
        let s = derive_session_anchor(&a, &b)?;
        assert_eq!(s.as_bytes().len(), 32);
        Ok(())
    }

    #[test]
    fn session_anchor_hex() -> Result<(), crate::StoreError> {
        let a = Kappa::from_key("ed25519", b"key-a")?;
        let b = Kappa::from_key("ed25519", b"key-b")?;
        let s = derive_session_anchor(&a, &b)?;
        assert_eq!(s.to_hex().len(), 64);
        Ok(())
    }

    #[test]
    fn identity_status_change_construction() -> Result<(), crate::kappa::KappaParseError> {
        let anchor = Kappa::from_key("ed25519", b"test")?;
        let change = IdentityStatusChange {
            anchor,
            old_state: TrustState::Pinned,
            new_state: TrustState::Verified,
            event: TrustEvent::VerificationSucceeded,
            timestamp_ms: 1000,
        };
        assert_eq!(change.old_state, TrustState::Pinned);
        assert_eq!(change.new_state, TrustState::Verified);
        Ok(())
    }
}
