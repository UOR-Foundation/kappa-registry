// kappa-types: content-addressed types for kappa-registry.
//
// This crate owns wire types. Cryptographic evidence lives in kappa-crypto.
// Protocol modules, kappa-handler, kappa-crypto, and SDKs
// depend on this crate for types. No IO, no async, no HTTP.

pub mod authorization;
pub mod availability;
pub mod axis;
pub mod bundle;
pub mod canonical;
pub mod chunks;
pub mod clock;
pub mod content;
pub mod coordinator;
pub mod counter;
pub mod delegation;
pub mod delta;
pub mod edge;
pub mod epoch;
pub mod epoch_root;
pub mod error;
pub mod identity;
pub mod kappa;
pub mod kappa_streaming;
pub mod merkle;
pub mod merkle_index;
pub mod namespace;
pub mod offload;
pub mod operation;
pub mod page;
pub mod path;
pub mod resource;
pub mod retirement;
pub mod retirement_request;
pub mod rotation_witness;
pub mod sequence;
pub mod sha256;
pub mod sha3_256;
pub mod sha512;
pub mod signed;
pub mod state_digest;
pub mod tag;
pub mod threshold;
pub mod time_attestation;
pub mod transport;
pub mod upload;
pub mod verified;
pub mod version;
pub mod versioning;
mod wire_map;
pub mod witness;

// -- Top-level re-exports for ergonomic use -----------------------------------

pub use axis::Axis;
pub use canonical::{CanonicalError, canonical_bytes, from_canonical};
pub use clock::ClockMs;
pub use content::ContentCommitment;
pub use delegation::{
    Capability, CapabilitySet, DELEGATION_CHAIN_MAX_DEPTH, DelegationScope,
    DelegationScopeSignable, EffectiveAuthority,
};
pub use edge::{
    BuiltinRelation, Direction, Edge, EdgeInput, EdgeQuery, EdgeRelation, SemanticRelation,
    semantic,
};
pub use epoch::{EpochMutation, MutationOp};
pub use epoch_root::{EpochRoot, EpochRootData, EpochRootError, EpochRootInput};
pub use error::StoreError;
pub use identity::{
    AbsenceProof, AnchorKappa, BindingMethod, DEFAULT_ROTATION_GRACE_MS, DegradeReason,
    DeviceBinding, EntityKind, HandleRecord, IdentityAssertion, IdentityBinding,
    IdentityStatusChange, IdentityTombstone, LocatorEntry, LocatorKind, LocatorRecord, PeerRecord,
    PrekeyBinding, ProbeResult, ProjectionProof, ProofSystem, Revocation, RevocationCommitment,
    RevocationReason, RotationEpoch, RotationGrace, SUCCESSION_CHAIN_MAX, ScopedProjection,
    SessionAnchor, Succession, SuccessionChain, SuccessionReason, TimeSourceProtocol, TrustEvent,
    TrustLevel, TrustPosition, TrustState, Watermark, WatermarkReason, derive_scoped_projection,
    derive_session_anchor, trust_transition,
};
pub use kappa::{
    FormattedKappa, Kappa, KappaParseError, kappa_from_bytes, kappa_from_value, sha256_raw,
    verify_kappa,
};
pub use kappa_streaming::{
    IncrementalHasher, streaming_compute_into, streaming_compute_kappa, streaming_compute_multi,
};
pub use namespace::{InvalidProtocolId, NamespaceRef, ProtocolId};
pub use operation::OperationReceipt;
pub use page::{MAX_ALIASES_PER_NAMESPACE, NamespaceFilter, Page, PageRequest};
pub use resource::{
    MemberCoordinate, ResourceAnchor, ResourceCompletion, ResourceHead, ResourceKind,
    ResourcePhase, ResourceSelection, SelectedMember,
};
pub use retirement::{Disposition, ObservedHead, RETIREMENT_DECISION_VERSION, RetirementDecision};
pub use retirement_request::RetirementRequest;
pub use rotation_witness::{
    ActivationDomain, ROTATION_WITNESS_BASIS, ROTATION_WITNESS_FACET, RotationWitness,
};
pub use sequence::SequenceValue;
pub use signed::{SignedPayload, content_types};
pub use state_digest::{STATE_DIGEST_ALGORITHM, StateDigest};
pub use tag::{TagEntry, TagUpdate};
pub use threshold::ThresholdRound;
pub use time_attestation::TimeAttestation;
pub use upload::{IngestResult, PartReceipt, UploadId};
pub use verified::{StreamingVerificationProof, VerifiedContent};
pub use versioning::{DeleteResult, VersionEntry, VersioningState};
