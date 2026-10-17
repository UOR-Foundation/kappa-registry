// kappa-store: read sub-traits, the execution contract through which every
// published mutation enters, and composed operations over both.
//
// Types are owned by kappa-types and re-exported here for convenience.
// Implementations are in kappa-store-memory and kappa-store-redb.
// This crate has NO store implementation code.

pub mod blob_admission;
pub mod delegation_chain;
mod delegation_policy;
pub mod epoch_authority;
pub mod epoch_publication;
pub mod execution;
pub mod gc;
pub mod governed_retirement;
pub mod graph;
pub mod identity_ops;
pub mod identity_scope;
pub mod meta_index;
pub mod operation;
pub mod replay;
pub mod resource;
pub mod succession_index;
pub mod succession_ops;
pub mod tag_resolution;
pub mod tag_update;
pub mod time;
pub mod traits;
pub mod version_ops;

pub use kappa_types::*;

pub use epoch_authority::{
    Activation, AuthorityKey, AuthorityRotationError, AuthorityTransition, EpochAuthority,
    WitnessEvidence, sign_witness, succession_identity, witness_standing,
};
pub use execution::{
    CompositionEvidence, ContentIdentity, ContentPreparation, Execution, ExecutionReads,
    ExecutionStore, ExecutionWrites, OperationAdmission, PreparationBounds, PreparedContent,
    Published, Retirement, absent, namespace_ensure, publish_if_changed,
};
pub use identity_ops::{
    ResolutionResult, assert_double_entry, assertion_create, default_handle_grace_ms,
    derive_audience_label, handle_claim, handle_update, resolve_all, resolve_all_filtered,
    resolve_at, resolve_at_filtered,
};
pub use meta_index::{blob_meta_put_indexed, meta_query};
pub use replay::{NamespaceState, replay_authenticated, replay_to};
pub use succession_ops::{
    VerifiedSuccession, default_watermark_for_succession, succession_chain, succession_put,
    succession_put_with_default_watermark, succession_resolve, verify_succession_chain,
};
pub use traits::blob::BlobReader;
pub use traits::namespace::NamespaceInfo;
pub use traits::{
    BlobStore, EdgeStore, EpochStore, IdentityStore, IndexRepair, KappaStore, MaintenanceStore,
    NamespaceStore, Reclamation, SequenceStore, TagStore,
};
