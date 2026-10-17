pub mod blob;
pub mod edge;
pub mod epoch;
pub mod identity;
pub mod maintenance;
pub mod namespace;
pub mod sequence;
pub mod tag;

pub use blob::BlobStore;
pub use edge::EdgeStore;
pub use epoch::EpochStore;
pub use identity::IdentityStore;
pub use maintenance::{IndexRepair, MaintenanceStore, Reclamation};
pub use namespace::{NamespaceInfo, NamespaceStore};
pub use sequence::SequenceStore;
pub use tag::TagStore;

/// Supertrait composing all sub-traits.
///
/// Protocol modules SHOULD NOT bound on this. Use the narrowest
/// sub-trait set the handler actually calls.
///
/// Each sub-trait has raw typed methods operating on native Rust
/// types. No serialization layer. Both `InMemoryStore` and
/// `PersistentStore` implement every method natively.
///
/// Business logic (succession chain walk, binding upsert, watermark
/// side effects, delegation depth check, version entry creation with
/// `DerivedFrom` edges) lives in free functions that compose sub-trait
/// methods. Written once, used by both backends.
/// Versioning logic is in `version_ops.rs` as free functions over
/// `TagStore` + `BlobStore` + `NamespaceStore` + `EdgeStore`.
/// No `VersionStore` trait on the supertrait.
///
/// Authenticated mutation enters through `ExecutionStore`: an execution owns
/// its private writes and publishes them with their ledger and signed epoch
/// as one unit. Content is prepared through `ContentPreparation` and
/// installed by an execution; staged resources are composed from these
/// primitives in `crate::resource`. There is no upload, multipart, or
/// staging-transaction store contract. Physical residue is settled through
/// `MaintenanceStore`.
pub trait KappaStore:
    BlobStore
    + TagStore
    + EdgeStore
    + EpochStore
    + SequenceStore
    + NamespaceStore
    + IdentityStore
    + MaintenanceStore
    + crate::execution::ExecutionStore
    + Send
    + Sync
{
}

impl<T> KappaStore for T where
    T: BlobStore
        + TagStore
        + EdgeStore
        + EpochStore
        + SequenceStore
        + NamespaceStore
        + IdentityStore
        + MaintenanceStore
        + crate::execution::ExecutionStore
        + Send
        + Sync
{
}
