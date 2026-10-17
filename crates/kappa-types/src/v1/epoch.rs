use dcbor::prelude::*;

use crate::kappa::Kappa;

/// Canonical evidence for a namespace-owned sequence reservation.
#[derive(Debug, Clone, CBORCodable)]
pub struct SequenceRecord {
    #[cbor(n = 0)]
    pub namespace_id: Vec<u8>,
    #[cbor(n = 1)]
    pub name: String,
    #[cbor(n = 2)]
    pub value: u64,
}

/// Canonical evidence for a namespace metadata change. `value` is `None`
/// when the key was deleted.
#[derive(Debug, Clone, CBORCodable)]
pub struct MetadataRecord {
    #[cbor(n = 0)]
    pub namespace_id: Vec<u8>,
    #[cbor(n = 1)]
    pub key: String,
    #[cbor(n = 2)]
    pub value: Option<Vec<u8>>,
}

/// A single mutation recorded in an epoch.
///
/// The kappa identifies the object that was mutated (the content kappa
/// a tag points to, the edge's own kappa, the assertion's kappa).
/// The op discriminates what kind of primitive was mutated for
/// forensic-grade audit trails. The context carries the human-readable
/// identifier (tag name for TagSet/TagDelete, edge relation for
/// EdgePut/EdgeDelete, None for identity mutations where the kappa
/// IS the identifier).
///
/// CBOR key assignments (PERMANENT):
///   0: op, 1: kappa, 2: `timestamp_ms`, 3: context
#[derive(Debug, Clone, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct EpochMutation {
    #[cbor(n = 0)]
    pub op: MutationOp,
    #[cbor(n = 1)]
    pub kappa: Kappa,
    #[cbor(n = 2)]
    pub timestamp_ms: i64,
    /// Human-readable context for the mutation.
    /// TagSet/TagDelete: the tag name.
    /// EdgePut/EdgeDelete: the edge relation `as_str()`.
    /// Identity mutations: None (the kappa is the identifier).
    #[cbor(n = 3)]
    pub context: Option<String>,
}

/// The operation that produced this mutation.
///
/// Discriminates what kind of primitive was mutated. An auditor
/// examining epoch 4,182 needs to know whether the mutation was
/// a tag set, an edge creation, or an assertion publication.
///
/// 16 variants at CBOR discriminants 0-15. Discriminants 16+ are
/// unassigned. Every variant has at least one store method that
/// records it.
///
/// CBOR discriminants (PERMANENT): 0-15
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum MutationOp {
    #[cbor(n = 0)]
    TagSet,
    #[cbor(n = 1)]
    TagDelete,
    #[cbor(n = 2)]
    EdgePut,
    #[cbor(n = 3)]
    EdgeDelete,
    #[cbor(n = 4)]
    AssertionPublish,
    #[cbor(n = 5)]
    RevocationPublish,
    #[cbor(n = 6)]
    AnchorOrigin,
    #[cbor(n = 7)]
    OperationPublish,
    #[cbor(n = 8)]
    NamespaceUpdate,
    #[cbor(n = 9)]
    SequenceUpdate,
    /// A namespace metadata key was set or deleted. The kappa identifies a
    /// `MetadataRecord`; the context is the key.
    #[cbor(n = 10)]
    MetadataUpdate,
    /// Chunked content was installed. The kappa identifies a
    /// `ContentCommitment` binding the content identity to its chunk size
    /// and chunk digest root; the context is None.
    #[cbor(n = 11)]
    ContentPublish,
    /// Verified bytes were bound to an identity under another digest axis.
    /// The kappa identifies a `ContentAlias` naming the alias, its target,
    /// and their common length; the context is None. Distinct from
    /// `ContentPublish` so every consumer of that operation decodes only
    /// `ContentCommitment` evidence.
    #[cbor(n = 12)]
    ContentAlias,
    /// A composite representation was installed. The kappa identifies a
    /// `ContentComposition` naming the composite identity, its ordered
    /// components with their lengths, and the total; the context is None.
    /// The binding a composite's retention of its components rests on is
    /// therefore history, not only a store index.
    #[cbor(n = 13)]
    ContentCompose,
    /// The namespace retired its admitted representation of the identity
    /// the kappa names; the context is None. The identity itself is the
    /// evidence: a retirement names no record. Projections settled from
    /// the ledger (catalog, allocation ownership) release the namespace's
    /// claim on it; the physical allocation goes only when every owner
    /// released and nothing protects it.
    #[cbor(n = 14)]
    ContentRetire,
    /// A record the execution produced was installed as content of the
    /// namespace (`ExecutionWrites::blob_put`: a repository object, a
    /// checkpoint, a signed record). The kappa is the record's content
    /// identity and the record is its own evidence; the context is None.
    /// Recorded only when the namespace did not already admit the
    /// identity, so the ledger names every admission the namespace's
    /// catalog and allocation ownership are settled from.
    #[cbor(n = 15)]
    RecordPublish,
}
