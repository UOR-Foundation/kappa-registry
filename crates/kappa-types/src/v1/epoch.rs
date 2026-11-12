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
/// The kappa identifies the complete canonical evidence record of the
/// transition (see [`MutationOp`]); the subject is decoded from that
/// evidence, never from the kappa. The op discriminates the transition.
/// The context carries the scope the transition derives (tag name, edge
/// relation, metadata key, sequence name, anchor scope); it is derived
/// from the evidence and checked against it on decode.
///
/// CBOR key assignments (PERMANENT):
///   0: op, 1: kappa, 2: `timestamp_ms`, 3: context
#[derive(Debug, Clone, CBORCodable, CBORBoundedDecodable, serde::Serialize, serde::Deserialize)]
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
/// Discriminates what kind of primitive was mutated. The kappa identifies
/// the canonical evidence record the epoch retains for that transition.
/// Independent replay fetches the evidence by its identity and
/// reconstructs state from every field it carries.
///
/// Every variant's kappa names the complete canonical record of the
/// transition. The context carries the human-readable locator (the tag
/// name, the edge relation, the metadata key, the sequence name).
///
/// CBOR discriminants (PERMANENT): 0-15
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    CBORCodable,
    CBORBoundedDecodable,
    serde::Serialize,
    serde::Deserialize,
)]
#[non_exhaustive]
pub enum MutationOp {
    /// A tag was set or updated. The kappa identifies the canonical
    /// `TagEntry` evidence record (name, target, version, timestamps,
    /// symref); the context is the tag name.
    #[cbor(n = 0)]
    TagSet,
    /// A tag was deleted. The kappa identifies the canonical `TagEntry`
    /// evidence record of the removed tag; the context is the tag name.
    #[cbor(n = 1)]
    TagDelete,
    /// An edge was admitted. The kappa identifies the canonical
    /// `EdgeInput` evidence record; the context is the relation.
    #[cbor(n = 2)]
    EdgePut,
    /// An edge was removed from membership. The kappa identifies the
    /// canonical `EdgeInput` evidence record; the context is the
    /// relation.
    #[cbor(n = 3)]
    EdgeDelete,
    /// An identity assertion was published. The kappa identifies the
    /// canonical `IdentityAssertion` record.
    #[cbor(n = 4)]
    AssertionPublish,
    /// A revocation was published. The kappa identifies the canonical
    /// `Revocation` record.
    #[cbor(n = 5)]
    RevocationPublish,
    /// An identity record was changed. The kappa identifies the canonical
    /// evidence record of the changed row (binding, handle, device,
    /// prekey, locator, commitment, succession, or watermark); the
    /// context names the family and scope.
    #[cbor(n = 6)]
    AnchorOrigin,
    /// An operation receipt was published. The kappa identifies the
    /// canonical `OperationReceipt` record.
    #[cbor(n = 7)]
    OperationPublish,
    /// The namespace record was updated. The kappa identifies the
    /// canonical `NamespaceInfo` record.
    #[cbor(n = 8)]
    NamespaceUpdate,
    /// A sequence counter advanced. The kappa identifies the canonical
    /// `SequenceRecord`; the context is the sequence name.
    #[cbor(n = 9)]
    SequenceUpdate,
    /// A namespace or blob metadata key was set or deleted. The kappa
    /// identifies the canonical `content::MetadataTransition` (namespace
    /// instance, subject, key, value or deletion); the context is the key.
    #[cbor(n = 10)]
    MetadataUpdate,
    /// Content was admitted from verified bytes or chunked preparation.
    /// The kappa identifies the canonical `ContentAdmissionRecord` whose
    /// evidence is verified bytes or a `ContentCommitment`.
    #[cbor(n = 11)]
    ContentPublish,
    /// Content was admitted as an alias of an identity under another
    /// digest axis. The kappa identifies the canonical
    /// `ContentAdmissionRecord` whose evidence is a `ContentAlias`.
    #[cbor(n = 12)]
    ContentAlias,
    /// Content was admitted as a composition. The kappa identifies the
    /// canonical `ContentAdmissionRecord` whose evidence is a
    /// `ContentComposition`.
    #[cbor(n = 13)]
    ContentCompose,
    /// The namespace retired a logical admission. The kappa identifies
    /// the canonical `ContentRetirementRecord` naming the exact admission
    /// removed; it stays decodable after the payload is gone.
    #[cbor(n = 14)]
    ContentRetire,
    /// An explicit record was admitted as content of the namespace. The
    /// kappa identifies the canonical `ContentAdmissionRecord` (verified
    /// bytes evidence); the payload identity is inside that record.
    #[cbor(n = 15)]
    RecordPublish,
}
