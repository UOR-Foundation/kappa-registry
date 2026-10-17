//! Mutation events: the delivery form of a published epoch's ledger.
//!
//! Every event is derived from authenticated history. Its coordinates are
//! the epoch that published it, its position in that epoch's ledger, and
//! that epoch's signed root, so an event id names exactly one mutation of
//! one namespace history and a consumer resumes from it through
//! [`crate::event_stream`] without any process-local sequence. Wakeups
//! come from [`crate::event_feed`]; they are hints to reread history, never
//! the events themselves.

use kappa_store::clock::ClockMs;
use kappa_store::kappa::Kappa;
use kappa_store::{EpochMutation, MutationOp, StoreError};

/// Type of mutation that produced an event.
///
/// One variant per `kappa_types::MutationOp`: every mutation committed by
/// an epoch ledger produces a `MutationEvent` with the corresponding
/// operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationEventOp {
    TagSet,
    TagDelete,
    EdgePut,
    EdgeDelete,
    AssertionPublish,
    RevocationPublish,
    AnchorOrigin,
    OperationPublish,
    NamespaceUpdate,
    SequenceUpdate,
    MetadataUpdate,
    ContentPublish,
    ContentAlias,
    ContentCompose,
    ContentRetire,
    RecordPublish,
}

impl MutationEventOp {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::TagSet => "tag_set",
            Self::TagDelete => "tag_delete",
            Self::EdgePut => "edge_put",
            Self::EdgeDelete => "edge_delete",
            Self::AssertionPublish => "assertion_publish",
            Self::RevocationPublish => "revocation_publish",
            Self::AnchorOrigin => "anchor_origin",
            Self::OperationPublish => "operation_publish",
            Self::NamespaceUpdate => "namespace_update",
            Self::SequenceUpdate => "sequence_update",
            Self::MetadataUpdate => "metadata_update",
            Self::ContentPublish => "content_publish",
            Self::ContentAlias => "content_alias",
            Self::ContentCompose => "content_compose",
            Self::ContentRetire => "content_retire",
            Self::RecordPublish => "record_publish",
        }
    }
}

impl TryFrom<MutationOp> for MutationEventOp {
    type Error = StoreError;

    fn try_from(op: MutationOp) -> Result<Self, Self::Error> {
        Ok(match op {
            MutationOp::TagSet => Self::TagSet,
            MutationOp::TagDelete => Self::TagDelete,
            MutationOp::EdgePut => Self::EdgePut,
            MutationOp::EdgeDelete => Self::EdgeDelete,
            MutationOp::AssertionPublish => Self::AssertionPublish,
            MutationOp::RevocationPublish => Self::RevocationPublish,
            MutationOp::AnchorOrigin => Self::AnchorOrigin,
            MutationOp::OperationPublish => Self::OperationPublish,
            MutationOp::NamespaceUpdate => Self::NamespaceUpdate,
            MutationOp::SequenceUpdate => Self::SequenceUpdate,
            MutationOp::MetadataUpdate => Self::MetadataUpdate,
            MutationOp::ContentPublish => Self::ContentPublish,
            MutationOp::ContentAlias => Self::ContentAlias,
            MutationOp::ContentCompose => Self::ContentCompose,
            MutationOp::ContentRetire => Self::ContentRetire,
            MutationOp::RecordPublish => Self::RecordPublish,
            other => {
                return Err(StoreError::Internal(format!(
                    "mutation operation {other:?} has no event form"
                )));
            }
        })
    }
}

/// One mutation of one published epoch.
///
/// `index` is the mutation's position in the epoch's ledger and `root` the
/// epoch's signed root; with `epoch` they are the event's coordinates in
/// the namespace's authenticated history ([`MutationEvent::id`]).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct MutationEvent {
    pub namespace: String,
    pub name: String,
    pub value: Option<String>,
    pub prev_value: Option<String>,
    pub epoch: u64,
    pub index: u64,
    pub root: String,
    pub mtime_ms: u64,
    pub operation: MutationEventOp,
}

impl MutationEvent {
    /// `epoch.consumed.root`: the history position after this event, where
    /// `consumed` counts the epoch's mutations up to and including it.
    pub fn id(&self) -> String {
        format!(
            "{}.{}.{}",
            self.epoch,
            self.index.saturating_add(1),
            self.root
        )
    }
}

/// Events for every mutation of the epoch `epoch` whose signed root is
/// `root`, in ledger order.
///
/// `name` is the mutation's context (tag name, relation, sequence or
/// metadata key) or, when it has none, the mutated identity. A deletion
/// carries the removed identity as `prev_value`.
pub fn events_from_ledger(
    namespace: &str,
    epoch: u64,
    root: &Kappa,
    mutations: &[EpochMutation],
) -> Result<Vec<MutationEvent>, StoreError> {
    let root = root.to_string();
    mutations
        .iter()
        .zip(0u64..)
        .map(|(mutation, index)| {
            let operation = MutationEventOp::try_from(mutation.op)?;
            let identity = mutation.kappa.to_string();
            let removed = matches!(
                operation,
                MutationEventOp::TagDelete | MutationEventOp::EdgeDelete
            );
            Ok(MutationEvent {
                namespace: namespace.to_string(),
                name: mutation.context.clone().unwrap_or_else(|| identity.clone()),
                value: (!removed).then(|| identity.clone()),
                prev_value: removed.then_some(identity),
                epoch,
                index,
                root: root.clone(),
                mtime_ms: ClockMs::from_raw(mutation.timestamp_ms).physical_ms(),
                operation,
            })
        })
        .collect()
}

#[cfg(test)]
#[path = "event_contract_tests.rs"]
mod event_contract_tests;
