//! Canonical interpretation of record-naming mutations.
//!
//! Writers and evidence consumers use the same closed record variants. The
//! mutation identity, context and index effect are derived here, never supplied
//! independently. This module does not grant authorization or commit a backend
//! transaction. Its output must remain owned by the execution through publication.

use kappa_types::authorization::{CredentialTransition, SessionTransition, TransitionKind};
use kappa_types::canonical::{canonical_bytes, from_canonical};
use kappa_types::epoch::{EpochMutation, MutationOp, SequenceRecord};
use kappa_types::identity::{IdentityAssertion, Revocation, Succession, TrustPosition, Watermark};
use kappa_types::state_index::Change;
use kappa_types::{
    ClockMs, EdgeInput, Kappa, LogicalIncarnation, NamespaceRef, StoreError, TagEntry,
    VerifiedContent,
};

use crate::traits::namespace::NamespaceInfo;

use crate::identity_scope::AnchorScope;

mod member;
pub use member::MemberTransition;

mod payload;
pub use payload::{
    InstallationPayload, PreparedResource, PreparedWrite, PrivatePayload, check_admitted_bytes,
    check_credential_secrets, check_session_metadata,
};

/// The namespace instance a transition belongs to. A live execution supplies
/// its protected current instance; replay, settlement and custody supply the
/// instance their authenticated historical context names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionDomain {
    namespace: [u8; 16],
    incarnation: LogicalIncarnation,
}

impl TransitionDomain {
    pub const fn new(namespace: [u8; 16], incarnation: LogicalIncarnation) -> Self {
        Self {
            namespace,
            incarnation,
        }
    }

    pub const fn namespace(&self) -> &[u8; 16] {
        &self.namespace
    }

    pub const fn incarnation(&self) -> LogicalIncarnation {
        self.incarnation
    }

    /// Refuse unless `(namespace, incarnation)` is exactly this instance.
    pub fn check(
        &self,
        namespace: &NamespaceRef,
        incarnation: &LogicalIncarnation,
    ) -> Result<(), StoreError> {
        if &self.namespace != namespace.id() || &self.incarnation != incarnation {
            return Err(rejected("transition belongs to another namespace instance"));
        }
        Ok(())
    }

    /// Whether `namespace` and `incarnation`, as a record carries them, name
    /// exactly this instance.
    fn names(&self, namespace: &[u8], incarnation: &[u8]) -> bool {
        namespace == self.namespace.as_slice() && self.incarnation.names(incarnation)
    }
}

/// A complete domain record and its operation. Authorization deletes retain
/// their latest transition in the authenticated index; membership deletes do not.
pub enum RecordTransition {
    Member(MemberTransition),
    TagSet(TagEntry),
    TagDelete(TagEntry),
    EdgePut(EdgeInput),
    EdgeDelete(EdgeInput),
    Assertion(IdentityAssertion),
    Revocation(Revocation),
    Watermark(Watermark),
    Succession(Succession),
    Session(SessionTransition),
    Credential(CredentialTransition),
    Trust(TrustPosition),
    /// Namespace or blob metadata set/delete. Replaces the old
    /// `MetadataRecord`; carries explicit subject kind.
    Metadata(kappa_types::MetadataTransition),
    Sequence(SequenceRecord),
    NamespaceUpdate(NamespaceInfo),
    /// Verified-bytes or chunked content admission.
    ContentPublish(kappa_types::ContentAdmissionRecord),
    /// Alias content admission.
    ContentAlias(kappa_types::ContentAdmissionRecord),
    /// Composition content admission.
    ContentCompose(kappa_types::ContentAdmissionRecord),
    /// Explicit record admission.
    RecordPublish(kappa_types::ContentAdmissionRecord),
    /// Retirement of a prior logical admission.
    ContentRetire(kappa_types::ContentRetirementRecord),
    /// An operation receipt published before sealing.
    OperationPublish(kappa_types::OperationReceipt),
}

/// Evidence, semantic record, ledger mutation and current-index effect with
/// checked correspondence. There is no constructor accepting independent effects.
pub struct PreparedTransition {
    domain: TransitionDomain,
    record: RecordTransition,
    evidence: VerifiedContent,
    mutation: EpochMutation,
    change: Change,
}

impl PreparedTransition {
    /// Bind an already prepared canonical record to its semantic interpretation.
    /// Rejects mismatched bytes before the result can be applied to a backend.
    /// Preparation/decoding resource admission belongs to the execution's bounded
    /// evidence codec; this constructor does not replace that admission boundary.
    pub fn bind(
        domain: TransitionDomain,
        record: RecordTransition,
        evidence: VerifiedContent,
        now: ClockMs,
    ) -> Result<Self, StoreError> {
        record.validate()?;
        let embedded_namespace: Option<&[u8]> = match &record {
            RecordTransition::Metadata(v) => Some(v.namespace()),
            RecordTransition::Sequence(v) => Some(&v.namespace_id),
            RecordTransition::NamespaceUpdate(v) => Some(v.ns.id()),
            RecordTransition::OperationPublish(v) => Some(v.namespace_id()),
            _ => None,
        };
        if embedded_namespace.is_some_and(|id| id != domain.namespace.as_slice()) {
            return Err(rejected("record names a different namespace"));
        }
        let admission = match &record {
            RecordTransition::ContentPublish(v)
            | RecordTransition::ContentAlias(v)
            | RecordTransition::ContentCompose(v)
            | RecordTransition::RecordPublish(v) => Some(v.admission()),
            RecordTransition::ContentRetire(v) => Some(v.removed()),
            _ => None,
        };
        if admission.is_some_and(|v| !domain.names(v.namespace(), v.incarnation()))
            || matches!(&record, RecordTransition::Metadata(v) if !domain.incarnation.names(v.incarnation()))
            || matches!(&record, RecordTransition::OperationPublish(v) if !domain.incarnation.names(v.incarnation()))
        {
            return Err(rejected("record names a different namespace instance"));
        }
        if record.canonical_bytes() != evidence.content() {
            return Err(rejected(
                "transition record differs from its prepared evidence",
            ));
        }
        let (op, context) = record.operation();
        let mutation = EpochMutation {
            op,
            kappa: evidence.kappa().clone(),
            timestamp_ms: now.as_i64(),
            context,
        };
        let change = record.index_change(&evidence)?;
        Ok(Self {
            domain,
            record,
            evidence,
            mutation,
            change,
        })
    }

    /// Interpret fetched, identity-verified evidence at a ledger boundary.
    /// Scope and operation must match the record; a latest mutable row is never
    /// substituted for the evidence named by this mutation.
    pub fn decode(
        domain: TransitionDomain,
        mutation: &EpochMutation,
        evidence: VerifiedContent,
    ) -> Result<Self, StoreError> {
        if evidence.kappa() != &mutation.kappa {
            return Err(rejected("mutation names different transition evidence"));
        }
        let bytes = evidence.content();
        let record = match mutation.op {
            MutationOp::TagSet => RecordTransition::TagSet(from_canonical(bytes)?),
            MutationOp::TagDelete => RecordTransition::TagDelete(from_canonical(bytes)?),
            MutationOp::EdgePut => RecordTransition::EdgePut(from_canonical(bytes)?),
            MutationOp::EdgeDelete => RecordTransition::EdgeDelete(from_canonical(bytes)?),
            MutationOp::AssertionPublish => RecordTransition::Assertion(from_canonical(bytes)?),
            MutationOp::RevocationPublish => RecordTransition::Revocation(from_canonical(bytes)?),
            MutationOp::MetadataUpdate => RecordTransition::Metadata(from_canonical(bytes)?),
            MutationOp::SequenceUpdate => RecordTransition::Sequence(from_canonical(bytes)?),
            MutationOp::NamespaceUpdate => {
                RecordTransition::NamespaceUpdate(from_canonical(bytes)?)
            }
            MutationOp::ContentPublish => RecordTransition::ContentPublish(from_canonical(bytes)?),
            MutationOp::ContentAlias => RecordTransition::ContentAlias(from_canonical(bytes)?),
            MutationOp::ContentCompose => RecordTransition::ContentCompose(from_canonical(bytes)?),
            MutationOp::RecordPublish => RecordTransition::RecordPublish(from_canonical(bytes)?),
            MutationOp::ContentRetire => RecordTransition::ContentRetire(from_canonical(bytes)?),
            MutationOp::OperationPublish => {
                RecordTransition::OperationPublish(from_canonical(bytes)?)
            }
            MutationOp::AnchorOrigin => match AnchorScope::parse(mutation.context.as_deref())? {
                AnchorScope::Watermark => RecordTransition::Watermark(from_canonical(bytes)?),
                AnchorScope::Succession => RecordTransition::Succession(from_canonical(bytes)?),
                AnchorScope::Session { .. } => RecordTransition::Session(from_canonical(bytes)?),
                AnchorScope::Credential { .. } => {
                    RecordTransition::Credential(from_canonical(bytes)?)
                }
                AnchorScope::Trust => RecordTransition::Trust(from_canonical(bytes)?),
                AnchorScope::Binding { .. }
                | AnchorScope::Handle { .. }
                | AnchorScope::Device
                | AnchorScope::Prekey
                | AnchorScope::Locator
                | AnchorScope::Commitment => RecordTransition::Member(from_canonical(bytes)?),
            },
            _ => return Err(rejected("operation is not a supported record transition")),
        };
        let prepared = Self::bind(
            domain,
            record,
            evidence,
            ClockMs::from_raw(mutation.timestamp_ms),
        )?;
        if prepared.mutation.op != mutation.op || prepared.mutation.context != mutation.context {
            return Err(rejected("transition evidence disagrees with ledger scope"));
        }
        Ok(prepared)
    }

    pub const fn record(&self) -> &RecordTransition {
        &self.record
    }
    pub const fn domain(&self) -> TransitionDomain {
        self.domain
    }
    pub const fn evidence(&self) -> &VerifiedContent {
        &self.evidence
    }
    pub const fn mutation(&self) -> &EpochMutation {
        &self.mutation
    }
    pub const fn index_change(&self) -> Change {
        self.change
    }

    /// Consume the bundle at the backend application boundary. The evidence
    /// remains owned and must be installed and retained with the mutation.
    pub fn into_parts(
        self,
        namespace: &NamespaceRef,
        incarnation: &LogicalIncarnation,
    ) -> Result<(RecordTransition, VerifiedContent, EpochMutation, Change), StoreError> {
        self.domain.check(namespace, incarnation)?;
        Ok((self.record, self.evidence, self.mutation, self.change))
    }
}

impl RecordTransition {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        match self {
            Self::Member(v) => canonical_bytes(v),
            Self::TagSet(v) | Self::TagDelete(v) => canonical_bytes(v),
            Self::EdgePut(v) | Self::EdgeDelete(v) => canonical_bytes(v),
            Self::Assertion(v) => canonical_bytes(v),
            Self::Revocation(v) => canonical_bytes(v),
            Self::Watermark(v) => canonical_bytes(v),
            Self::Succession(v) => canonical_bytes(v),
            Self::Session(v) => canonical_bytes(v),
            Self::Credential(v) => canonical_bytes(v),
            Self::Trust(v) => canonical_bytes(v),
            Self::Metadata(v) => canonical_bytes(v),
            Self::Sequence(v) => canonical_bytes(v),
            Self::NamespaceUpdate(v) => canonical_bytes(v),
            Self::ContentPublish(v)
            | Self::ContentAlias(v)
            | Self::ContentCompose(v)
            | Self::RecordPublish(v) => canonical_bytes(v),
            Self::ContentRetire(v) => canonical_bytes(v),
            Self::OperationPublish(v) => canonical_bytes(v),
        }
    }

    fn validate(&self) -> Result<(), StoreError> {
        use kappa_types::content::ContentAdmissionEvidence;
        match self {
            Self::ContentPublish(v)
                if !matches!(
                    v.evidence(),
                    ContentAdmissionEvidence::VerifiedBytes | ContentAdmissionEvidence::Chunked(_)
                ) =>
            {
                return Err(rejected(
                    "content publication requires bytes or chunk evidence",
                ));
            }
            Self::ContentAlias(v)
                if !matches!(v.evidence(), ContentAdmissionEvidence::Alias(_)) =>
            {
                return Err(rejected("alias publication requires alias evidence"));
            }
            Self::ContentCompose(v)
                if !matches!(v.evidence(), ContentAdmissionEvidence::Composition(_)) =>
            {
                return Err(rejected(
                    "composition publication requires composition evidence",
                ));
            }
            Self::RecordPublish(v)
                if !matches!(v.evidence(), ContentAdmissionEvidence::VerifiedBytes) =>
            {
                return Err(rejected("record publication requires verified bytes"));
            }
            Self::Session(v) => {
                AnchorScope::parse(Some(
                    &AnchorScope::Session { id: v.id.clone() }.to_context(),
                ))?;
                match v.kind {
                    TransitionKind::Set => {}
                    TransitionKind::Deleted
                        if v.expires_at_ms == 0 && v.metadata_digest == Kappa::sha256(&[]) => {}
                    _ => return Err(rejected("invalid session transition")),
                }
            }
            Self::Credential(v) => {
                if v.id.is_empty() || v.grace_commitment.is_some() != v.grace_expires_ms.is_some() {
                    return Err(rejected("invalid credential scope or grace pair"));
                }
                match v.kind {
                    TransitionKind::Set => {}
                    TransitionKind::Deleted
                        if v.grace_commitment.is_none()
                            && v.secret_commitment == Kappa::sha256(&[]) => {}
                    _ => return Err(rejected("invalid credential transition")),
                }
            }
            Self::Sequence(v) if v.namespace_id.len() != 16 => {
                return Err(rejected("invalid sequence namespace"));
            }
            Self::NamespaceUpdate(v) if v.ns.id() == &[0; 16] => {
                return Err(rejected("namespace update names an unknown namespace"));
            }
            Self::OperationPublish(v) => {
                v.validate()?;
            }
            _ => {}
        }
        Ok(())
    }

    fn operation(&self) -> (MutationOp, Option<String>) {
        match self {
            Self::Member(v) => (MutationOp::AnchorOrigin, Some(v.scope().to_context())),
            Self::TagSet(v) => (MutationOp::TagSet, Some(v.name.clone())),
            Self::TagDelete(v) => (MutationOp::TagDelete, Some(v.name.clone())),
            Self::EdgePut(v) => (MutationOp::EdgePut, Some(v.relation.to_string())),
            Self::EdgeDelete(v) => (MutationOp::EdgeDelete, Some(v.relation.to_string())),
            Self::Assertion(_) => (MutationOp::AssertionPublish, None),
            Self::Revocation(_) => (MutationOp::RevocationPublish, None),
            Self::NamespaceUpdate(_) => (MutationOp::NamespaceUpdate, None),
            Self::Metadata(v) => (MutationOp::MetadataUpdate, Some(v.key().to_owned())),
            Self::Sequence(v) => (MutationOp::SequenceUpdate, Some(v.name.clone())),
            Self::ContentPublish(_) => (MutationOp::ContentPublish, None),
            Self::ContentAlias(_) => (MutationOp::ContentAlias, None),
            Self::ContentCompose(_) => (MutationOp::ContentCompose, None),
            Self::RecordPublish(_) => (MutationOp::RecordPublish, None),
            Self::ContentRetire(_) => (MutationOp::ContentRetire, None),
            Self::OperationPublish(_) => (MutationOp::OperationPublish, None),
            other => {
                let scope = match other {
                    Self::Watermark(_) => AnchorScope::Watermark,
                    Self::Succession(_) => AnchorScope::Succession,
                    Self::Session(v) => AnchorScope::Session { id: v.id.clone() },
                    Self::Credential(v) => AnchorScope::Credential { id: v.id.clone() },
                    Self::Trust(_) => AnchorScope::Trust,
                    _ => unreachable!("non-anchor variants returned above"),
                };
                (MutationOp::AnchorOrigin, Some(scope.to_context()))
            }
        }
    }

    fn index_change(&self, evidence: &VerifiedContent) -> Result<Change, StoreError> {
        use kappa_types::state_key as key;
        let bytes = evidence.content();
        let id = evidence.kappa();
        let (path, value) = match self {
            Self::Member(v) => return Ok(v.index_change()),
            Self::TagSet(v) | Self::TagDelete(v) => key::tag_entry(&v.name, bytes),
            Self::EdgePut(_) | Self::EdgeDelete(_) => key::edge_entry(id, bytes),
            Self::Assertion(_) => key::assertion_entry(id, bytes),
            Self::Revocation(_) => key::revocation_entry(id, bytes),
            Self::Watermark(_) => key::watermark_entry(id, bytes),
            Self::Succession(v) => key::succession_entry(&v.old_anchor, bytes),
            Self::Session(v) => key::session_entry(&v.id, bytes),
            Self::Credential(v) => key::credential_entry(&v.id, bytes),
            Self::Trust(_) => key::trust_entry("trust", bytes),
            Self::Metadata(v) => {
                use kappa_types::MetadataSubject;
                match v.subject() {
                    MetadataSubject::Namespace => key::metadata_entry(v.key(), bytes),
                    MetadataSubject::Blob(identity) => {
                        key::blob_meta_entry(identity, v.key(), bytes)
                    }
                }
            }
            Self::Sequence(v) => key::sequence_entry(&v.name, bytes),
            Self::NamespaceUpdate(_) => key::namespace_record_entry(bytes),
            Self::ContentPublish(v)
            | Self::ContentAlias(v)
            | Self::ContentCompose(v)
            | Self::RecordPublish(v) => {
                key::content_entry(v.admission().identity(), &canonical_bytes(v.admission()))
            }
            Self::ContentRetire(v) => {
                return Ok((
                    key::path(key::Family::Content, &v.removed().identity().key_bytes()),
                    None,
                ));
            }
            Self::OperationPublish(v) => {
                let op_id = v.operation_id()?;
                key::operation_entry(op_id, bytes)
            }
        };
        let removed = matches!(self, Self::TagDelete(_) | Self::EdgeDelete(_))
            || matches!(self, Self::Metadata(v) if v.value().is_none());
        Ok((path, (!removed).then_some(value)))
    }
}

fn rejected(message: &str) -> StoreError {
    StoreError::Rejected(message.to_owned())
}

#[cfg(test)]
mod tests;
