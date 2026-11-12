//! What a backend installs with a prepared transition beyond its canonical
//! evidence, and the binding that checks the two correspond.
//!
//! Public evidence commits private values by digest: a session set commits
//! its metadata, a credential set its secret hashes, a content admission
//! the bytes it admits. The payload carries those values, and
//! [`PreparedWrite::bind`] refuses a payload that does not correspond to
//! its transition, so a backend applies a transition only with the exact
//! resources its evidence commits. Which transition needs which payload is
//! decided once, here ([`PrivatePayload`]); a backend supplies only its own
//! prepared-content resource ([`PreparedResource`]).

use kappa_types::authorization::{CredentialTransition, SessionTransition, TransitionKind};
use kappa_types::content::{ContentAdmissionEvidence, ContentAdmissionRecord};
use kappa_types::epoch::EpochMutation;
use kappa_types::state_index::Change;
use kappa_types::{Kappa, LogicalIncarnation, NamespaceRef, StoreError, VerifiedContent};

use super::{PreparedTransition, RecordTransition, rejected};

/// Backend-owned installation payload validated against a transition.
///
/// Shared semantic checks (digest commitments, identity and length
/// correspondence) are the helpers below; backend-specific checks (store
/// ownership, allocation protection) are the backend's.
pub trait InstallationPayload: Sized {
    /// Backend context for native ownership checks.
    type Context: ?Sized;

    /// Reject if this payload does not correspond to `transition`: wrong
    /// operation kind, mismatched identity or length, failed digest
    /// commitment, or foreign store ownership.
    fn validate_for(
        &self,
        transition: &PreparedTransition,
        context: &Self::Context,
    ) -> Result<(), StoreError>;
}

/// Check the private session metadata a backend installs against the digest
/// its set transition commits. Only a set transition carries metadata.
pub fn check_session_metadata(
    record: &SessionTransition,
    metadata: &[u8],
) -> Result<(), StoreError> {
    if record.kind != TransitionKind::Set {
        return Err(rejected("only a session set carries metadata"));
    }
    if record.metadata_digest != Kappa::sha256(metadata) {
        return Err(rejected(
            "session metadata does not match its evidence digest",
        ));
    }
    Ok(())
}

/// Check the private secret hashes a backend installs against the
/// commitments its set transition carries: the current secret always, the
/// grace secret exactly when the transition commits one.
pub fn check_credential_secrets(
    record: &CredentialTransition,
    secret_hash: &[u8],
    grace_secret_hash: Option<&[u8]>,
) -> Result<(), StoreError> {
    if record.kind != TransitionKind::Set {
        return Err(rejected("only a credential set carries secrets"));
    }
    if record.secret_commitment != Kappa::sha256(secret_hash) {
        return Err(rejected("credential secret does not match its commitment"));
    }
    match (&record.grace_commitment, grace_secret_hash) {
        (Some(commitment), Some(grace)) if *commitment == Kappa::sha256(grace) => Ok(()),
        (Some(_), Some(_)) => Err(rejected(
            "credential grace secret does not match its commitment",
        )),
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => Err(rejected(
            "credential grace presence disagrees with evidence",
        )),
    }
}

/// Check verified bytes a backend installs against the verified-bytes
/// admission that names them: identity and logical size.
pub fn check_admitted_bytes(
    record: &ContentAdmissionRecord,
    content: &VerifiedContent,
) -> Result<(), StoreError> {
    let admission = record.admission();
    if admission.identity() != content.kappa()
        || admission.logical_size() != content.len() as u64
        || !matches!(record.evidence(), ContentAdmissionEvidence::VerifiedBytes)
    {
        return Err(rejected("record bytes differ from their admission"));
    }
    Ok(())
}

/// A backend's prepared content: bytes staged and verified outside the
/// writer, owned until installation moves them into the candidate.
pub trait PreparedResource {
    /// The store the resource must belong to.
    type Context: ?Sized;

    /// Reject unless this resource was prepared by `context` and holds
    /// exactly the bytes `record` admits: its canonical holder identity,
    /// its logical size, and verified-bytes evidence.
    fn validate_admission(
        &self,
        record: &ContentAdmissionRecord,
        context: &Self::Context,
    ) -> Result<(), StoreError>;
}

/// The private resources a transition installs beyond its evidence, with
/// the backend's prepared-content resource `C`.
pub enum PrivatePayload<C> {
    /// The canonical evidence supplies every authoritative value: tags,
    /// edges, sequences, namespace records, identity members, assertions,
    /// revocations, watermarks, metadata, successions, trust, alias and
    /// composition admissions, retirements, receipts, and authorization
    /// deletions.
    NoResources,
    /// Session set: the metadata its digest commits.
    SessionMetadata(Vec<u8>),
    /// Credential set or rotation: the secret hashes its commitments name.
    CredentialSecrets {
        secret_hash: Vec<u8>,
        grace_secret_hash: Option<Vec<u8>>,
    },
    /// Streamed or compressed content prepared by the backend.
    PreparedContent(C),
    /// Verified bytes of an explicit record admission.
    ExplicitRecord(VerifiedContent),
}

impl<C: PreparedResource> InstallationPayload for PrivatePayload<C> {
    type Context = C::Context;

    fn validate_for(
        &self,
        transition: &PreparedTransition,
        context: &Self::Context,
    ) -> Result<(), StoreError> {
        match (transition.record(), self) {
            (
                RecordTransition::TagSet(_)
                | RecordTransition::TagDelete(_)
                | RecordTransition::EdgePut(_)
                | RecordTransition::EdgeDelete(_)
                | RecordTransition::Assertion(_)
                | RecordTransition::Revocation(_)
                | RecordTransition::Watermark(_)
                | RecordTransition::Succession(_)
                | RecordTransition::Metadata(_)
                | RecordTransition::Sequence(_)
                | RecordTransition::NamespaceUpdate(_)
                | RecordTransition::Trust(_)
                | RecordTransition::Member(_)
                | RecordTransition::ContentAlias(_)
                | RecordTransition::ContentCompose(_)
                | RecordTransition::ContentRetire(_)
                | RecordTransition::OperationPublish(_),
                Self::NoResources,
            ) => Ok(()),
            (RecordTransition::Session(session), Self::SessionMetadata(metadata)) => {
                check_session_metadata(session, metadata)
            }
            (RecordTransition::Session(session), Self::NoResources) => match session.kind {
                TransitionKind::Deleted => Ok(()),
                _ => Err(rejected("a session set requires its metadata payload")),
            },
            (
                RecordTransition::Credential(credential),
                Self::CredentialSecrets {
                    secret_hash,
                    grace_secret_hash,
                },
            ) => check_credential_secrets(credential, secret_hash, grace_secret_hash.as_deref()),
            (RecordTransition::Credential(credential), Self::NoResources) => {
                match credential.kind {
                    TransitionKind::Deleted => Ok(()),
                    _ => Err(rejected("a credential set requires its secret payload")),
                }
            }
            (RecordTransition::ContentPublish(record), Self::PreparedContent(prepared)) => {
                prepared.validate_admission(record, context)
            }
            (
                RecordTransition::ContentPublish(record) | RecordTransition::RecordPublish(record),
                Self::ExplicitRecord(bytes),
            ) => check_admitted_bytes(record, bytes),
            _ => Err(rejected("transition and payload do not correspond")),
        }
    }
}

/// A prepared transition with its checked backend-owned payload.
///
/// Ready for backend application. Fields are private; construction
/// validates through `InstallationPayload::validate_for`. Application
/// consumes the payload by value, moving owned resources into the
/// candidate.
pub struct PreparedWrite<P> {
    transition: PreparedTransition,
    payload: P,
}

impl<P: InstallationPayload> PreparedWrite<P> {
    /// Bind a payload to a transition after validating correspondence.
    pub fn bind(
        transition: PreparedTransition,
        payload: P,
        context: &P::Context,
    ) -> Result<Self, StoreError> {
        payload.validate_for(&transition, context)?;
        Ok(Self {
            transition,
            payload,
        })
    }

    pub const fn transition(&self) -> &PreparedTransition {
        &self.transition
    }

    pub const fn payload(&self) -> &P {
        &self.payload
    }

    /// Consume at the backend application boundary.
    pub fn into_parts(
        self,
        namespace: &NamespaceRef,
        incarnation: &LogicalIncarnation,
    ) -> Result<(RecordTransition, VerifiedContent, EpochMutation, Change, P), StoreError> {
        let (record, evidence, mutation, change) =
            self.transition.into_parts(namespace, incarnation)?;
        Ok((record, evidence, mutation, change, self.payload))
    }
}
