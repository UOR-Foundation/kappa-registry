//! Governed retirement of one storage instance.
//!
//! A retirement is released only by evidence published by an execution of
//! its governing namespace, as one operation:
//!
//! 1. the principal's signed [`RetirementRequest`] naming the instance,
//!    disposition and observed head;
//! 2. the target namespace record the backend observed under its exact
//!    instance reservation ([`TargetObservation`]), naming the principal as
//!    owner: the authority evidence at the decision's revision;
//! 3. the [`RetirementDecision`] binding both by identity, with retaining
//!    (`Owns`) edges from it to both records;
//! 4. the create-only tag [`retirement_tag`] locating the decision;
//! 5. the operation receipt whose result is the decision's identity.
//!
//! [`verify_retirement`] admits a retirement from that evidence alone: the
//! tag only locates; the receipt proves the governing namespace published
//! the decision as this operation; the signature proves the principal asked
//! for exactly this instance; the evidence record proves the principal
//! owned the target when the decision was published. Current ownership of
//! any namespace is never consulted, so a committed release stays
//! verifiable after ownership changes, and a writer of the governing
//! namespace cannot authorize a retirement by naming an owner.
//!
//! Backends inspect storage, hold the instance reservation across the
//! observation and the publication, and delete; this module decides what
//! the published evidence authorizes.

use kappa_crypto::Verified;
use kappa_crypto::signed_types::admit_retirement_request;

use crate::execution::{ExecutionStore, ExecutionWrites, OperationAdmission};
use crate::time::Clock;
use crate::traits::namespace::NamespaceInfo;
use crate::traits::{BlobStore, KappaStore, TagStore};
use crate::{
    Axis, BuiltinRelation, Disposition, EdgeInput, EdgeRelation, EpochRoot, Kappa, NamespaceRef,
    ObservedHead, RetirementDecision, RetirementRequest, StoreError, TagUpdate, VerifiedContent,
    canonical_bytes, from_canonical,
};

/// Prefix of every retirement locator tag.
pub const RETIREMENT_TAG_PREFIX: &str = "_retirement/";

/// Largest record this module reads back.
const RECORD_LIMIT: usize = 64 * 1024;

/// The locator of the decision about `incarnation` of `target`.
pub fn retirement_tag(target: &[u8; 16], incarnation: &[u8; 16]) -> String {
    format!(
        "{RETIREMENT_TAG_PREFIX}{}/{}",
        hex::encode(target),
        hex::encode(incarnation)
    )
}

/// The operation identity of a request: the same signed request replays
/// as the same operation.
pub fn retirement_operation(request: &Kappa) -> [u8; 32] {
    blake3::derive_key("kappa retirement operation v1", &request.key_bytes())
}

/// What the backend observed of the target.
///
/// Observed under the instance reservation it holds until the decision
/// publishes: its namespace record and, for present storage, its
/// authenticated head. For lost storage the record is the last one the
/// backend's directory holds, and the head the last one known, if any.
#[derive(Debug, Clone)]
pub struct TargetObservation {
    pub record: NamespaceInfo,
    pub head: Option<ObservedHead>,
}

/// A retirement admitted from its published evidence. Only
/// [`verify_retirement`] constructs one.
#[derive(Debug)]
pub struct VerifiedRetirement {
    decision: RetirementDecision,
    record: Kappa,
    request: Verified<RetirementRequest>,
    evidence: NamespaceInfo,
    epoch: EpochRoot,
}

impl VerifiedRetirement {
    pub const fn decision(&self) -> &RetirementDecision {
        &self.decision
    }
    /// Identity of the decision record.
    pub const fn record(&self) -> &Kappa {
        &self.record
    }
    pub const fn request(&self) -> &Verified<RetirementRequest> {
        &self.request
    }
    /// The target record the decision was authorized against.
    pub const fn evidence(&self) -> &NamespaceInfo {
        &self.evidence
    }
    /// The governing epoch that published the decision.
    pub const fn epoch(&self) -> &EpochRoot {
        &self.epoch
    }
}

fn mismatch(what: &str) -> StoreError {
    StoreError::Rejected(format!("retirement {what} does not correspond"))
}

/// Whether `observation` authorizes `request`: the record is the target's
/// and names the principal as owner, and the head is the one the principal
/// signed.
fn authorize(
    request: &RetirementRequest,
    observation: &TargetObservation,
) -> Result<(), StoreError> {
    if observation.record.ns.id() != request.target() {
        return Err(mismatch("target record"));
    }
    if observation.record.owner_anchor.as_ref() != Some(request.principal()) {
        return Err(StoreError::Rejected(
            "the requesting principal does not own the target namespace".into(),
        ));
    }
    if observation.head.as_ref() != request.observed_head() {
        return Err(mismatch("observed head"));
    }
    Ok(())
}

/// `bytes` as a record [`verify_retirement`] can read back: refused
/// before anything is written when it exceeds [`RECORD_LIMIT`]. A decision
/// whose evidence cannot be read back would never verify, and its
/// create-only locator would keep every later decision for the instance
/// out.
fn readable_record(what: &str, bytes: &[u8]) -> Result<VerifiedContent, StoreError> {
    if bytes.len() > RECORD_LIMIT {
        return Err(StoreError::Rejected(format!(
            "retirement {what} of {} bytes exceeds the {RECORD_LIMIT} byte record bound",
            bytes.len()
        )));
    }
    Ok(VerifiedContent::compute(Axis::Sha256, bytes)?)
}

/// Publish the retirement inside `execution`.
///
/// `execution` is an execution of the governing namespace admitted as
/// [`retirement_operation`] of the request. Returns the decision and its
/// identity, which the operation's result must be. Every record is checked
/// against the bound [`verify_retirement`] reads under before any of them
/// is written.
pub fn publish_retirement(
    execution: &mut dyn ExecutionWrites,
    request: &Verified<RetirementRequest>,
    observation: &TargetObservation,
) -> Result<(RetirementDecision, Kappa), StoreError> {
    let request = request.get();
    if execution.namespace().id() != request.governing() {
        return Err(mismatch("governing namespace"));
    }
    let governing = execution
        .namespace_info()?
        .ok_or_else(|| StoreError::NotFound("governing namespace record".into()))?;
    if governing.tombstoned {
        return Err(StoreError::Rejected(
            "the governing namespace is deleted".into(),
        ));
    }
    authorize(request, observation)?;
    let request_content = readable_record("request", &canonical_bytes(request))?;
    let evidence_content = readable_record("evidence", &canonical_bytes(&observation.record))?;
    let decision = RetirementDecision::new(
        *request.governing(),
        *request.target(),
        *request.incarnation(),
        request.disposition(),
        request.observed_head().cloned(),
        request_content.kappa().clone(),
        request.principal().clone(),
        evidence_content.kappa().clone(),
    )?;
    let record = readable_record("decision", &canonical_bytes(&decision))?;
    execution.blob_put(&request_content)?;
    execution.blob_put(&evidence_content)?;
    execution.blob_put(&record)?;
    // The decision retains the records it names, as the locator tag
    // retains the decision: none of them is retired while the decision
    // stands. The edges are a function of the request, so a replayed
    // publication writes the same ones.
    for named in [request_content.kappa(), evidence_content.kappa()] {
        execution.edge_put(&EdgeInput {
            source: record.kappa().clone(),
            target: named.clone(),
            relation: EdgeRelation::Builtin(BuiltinRelation::Owns),
            asserter: request.principal().clone(),
            created_at_ms: request.issued_at_ms(),
            metadata: None,
        })?;
    }
    execution.tag_put(
        &retirement_tag(request.target(), request.incarnation()),
        &TagUpdate::CreateIfAbsent {
            kappa: record.kappa().clone(),
        },
    )?;
    Ok((decision, record.kappa().clone()))
}

/// Retire as one operation of `governing`: publish the evidence unless the
/// operation already committed, then admit it from what was published.
///
/// Present storage is checked against the store before publication: the
/// target's current record and head must be the observation's, so the
/// evidence published is the target's own committed state at the head the
/// principal signed. The caller holds the instance reservation across this
/// call, so neither can change before the decision publishes.
///
/// `admit` admits the operation in `governing` (namespace, operation
/// identity, request identity, clock), as `ExecutionStore::begin_operation`
/// does: the protocol is this function's, how its publication is admitted
/// is the backend's. A backend whose admission depends on why the
/// publication exists (a release that must publish while capacity is
/// closed) decides that here, with no state outside the call.
pub fn retire<'s, S, A>(
    store: &'s S,
    governing: &NamespaceRef,
    request: &Verified<RetirementRequest>,
    observation: &TargetObservation,
    clock: &dyn Clock,
    admit: A,
) -> Result<VerifiedRetirement, StoreError>
where
    S: KappaStore + ?Sized,
    A: FnOnce(
        &NamespaceRef,
        [u8; 32],
        Kappa,
        &dyn Clock,
    ) -> Result<OperationAdmission<'s>, StoreError>,
{
    let inner = request.get();
    let request_identity = Kappa::compute(Axis::Sha256, &canonical_bytes(inner))?;
    let operation = retirement_operation(&request_identity);
    // A committed retirement replays from its published evidence before the
    // target is inspected: the target may already be gone.
    if store
        .resolve_operation(governing, &operation, &request_identity)?
        .is_some()
    {
        return admitted(store, governing, inner, &request_identity);
    }
    if inner.disposition() == Disposition::RetirePresent {
        let target = &observation.record.ns;
        let current = store.namespace_info(target)?;
        if canonical_bytes(&current) != canonical_bytes(&observation.record) {
            return Err(mismatch("target record"));
        }
        let (epoch_number, root) = store.epoch_current(target)?;
        if observation.head != Some(ObservedHead { epoch_number, root }) {
            return Err(mismatch("target head"));
        }
    }
    // Admission rechecks the operation under the governing writer: a
    // concurrent publication of the same request replays here.
    match admit(governing, operation, request_identity.clone(), clock)? {
        OperationAdmission::Execute(mut execution) => {
            let (_, record) = publish_retirement(&mut *execution, request, observation)?;
            execution.publish_result(record.key_bytes())?;
        }
        OperationAdmission::Replay { .. } => {}
    }
    admitted(store, governing, inner, &request_identity)
}

/// The retirement `request` (of identity `identity`) published in
/// `governing`, admitted from its evidence. A decision for the instance
/// that another request published is a conflict, not this request's
/// outcome.
fn admitted<S: KappaStore + ?Sized>(
    store: &S,
    governing: &NamespaceRef,
    request: &RetirementRequest,
    identity: &Kappa,
) -> Result<VerifiedRetirement, StoreError> {
    let verified = verify_retirement(store, governing, request.target(), request.incarnation())?
        .ok_or_else(|| {
            StoreError::Internal("a published retirement is not found by its locator".into())
        })?;
    if verified.decision().request() != identity {
        return Err(StoreError::Conflict(
            "another request's retirement decision holds this instance".into(),
        ));
    }
    Ok(verified)
}

/// Verified bytes of `kappa` admitted by `ns`. Evidence the locator names
/// but the namespace cannot serve is unavailable, never absent.
fn evidence_bytes<S: BlobStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    kappa: &Kappa,
) -> Result<Vec<u8>, StoreError> {
    let bytes = store.blob_get_in(ns, kappa).map_err(|error| match error {
        StoreError::NotFound(_) => {
            StoreError::Unavailable(format!("retirement evidence {kappa} in {ns}"))
        }
        other => other,
    })?;
    if bytes.len() > RECORD_LIMIT {
        return Err(StoreError::Rejected(format!(
            "retirement evidence {kappa} exceeds its bound"
        )));
    }
    VerifiedContent::verify(kappa, &bytes)
        .map_err(|error| StoreError::Internal(format!("retirement evidence {kappa}: {error}")))?;
    Ok(bytes)
}

/// The admitted retirement of `incarnation` of `target` under `governing`.
///
/// Admitted from its published evidence (see the module documentation).
/// `None` only when the governing namespace holds no locator for the
/// instance.
pub fn verify_retirement<S>(
    store: &S,
    governing: &NamespaceRef,
    target: &[u8; 16],
    incarnation: &[u8; 16],
) -> Result<Option<VerifiedRetirement>, StoreError>
where
    S: ExecutionStore + BlobStore + TagStore + ?Sized,
{
    let tag = match store.tag_get_raw(governing, &retirement_tag(target, incarnation)) {
        Ok(tag) => tag,
        Err(StoreError::NotFound(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    if tag.symref.is_some() {
        return Err(mismatch("locator"));
    }
    let record = tag.kappa;
    let decision: RetirementDecision = from_canonical(&evidence_bytes(store, governing, &record)?)?;
    if decision.governing() != governing.id()
        || decision.target() != target
        || decision.incarnation() != incarnation
    {
        return Err(mismatch("decision"));
    }
    let request: RetirementRequest =
        from_canonical(&evidence_bytes(store, governing, decision.request())?)?;
    let request = admit_retirement_request(request)
        .map_err(|error| StoreError::Rejected(format!("retirement request signature: {error}")))?;
    let signed = request.get();
    if signed.governing() != decision.governing()
        || signed.target() != decision.target()
        || signed.incarnation() != decision.incarnation()
        || signed.disposition() != decision.disposition()
        || signed.observed_head() != decision.observed_head()
        || signed.principal() != decision.principal()
    {
        return Err(mismatch("request"));
    }
    let evidence: NamespaceInfo =
        from_canonical(&evidence_bytes(store, governing, decision.evidence())?)?;
    authorize(
        signed,
        &TargetObservation {
            record: evidence.clone(),
            head: signed.observed_head().cloned(),
        },
    )?;
    let (epoch, receipt) = store
        .resolve_operation(
            governing,
            &retirement_operation(decision.request()),
            decision.request(),
        )?
        .ok_or_else(|| {
            StoreError::Rejected(
                "the retirement decision was not published as its operation".into(),
            )
        })?;
    if receipt.result() != record.key_bytes().as_slice() {
        return Err(mismatch("operation result"));
    }
    Ok(Some(VerifiedRetirement {
        decision,
        record,
        request,
        evidence,
        epoch,
    }))
}
