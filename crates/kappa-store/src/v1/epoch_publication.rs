//! Shared epoch publication policy. Backends supply a locked, coherent view
//! and persist the resulting publication without reimplementing its rules.
//!
//! Work is admitted before it starts. Each unit (encoding the ledger,
//! building the root, invoking the signer, forming the signed root,
//! verifying it, encoding each generated record) is admitted at its checked
//! upper bound against the caller's meter, which the caller holds
//! exclusively while the unit runs, and is accounted when it ends, failed
//! or not: as measured where the unit can measure what it did, at its
//! admitted bound where the work is internal to the COSE and signature
//! libraries. A unit refused for lack of allowance or past its deadline
//! leaves the candidate exactly as it was, and a later call under a fresh
//! allowance continues from there.

use std::iter;
use std::mem;

use kappa_crypto::cose::{UnsignedEnvelope, envelope_bound};
use kappa_crypto::epoch_verification::{check_successor, succession_path_identity};
use kappa_crypto::signed_types::verify_epoch;
use kappa_types::{
    Kappa, NamespaceRef, PublicationPhase, RecoveryDisposition, StoreError, VerifiedContent,
    axis::Axis,
    canonical::{canonical_bytes, from_canonical},
    clock::ClockMs,
    edge::{BuiltinRelation, EdgeInput, EdgeRelation},
    epoch::EpochMutation,
    epoch_root::{EpochRoot, EpochRootInput, mutations_merkle_root},
    signed::content_types,
    work::{Dimension, Meter, Work, WorkMeter},
};

use crate::epoch_authority::{EpochAuthority, PathEvidence};
use crate::namespace_commitment::{CommittedState, StateInput, commit};

#[derive(Clone, Copy)]
pub struct EpochPublicationInput<'a> {
    pub namespace: &'a NamespaceRef,
    pub predecessor: Option<&'a EpochRoot>,
    pub state_root: [u8; 32],
    pub tag_count: u64,
    pub mutations: &'a [EpochMutation],
    pub now: ClockMs,
    /// Anchor the caller requires the epoch to be signed under. Publication
    /// fails unless it is the store's current authority.
    pub signer_override: Option<&'a Kappa>,
    /// The namespace-state commitment inputs (`namespace_commitment`).
    pub state: StateInput<'a>,
}

/// The signing coordinate of one epoch, consumed.
///
/// A backend constructs it only inside the operation that records `(namespace, epoch_number)` as
/// consumed in state its rollback cannot undo: memory in the namespace
/// slot outside every candidate view, redb in a committed transaction
/// before the signer is invoked. `recorded` is that backend's assertion;
/// no other caller constructs one. The publication carries it to the
/// backend's ownership transfer, so a coordinate that may carry a
/// signature is never released for another root.
#[derive(Debug, PartialEq, Eq)]
pub struct SigningReservation {
    namespace: [u8; 16],
    epoch_number: u64,
}

impl SigningReservation {
    /// The reservation of a coordinate the calling backend has just
    /// recorded as consumed.
    pub const fn recorded(namespace: [u8; 16], epoch_number: u64) -> Self {
        Self {
            namespace,
            epoch_number,
        }
    }
    pub const fn namespace(&self) -> &[u8; 16] {
        &self.namespace
    }
    pub const fn epoch_number(&self) -> u64 {
        self.epoch_number
    }
}

/// Complete authenticated publication; fields are private so a backend cannot
/// substitute a ledger, edge, root, state commitment or rotation evidence
/// after shared validation.
pub struct EpochPublication {
    root: EpochRoot,
    ledger: VerifiedContent,
    root_blob: VerifiedContent,
    edge: EdgeInput,
    edge_blob: VerifiedContent,
    rotation_record: Option<VerifiedContent>,
    retained_links: Vec<(EdgeInput, VerifiedContent)>,
    committed: CommittedState,
    reservation: SigningReservation,
}

/// A complete epoch candidate and how far its signing has progressed.
///
/// Every record the epoch commits is built before the signature, and all
/// the work after it is admitted before the signer is invoked. The
/// candidate owns its signing input, its succession evidence, the exact
/// bytes the signer returned and every record generated from them, so a
/// backend can retain it through any failure after its coordinate is
/// consumed: signing never consumes the candidate, records each step it
/// completes, and invokes the signer at most once. Only
/// [`EpochCandidate::into_publication`] yields the publication, once every
/// step is complete.
pub struct EpochCandidate {
    predecessor: Option<EpochRoot>,
    unsigned: EpochRoot,
    path: Option<PathEvidence>,
    ledger: VerifiedContent,
    rotation_record: Option<VerifiedContent>,
    committed: CommittedState,
    targets: Vec<Kappa>,
    work: SigningWork,
    envelope: UnsignedEnvelope,
    /// The exact bytes the signer returned, kept from the moment it
    /// returned them, whatever became of them.
    returned_signature: Option<Vec<u8>>,
    /// Whether the returned bytes' record was acknowledged; signing does
    /// not progress past them until it is.
    returned_recorded: bool,
    progress: Signing,
    root_blob: Option<VerifiedContent>,
    ledger_edge: Option<(EdgeInput, VerifiedContent)>,
    /// One edge per retained target, in target order; its room is reserved
    /// before the signer is invoked.
    links: Vec<(EdgeInput, VerifiedContent)>,
}

/// One signing step a backend records durably as it happens
/// ([`EpochCandidate::sign_recorded`]), with all the work the meter has
/// consumed when it happens, so a restart resumes exactly where signing
/// stood with its cumulative work, and never invokes the signer again for
/// a coordinate it was invoked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningEvent<'a> {
    /// The signer is about to be invoked. A refusal to record it leaves the
    /// candidate as it was, its signer not invoked.
    Invoking,
    /// The signer returned exactly these bytes. The candidate keeps them
    /// whatever becomes of their record.
    Returned(&'a [u8]),
}

/// Where a recorded signing stood: what [`EpochCandidate::restore`] puts
/// back into a candidate rebuilt from the same inputs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedSigning {
    /// The signer was never invoked.
    Prepared,
    /// The signer was invoked and no returned bytes were recorded: a
    /// signature may exist, so the coordinate is never signed again.
    Invoked,
    /// The signer returned these bytes.
    Returned(Vec<u8>),
}

/// How far signing a candidate has progressed.
enum Signing {
    /// The signer has not been invoked.
    Prepared,
    /// The signer was invoked and did not return: a signature may exist.
    Invoked,
    /// The signer returned this error and no bytes.
    Refused(String),
    /// The signer returned the bytes in `returned_signature`; no root has
    /// been formed from them.
    Returned,
    /// The returned bytes are conclusively invalid: their length or
    /// envelope violates the signing profile (`root` absent), or the root
    /// formed from them does not verify (`root` present).
    Invalid {
        root: Option<EpochRoot>,
        reason: String,
    },
    /// The root formed from the returned bytes; `verified` once it passed
    /// the successor rule.
    Signed { root: EpochRoot, verified: bool },
}

/// The checked upper bound of one unit of work.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Unit {
    allocated: u64,
    hashed: u64,
    signatures: u64,
}

impl Unit {
    const fn bounds(&self) -> [(Dimension, u64); 3] {
        [
            (Dimension::BytesAllocated, self.allocated),
            (Dimension::BytesHashed, self.hashed),
            (Dimension::Signatures, self.signatures),
        ]
    }

    const fn plus(self, other: Self) -> Self {
        Self {
            allocated: self.allocated.saturating_add(other.allocated),
            hashed: self.hashed.saturating_add(other.hashed),
            signatures: self.signatures.saturating_add(other.signatures),
        }
    }

    /// Admit this unit: the deadline has not passed and it fits.
    fn admit(&self, meter: &WorkMeter) -> Result<(), StoreError> {
        Ok(meter.admits(&self.bounds())?)
    }

    /// Account this unit at its admitted bound.
    fn account(&self, meter: &mut WorkMeter) -> Result<(), StoreError> {
        for (dimension, amount) in self.bounds() {
            meter.consume(dimension, amount)?;
        }
        Ok(())
    }
}

/// The units of work after the coordinate is consumed, each bounded before
/// the signer is invoked.
#[derive(Clone, Copy, Debug)]
struct SigningWork {
    invocation: Unit,
    formation: Unit,
    verification: Unit,
    root_blob: Unit,
    edges: Unit,
}

impl SigningWork {
    const fn total(&self) -> Unit {
        self.invocation
            .plus(self.formation)
            .plus(self.verification)
            .plus(self.root_blob)
            .plus(self.edges)
    }
}

impl EpochPublication {
    /// Prepare the next epoch of `input.namespace` under the current
    /// authority of `authority`, unsigned.
    ///
    /// A predecessor signed by an earlier authority of this store is
    /// followed by an epoch carrying the succession path from that
    /// authority to the current one, however many rotations the namespace
    /// was idle across.
    ///
    /// Every encoding, hash and record is charged to `meter` before it is
    /// produced, and the work after the signature is admitted. A refusal
    /// here consumes no signing coordinate.
    pub fn prepare(
        input: EpochPublicationInput<'_>,
        authority: &EpochAuthority,
        meter: &mut WorkMeter,
    ) -> Result<EpochCandidate, StoreError> {
        let anchor = authority.anchor();
        if input
            .signer_override
            .is_some_and(|required| required != anchor)
        {
            return Err(StoreError::Conflict(
                "epoch signing key does not match authority".into(),
            ));
        }
        let (epoch_number, path) = successor(&input, authority, meter)?;
        let rotation_record = path
            .as_ref()
            .map(|path| rotation_record(path, meter))
            .transpose()?;
        let (ledger, mutations_root) = encode_ledger(input.mutations, meter)?;
        let committed = commit(
            input.state,
            input.namespace,
            input.predecessor,
            input.mutations,
            meter,
        )?;
        let prev_identifier = input.predecessor.map(EpochRoot::kappa);
        let rotation_kappa = rotation_record.as_ref().map(VerifiedContent::kappa);
        let state = committed.state_record().kappa();
        // Building the root encodes it once and hashes the encoding.
        let root_bytes = unsigned_root_bound(
            prev_identifier,
            anchor,
            rotation_kappa,
            ledger.kappa(),
            state,
        );
        meter.charge_all(&[
            (Dimension::BytesAllocated, root_bytes),
            (Dimension::BytesHashed, root_bytes),
        ])?;
        let unsigned = EpochRoot::build(EpochRootInput {
            namespace: input.namespace,
            epoch_number,
            prev_identifier,
            state_digest: input.state_root,
            mutations_root,
            timestamp: input.now,
            signer_anchor: anchor,
            tag_count: input.tag_count,
            rotation_kappa,
            ledger_root: ledger.kappa(),
            state,
        });
        let targets = retained_targets(
            input.predecessor,
            rotation_record.as_ref(),
            &committed,
            input.mutations,
            meter,
        )?;
        let (envelope, signable) = signing_input(&unsigned, authority, root_bytes, meter)?;
        let work = signing_work(
            &unsigned,
            authority,
            (signable, root_bytes),
            path.as_ref().zip(rotation_record.as_ref()),
            ledger.kappa(),
            &targets,
        )?;
        work.total().admit(meter)?;
        Ok(EpochCandidate {
            predecessor: input.predecessor.cloned(),
            unsigned,
            path,
            ledger,
            rotation_record,
            committed,
            targets,
            work,
            envelope,
            returned_signature: None,
            returned_recorded: false,
            progress: Signing::Prepared,
            root_blob: None,
            ledger_edge: None,
            links: Vec::new(),
        })
    }

    pub const fn root(&self) -> &EpochRoot {
        &self.root
    }
    pub const fn ledger(&self) -> &VerifiedContent {
        &self.ledger
    }
    pub const fn root_blob(&self) -> &VerifiedContent {
        &self.root_blob
    }
    pub const fn edge(&self) -> &EdgeInput {
        &self.edge
    }
    pub const fn edge_blob(&self) -> &VerifiedContent {
        &self.edge_blob
    }
    /// The succession path content `root().rotation_kappa()` names. A
    /// backend publishes it with the root so replay can retrieve it.
    pub const fn rotation_record(&self) -> Option<&VerifiedContent> {
        self.rotation_record.as_ref()
    }
    /// The state commitment the root names: its state and authority
    /// records, which a backend publishes with the root, and the history
    /// the next epoch extends.
    pub const fn committed(&self) -> &CommittedState {
        &self.committed
    }
    /// The consumed coordinate this publication was signed under.
    pub const fn reservation(&self) -> &SigningReservation {
        &self.reservation
    }
    pub fn into_root(self) -> EpochRoot {
        self.root
    }
    /// The root, its state commitment and its consumed coordinate.
    pub fn into_parts(self) -> (EpochRoot, CommittedState, SigningReservation) {
        (self.root, self.committed, self.reservation)
    }

    pub fn retained_links(&self) -> &[(EdgeInput, VerifiedContent)] {
        &self.retained_links
    }

    /// The signed root and every record generated from it, owned: the
    /// root's own encoding, its ledger edge, and one edge per retained
    /// target. A backend that retains them moves their bytes rather than
    /// copying them.
    pub fn into_generated(self) -> (EpochRoot, Vec<GeneratedRecord>) {
        let mut records = Vec::with_capacity(self.retained_links.len().saturating_add(2));
        records.push(GeneratedRecord {
            edge: None,
            content: self.root_blob,
        });
        records.push(GeneratedRecord {
            edge: Some(self.edge),
            content: self.edge_blob,
        });
        records.extend(
            self.retained_links
                .into_iter()
                .map(|(edge, content)| GeneratedRecord {
                    edge: Some(edge),
                    content,
                }),
        );
        (self.root, records)
    }
}

/// One record generated from a signed root: its identified bytes and, for
/// an edge, the edge they encode.
pub struct GeneratedRecord {
    pub edge: Option<EdgeInput>,
    pub content: VerifiedContent,
}

/// The number of the epoch following `input.predecessor` and the succession
/// evidence it carries, when the predecessor's signer differs from the
/// current authority.
///
/// Verifying the predecessor's authority and retaining the predecessor are
/// charged first; the evidence is admitted at its bound and accounted as
/// measured by [`rotation_record`].
fn successor(
    input: &EpochPublicationInput<'_>,
    authority: &EpochAuthority,
    meter: &mut WorkMeter,
) -> Result<(u64, Option<PathEvidence>), StoreError> {
    let Some(previous) = input.predecessor else {
        return Ok((1, None));
    };
    if previous.namespace_id() != input.namespace.id() {
        return Err(StoreError::Internal(
            "epoch predecessor crosses namespace identity".into(),
        ));
    }
    if input.now.as_i64() < previous.timestamp_ms() {
        return Err(StoreError::Rejected("epoch timestamp regressed".into()));
    }
    let transitions = authority
        .path_from(previous.signer_anchor())
        .ok_or_else(|| {
            StoreError::Conflict(
                "predecessor signer has no succession path to the current authority".into(),
            )
        })?;
    meter.charge_all(&predecessor_verification(previous, authority).bounds())?;
    verify_epoch_authority(previous, authority)?;
    meter.charge(Dimension::BytesAllocated, held_root_bound(previous))?;
    let number = previous
        .epoch_number()
        .checked_add(1)
        .ok_or_else(|| StoreError::CapacityExceeded("epoch number exhausted".into()))?;
    if transitions.is_empty() {
        return Ok((number, None));
    }
    meter.admits(&[(
        Dimension::BytesAllocated,
        PathEvidence::bound(transitions.len()),
    )])?;
    Ok((number, Some(PathEvidence::new(transitions))))
}

/// The succession path content `path` is, owned and identified, with the
/// path's own retention accounted as measured.
fn rotation_record(
    path: &PathEvidence,
    meter: &mut WorkMeter,
) -> Result<VerifiedContent, StoreError> {
    let bound = PathEvidence::bound(path.len()).saturating_add(ARRAY_HEADER);
    meter.admits(&[
        (Dimension::BytesAllocated, bound.saturating_mul(2)),
        (Dimension::BytesHashed, bound),
    ])?;
    let content = path.content();
    let measured = content.len() as u64;
    meter.consume(
        Dimension::BytesAllocated,
        path.held_bytes(&content).saturating_add(measured),
    )?;
    meter.consume(Dimension::BytesHashed, measured)?;
    Ok(VerifiedContent::compute_owned(Axis::Sha256, content)?)
}

/// What verifying `previous` against `authority` (`verify_epoch_authority`)
/// may take: its signature check over its signable encoding, its envelope
/// and the envelope's to-be-signed structure, and, when it names rotation
/// evidence, every candidate path of this store's transitions encoded and
/// hashed once.
fn predecessor_verification(previous: &EpochRoot, authority: &EpochAuthority) -> Unit {
    let envelope = previous.cose_signature().len() as u64;
    let root = Unit {
        allocated: held_root_bound(previous).saturating_add(envelope.saturating_mul(2)),
        hashed: envelope,
        signatures: 1,
    };
    let Some(end) = previous.rotation_kappa().and_then(|_| {
        authority
            .transitions()
            .iter()
            .position(|transition| transition.incoming().anchor() == previous.signer_anchor())
    }) else {
        return root;
    };
    let paths = (end as u64).saturating_add(1);
    // Paths ending at `end`, from each start, hold (end + 1)(end + 2) / 2
    // links together; each is cloned, encoded and hashed.
    let links = paths.saturating_mul(paths.saturating_add(1)) / 2;
    let bytes = PathEvidence::bound(usize::try_from(links).unwrap_or(usize::MAX));
    root.plus(Unit {
        allocated: bytes.saturating_mul(2),
        hashed: bytes,
        signatures: 0,
    })
}

/// `root`, formed from the returned signature, admitted under the rule
/// replay admits history with: the successor rule after `predecessor`
/// along `path`, or its own signature at genesis. Every refusal is
/// conclusive for this root.
fn admit_signed(
    root: &EpochRoot,
    predecessor: Option<&EpochRoot>,
    public_key: &[u8],
    path: Option<&PathEvidence>,
) -> Result<(), StoreError> {
    predecessor.map_or_else(
        || {
            verify_epoch(root, public_key)
                .map_err(|error| StoreError::Rejected(format!("epoch signature: {error}")))
        },
        |previous| {
            let keys = path.map(PathEvidence::keys);
            let path = path
                .zip(keys.as_deref())
                .map(|(path, keys)| path.path(keys));
            check_successor(previous, root, public_key, path)
                .map_err(|error| StoreError::Rejected(format!("epoch succession: {error}")))
        },
    )
}

impl EpochCandidate {
    pub fn epoch_number(&self) -> u64 {
        self.unsigned.epoch_number()
    }

    /// The timestamp the epoch is signed at: once its coordinate is
    /// consumed, a lineage summary bounding authority transitions must
    /// include it, published or not.
    pub fn timestamp_ms(&self) -> i64 {
        self.unsigned.timestamp_ms()
    }

    /// The identity of the candidate's unsigned root: the candidate's name
    /// in outcome records, never a signed or published root.
    pub const fn unsigned_identity(&self) -> &Kappa {
        self.unsigned.kappa()
    }

    /// The most bytes the records generated from the signed root hold: the
    /// root's encoding and one edge encoding per generated edge. A backend
    /// retaining them charges this as their retention before the signature.
    pub const fn generated_bytes_bound(&self) -> u64 {
        self.work
            .root_blob
            .allocated
            .saturating_add(self.work.edges.allocated)
    }

    /// How far signing has progressed.
    pub const fn phase(&self) -> PublicationPhase {
        match &self.progress {
            Signing::Prepared => PublicationPhase::Prepared,
            Signing::Invoked => PublicationPhase::SignerInvoked,
            Signing::Refused(_) => PublicationPhase::SignerRefused,
            Signing::Returned => PublicationPhase::SignatureReturned,
            Signing::Invalid { .. } => PublicationPhase::SignatureInvalid,
            Signing::Signed { .. } => PublicationPhase::Completing,
        }
    }

    /// Whether signing can still complete: not once the signer was invoked
    /// without returning bytes, refused, or returned invalid bytes.
    pub const fn disposition(&self) -> RecoveryDisposition {
        match &self.progress {
            Signing::Invoked | Signing::Refused(_) | Signing::Invalid { .. } => {
                RecoveryDisposition::Terminal
            }
            Signing::Prepared | Signing::Returned | Signing::Signed { .. } => {
                RecoveryDisposition::Resumable
            }
        }
    }

    /// Why signing became terminal, when it did.
    pub fn failure(&self) -> Option<&str> {
        match &self.progress {
            Signing::Invoked => Some("the signer was invoked and did not return"),
            Signing::Refused(reason) | Signing::Invalid { reason, .. } => Some(reason),
            Signing::Prepared | Signing::Returned | Signing::Signed { .. } => None,
        }
    }

    /// Whether every record generated from the signed root is built.
    const fn generated(&self) -> bool {
        matches!(self.progress, Signing::Signed { verified: true, .. })
            && self.root_blob.is_some()
            && self.ledger_edge.is_some()
            && self.links.len() == self.targets.len()
    }

    /// The ledger the epoch commits, known before the signature: a backend
    /// installs it before it reserves the coordinate.
    pub const fn ledger(&self) -> &VerifiedContent {
        &self.ledger
    }

    /// The succession path content the epoch names, when its signer
    /// changed; installable before the signature.
    pub const fn rotation_record(&self) -> Option<&VerifiedContent> {
        self.rotation_record.as_ref()
    }

    /// The state commitment the epoch names; its records and history are
    /// installable before the signature.
    pub const fn committed(&self) -> &CommittedState {
        &self.committed
    }

    /// How many records the signed root generates: the root itself, its
    /// ledger edge, and one edge per retained target.
    pub const fn generated_records(&self) -> usize {
        self.targets.len().saturating_add(2)
    }

    /// The namespace whose coordinate this epoch consumes.
    pub fn namespace(&self) -> Result<[u8; 16], StoreError> {
        self.unsigned
            .namespace_id()
            .try_into()
            .map_err(|_| StoreError::Internal("epoch namespace is not 16 bytes".into()))
    }

    /// Whether `meter` admits all the work after the signature. A backend
    /// checks this before it records the coordinate, so a refusal consumes
    /// none.
    pub fn admit(&self, meter: &WorkMeter) -> Result<(), StoreError> {
        self.work.total().admit(meter)
    }

    /// Sign under `authority` at the coordinate `reservation` names, and
    /// generate the evidence the signed root names, each unit admitted
    /// against `meter` before it starts.
    ///
    /// Resumable: every step completed is kept, and a call after a failure
    /// continues from the first incomplete step. The signer is invoked at
    /// most once. A refusal for lack of allowance leaves the candidate as
    /// it was; a terminal failure ([`Self::disposition`]) is reported again
    /// by every later call without repeating any work.
    pub fn sign(
        &mut self,
        authority: &EpochAuthority,
        reservation: &SigningReservation,
        meter: &mut WorkMeter,
    ) -> Result<(), StoreError> {
        self.sign_recorded(authority, reservation, meter, &mut |_, _| Ok(()))
    }

    /// [`Self::sign`], with every signing step passed to `record` as it
    /// happens, with all the work `meter` has consumed by then:
    /// [`SigningEvent::Invoking`] before the signer is invoked (a refusal
    /// leaves the signer uninvoked), and [`SigningEvent::Returned`] with the
    /// exact bytes it returned. A refused record of the returned bytes is
    /// retried by the next call before signing progresses past them. A
    /// backend whose custody outlives the process persists both, and
    /// restores them with [`Self::restore`].
    pub fn sign_recorded(
        &mut self,
        authority: &EpochAuthority,
        reservation: &SigningReservation,
        meter: &mut WorkMeter,
        record: &mut dyn FnMut(SigningEvent<'_>, &Work) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        if *reservation.namespace() != self.namespace()?
            || reservation.epoch_number() != self.epoch_number()
        {
            return Err(StoreError::Internal(
                "signing reservation names another coordinate".into(),
            ));
        }
        if authority.anchor() != self.unsigned.signer_anchor() {
            return Err(StoreError::Conflict(format!(
                "epoch {} is signed by {}, not the supplied authority {}",
                self.epoch_number(),
                self.unsigned.signer_anchor(),
                authority.anchor()
            )));
        }
        if let Some(reason) = self.failure() {
            return Err(StoreError::Conflict(format!(
                "epoch {} cannot be signed: {reason}; its signer is not invoked again",
                self.epoch_number()
            )));
        }
        if matches!(self.progress, Signing::Prepared) {
            self.invoke(authority, meter, record)?;
        }
        if !self.returned_recorded
            && let Some(signature) = self.returned_signature.as_deref()
        {
            record(SigningEvent::Returned(signature), meter.used())?;
            self.returned_recorded = true;
        }
        if matches!(self.progress, Signing::Returned) {
            self.form(meter)?;
        }
        if matches!(
            self.progress,
            Signing::Signed {
                verified: false,
                ..
            }
        ) {
            self.verify(authority, meter)?;
        }
        self.generate(meter)
    }

    /// Invoke the signer once over the retained to-be-signed bytes and keep
    /// whatever it returned before anything can refuse it. The invocation
    /// is recorded before it happens, the returned bytes after, once they
    /// are owned by the candidate and the invocation is accounted.
    fn invoke(
        &mut self,
        authority: &EpochAuthority,
        meter: &mut WorkMeter,
        record: &mut dyn FnMut(SigningEvent<'_>, &Work) -> Result<(), StoreError>,
    ) -> Result<(), StoreError> {
        self.work.total().admit(meter)?;
        self.links
            .try_reserve_exact(self.targets.len())
            .map_err(|error| StoreError::CapacityExceeded(format!("epoch edges: {error}")))?;
        record(SigningEvent::Invoking, meter.used())?;
        self.progress = Signing::Invoked;
        let returned = authority
            .current()
            .signer()
            .sign(self.envelope.to_be_signed());
        let accounted = self.work.invocation.account(meter);
        match returned {
            Ok(signature) => {
                self.progress = Signing::Returned;
                self.returned_recorded = false;
                let signature = self.returned_signature.insert(signature);
                let recorded = record(SigningEvent::Returned(signature), meter.used());
                accounted?;
                recorded?;
                self.returned_recorded = true;
                Ok(())
            }
            Err(error) => {
                let reason = format!("epoch signer refused: {error}");
                self.progress = Signing::Refused(reason.clone());
                accounted?;
                Err(StoreError::Internal(reason))
            }
        }
    }

    /// Put back where a recorded signing of this candidate stood, into a
    /// candidate freshly prepared from the same inputs: refused once its
    /// signing has progressed, so a record never overwrites what this
    /// process observed.
    pub fn restore(&mut self, recorded: RecordedSigning) -> Result<(), StoreError> {
        if !matches!(self.progress, Signing::Prepared) || self.returned_signature.is_some() {
            return Err(StoreError::Internal(format!(
                "epoch {} has progressed past preparation; its signing record is not restored",
                self.epoch_number()
            )));
        }
        match recorded {
            RecordedSigning::Prepared => {}
            RecordedSigning::Invoked => self.progress = Signing::Invoked,
            RecordedSigning::Returned(signature) => {
                self.returned_signature = Some(signature);
                self.returned_recorded = true;
                self.progress = Signing::Returned;
            }
        }
        Ok(())
    }

    /// Form the signed root from the retained bytes, borrowed. Bytes the
    /// signing profile rejects are conclusive for this candidate.
    fn form(&mut self, meter: &mut WorkMeter) -> Result<(), StoreError> {
        let unit = self.work.formation;
        unit.admit(meter)?;
        let Some(signature) = self.returned_signature.as_deref() else {
            return Err(StoreError::Internal(
                "a returned signature is not retained".into(),
            ));
        };
        let formed = self
            .envelope
            .complete(signature)
            .map(|envelope| self.unsigned.clone().with_signature(envelope));
        unit.account(meter)?;
        match formed {
            Ok(root) => {
                self.progress = Signing::Signed {
                    root,
                    verified: false,
                };
                Ok(())
            }
            Err(error) => {
                let reason = format!("epoch envelope: {error}");
                self.progress = Signing::Invalid {
                    root: None,
                    reason: reason.clone(),
                };
                Err(StoreError::Rejected(reason))
            }
        }
    }

    /// Verify the formed root once. A root that does not verify is
    /// conclusive for this candidate and is never verified again.
    fn verify(
        &mut self,
        authority: &EpochAuthority,
        meter: &mut WorkMeter,
    ) -> Result<(), StoreError> {
        let unit = self.work.verification;
        unit.admit(meter)?;
        let Signing::Signed { root, verified } = &mut self.progress else {
            return Err(StoreError::Internal("verifying an unformed root".into()));
        };
        let checked = admit_signed(
            root,
            self.predecessor.as_ref(),
            authority.current().signer().public_key(),
            self.path.as_ref(),
        );
        unit.account(meter)?;
        match checked {
            Ok(()) => {
                *verified = true;
                Ok(())
            }
            Err(error) => {
                let reason = error.to_string();
                let progress = mem::replace(&mut self.progress, Signing::Prepared);
                self.progress = Signing::Invalid {
                    root: match progress {
                        Signing::Signed { root, .. } => Some(root),
                        Signing::Prepared
                        | Signing::Invoked
                        | Signing::Refused(_)
                        | Signing::Returned
                        | Signing::Invalid { .. } => None,
                    },
                    reason,
                };
                Err(error)
            }
        }
    }

    /// Generate the records the verified root names: its own encoding, its
    /// ledger edge and one edge per retained target, each a unit admitted
    /// before it starts and kept once built.
    fn generate(&mut self, meter: &mut WorkMeter) -> Result<(), StoreError> {
        let Signing::Signed {
            root,
            verified: true,
        } = &self.progress
        else {
            return Err(StoreError::Internal(
                "generating evidence of an unverified root".into(),
            ));
        };
        if self.root_blob.is_none() {
            let unit = self.work.root_blob;
            unit.admit(meter)?;
            let bytes = root.to_bytes();
            let length = bytes.len() as u64;
            if length > unit.allocated {
                unit.account(meter)?;
                return Err(StoreError::Internal(
                    "signed root exceeds its admitted bound".into(),
                ));
            }
            meter.consume(Dimension::BytesAllocated, length)?;
            meter.consume(Dimension::BytesHashed, length)?;
            self.root_blob = Some(VerifiedContent::verify_owned(root.kappa(), bytes)?);
        }
        if self.ledger_edge.is_none() {
            self.ledger_edge = Some(generated_edge(root, self.ledger.kappa(), meter)?);
        }
        while let Some(target) = self.targets.get(self.links.len()) {
            let generated = generated_edge(root, target, meter)?;
            self.links.push(generated);
        }
        Ok(())
    }

    /// The root formed from the bytes the signer returned, once one was
    /// formed, verified or not.
    pub const fn signed_root(&self) -> Option<&EpochRoot> {
        match &self.progress {
            Signing::Signed { root, .. }
            | Signing::Invalid {
                root: Some(root), ..
            } => Some(root),
            Signing::Prepared
            | Signing::Invoked
            | Signing::Refused(_)
            | Signing::Returned
            | Signing::Invalid { root: None, .. } => None,
        }
    }

    /// The exact bytes the signer returned, including bytes the signing
    /// profile rejects.
    pub fn returned_signature(&self) -> Option<&[u8]> {
        self.returned_signature.as_deref()
    }

    /// The publication, once signing is complete; otherwise the candidate
    /// and its reservation come back unchanged, boxed so the success path
    /// does not carry the candidate's size.
    pub fn into_publication(
        self,
        reservation: SigningReservation,
    ) -> Result<EpochPublication, Box<(Self, SigningReservation)>> {
        let coordinate = self
            .namespace()
            .is_ok_and(|namespace| namespace == *reservation.namespace())
            && reservation.epoch_number() == self.epoch_number();
        if !coordinate || !self.generated() {
            return Err(Box::new((self, reservation)));
        }
        match (self.progress, self.root_blob, self.ledger_edge) {
            (Signing::Signed { root, .. }, Some(root_blob), Some((edge, edge_blob))) => {
                Ok(EpochPublication {
                    root,
                    ledger: self.ledger,
                    root_blob,
                    edge,
                    edge_blob,
                    rotation_record: self.rotation_record,
                    retained_links: self.links,
                    committed: self.committed,
                    reservation,
                })
            }
            (progress, root_blob, ledger_edge) => Err(Box::new((
                Self {
                    predecessor: self.predecessor,
                    unsigned: self.unsigned,
                    path: self.path,
                    ledger: self.ledger,
                    rotation_record: self.rotation_record,
                    committed: self.committed,
                    targets: self.targets,
                    work: self.work,
                    envelope: self.envelope,
                    returned_signature: self.returned_signature,
                    returned_recorded: self.returned_recorded,
                    progress,
                    root_blob,
                    ledger_edge,
                    links: self.links,
                },
                reservation,
            ))),
        }
    }
}

/// The edge from `root` retaining `target`, admitted at its bound before it
/// is encoded and accounted as measured.
fn generated_edge(
    root: &EpochRoot,
    target: &Kappa,
    meter: &mut WorkMeter,
) -> Result<(EdgeInput, VerifiedContent), StoreError> {
    let bound = epoch_edge_bound(root, target);
    meter.admits(&[
        (Dimension::BytesAllocated, bound),
        (Dimension::BytesHashed, bound),
    ])?;
    let edge = epoch_edge(root, target);
    let bytes = canonical_bytes(&edge);
    let length = bytes.len() as u64;
    if length > bound {
        meter.consume(Dimension::BytesAllocated, bound)?;
        meter.consume(Dimension::BytesHashed, bound)?;
        return Err(StoreError::Internal(
            "generated epoch edge exceeds its admitted bound".into(),
        ));
    }
    meter.consume(Dimension::BytesAllocated, length)?;
    meter.consume(Dimension::BytesHashed, length)?;
    let content = VerifiedContent::compute_owned(Axis::Sha256, bytes)?;
    Ok((edge, content))
}

/// The edge from `root` retaining `target`, asserted by the root's signer at
/// the root's timestamp.
fn epoch_edge(root: &EpochRoot, target: &Kappa) -> EdgeInput {
    EdgeInput {
        source: root.kappa().clone(),
        target: target.clone(),
        relation: EdgeRelation::Builtin(BuiltinRelation::EpochRoot),
        asserter: root.signer_anchor().clone(),
        created_at_ms: root.timestamp_ms(),
        metadata: None,
    }
}

/// Bytes of a canonical kappa beyond its text: the text-string header.
const KAPPA_HEADER: u64 = 2;

/// Bytes of an epoch edge's encoding beyond its three kappa texts: the map
/// header, six labels, the builtin relation's enum encoding, the timestamp
/// at its widest and the absent metadata.
const EPOCH_EDGE_FRAMING: u64 = 32;

/// Bytes of a mutation's encoding beyond its kappa and context texts: the
/// map header, four labels, the operation's enum encoding, the timestamp
/// at its widest and the context's text-string header or null.
const MUTATION_FRAMING: u64 = 32;

/// Bytes of an unsigned root's encoding beyond its kappa texts: the map
/// header, thirteen labels, the 16-byte namespace and the two 32-byte
/// digests with their byte-string headers, the epoch number, timestamp, tag
/// count and format version at their widest, and the empty signature.
const ROOT_FRAMING: u64 = 1 + 13 + 17 + 34 + 34 + 4 * 9 + 1;

/// Bytes of a canonical array or byte-string header at its widest.
const ARRAY_HEADER: u64 = 9;

/// Bytes one Merkle interior node hashes (`merkle`): its domain byte and
/// two child hashes.
const MERKLE_NODE_HASHED: u64 = 65;

/// Bytes one borrowed `(algorithm, public key)` pair of a succession path
/// occupies.
const PATH_KEY: u64 = size_of::<(&str, &[u8])>() as u64;

fn kappa_text(kappa: &Kappa) -> u64 {
    KAPPA_HEADER + kappa.format().as_str().len() as u64
}

/// The most bytes an unsigned root with these identities encodes to.
fn unsigned_root_bound(
    prev_identifier: Option<&Kappa>,
    signer: &Kappa,
    rotation: Option<&Kappa>,
    ledger: &Kappa,
    state: &Kappa,
) -> u64 {
    [
        prev_identifier,
        Some(signer),
        rotation,
        Some(ledger),
        Some(state),
    ]
    .into_iter()
    .flatten()
    .map(kappa_text)
    .fold(ROOT_FRAMING, u64::saturating_add)
}

/// The most bytes a persisted root holds: its unsigned encoding and its
/// envelope with the envelope's header.
fn held_root_bound(root: &EpochRoot) -> u64 {
    unsigned_root_bound(
        root.prev_identifier(),
        root.signer_anchor(),
        root.rotation_kappa(),
        root.ledger_root(),
        root.state(),
    )
    .saturating_add(root.cose_signature().len() as u64)
    .saturating_add(ARRAY_HEADER)
}

/// The most bytes one epoch edge to `target` encodes to.
fn epoch_edge_bound(root: &EpochRoot, target: &Kappa) -> u64 {
    EPOCH_EDGE_FRAMING
        + kappa_text(root.kappa())
        + kappa_text(target)
        + kappa_text(root.signer_anchor())
}

/// The owned signing input of `unsigned` under `authority`, charged before
/// it is built: the signable encoding (at most the root's encoding), the
/// envelope's copy of it, and the envelope's headers and to-be-signed
/// structure (each at most the envelope's bound). Returns the input and
/// the signable length.
fn signing_input(
    unsigned: &EpochRoot,
    authority: &EpochAuthority,
    root_bytes: u64,
    meter: &mut WorkMeter,
) -> Result<(UnsignedEnvelope, u64), StoreError> {
    let signer = authority.current().signer();
    let envelope = envelope_bound(
        signer.algorithm(),
        authority.anchor(),
        content_types::EPOCH,
        usize::try_from(root_bytes)
            .map_err(|_| StoreError::CapacityExceeded("epoch root exceeds address space".into()))?,
    )
    .map_err(|error| StoreError::Internal(format!("epoch envelope bound: {error}")))?
        as u64;
    meter.charge(
        Dimension::BytesAllocated,
        root_bytes
            .saturating_mul(2)
            .saturating_add(envelope.saturating_mul(2)),
    )?;
    let signable = unsigned.signable_bytes();
    let length = signable.len() as u64;
    let input = UnsignedEnvelope::new(
        signer,
        unsigned.signer_anchor(),
        content_types::EPOCH,
        &signable,
    )
    .map_err(|error| StoreError::Internal(format!("epoch signing input: {error}")))?;
    Ok((input, length))
}

/// The bound of each unit of work after the coordinate is consumed, where
/// `lengths` holds the signable encoding's length and the unsigned root's
/// bound, `evidence` the succession path and its content after a signer
/// change, and `envelope` is the signing profile's envelope bound:
///
/// - invocation: the signer hashes the to-be-signed structure and returns
///   at most the envelope's worth of signature, and the generated edges'
///   room is reserved; one signature;
/// - formation: the envelope's copy (payload and headers), the signature's
///   copy and the serialized envelope, then the root's clone and its
///   encoding, which is hashed for its identity;
/// - verification: the root's signable encoding, its envelope parsed and
///   its to-be-signed structure rebuilt and hashed, and, after a signer
///   change, the path's content encoded and hashed for its identity and
///   each link's signable encoding with its two envelopes parsed and
///   rebuilt and hashed; one signature, and two per link;
/// - the root's encoding, hashed to its identity;
/// - each generated edge's encoding, hashed to its identity.
///
/// The signed root's identity has the length of the unsigned one's, so
/// every edge bound holds for the signed root.
fn signing_work(
    unsigned: &EpochRoot,
    authority: &EpochAuthority,
    (signable, root_bytes): (u64, u64),
    evidence: Option<(&PathEvidence, &VerifiedContent)>,
    ledger: &Kappa,
    targets: &[Kappa],
) -> Result<SigningWork, StoreError> {
    let signer = authority.current().signer();
    let envelope = envelope_bound(
        signer.algorithm(),
        authority.anchor(),
        content_types::EPOCH,
        usize::try_from(signable)
            .map_err(|_| StoreError::CapacityExceeded("epoch root exceeds address space".into()))?,
    )
    .map_err(|error| StoreError::Internal(format!("epoch envelope bound: {error}")))?
        as u64;
    let signed_root = root_bytes
        .saturating_add(envelope)
        .saturating_add(ARRAY_HEADER);
    let (links, path_bytes) = evidence.map_or((0, 0), |(path, content)| {
        (path.len() as u64, content.len() as u64)
    });
    let edge_room = (targets.len() * size_of::<(EdgeInput, VerifiedContent)>()) as u64;
    let edge_bytes = iter::once(ledger)
        .chain(targets)
        .map(|target| epoch_edge_bound(unsigned, target))
        .fold(0u64, u64::saturating_add);
    Ok(SigningWork {
        invocation: Unit {
            allocated: edge_room.saturating_add(envelope),
            hashed: envelope,
            signatures: 1,
        },
        formation: Unit {
            allocated: signable
                .saturating_add(envelope.saturating_mul(3))
                .saturating_add(root_bytes)
                .saturating_add(signed_root),
            hashed: signed_root,
            signatures: 0,
        },
        verification: Unit {
            allocated: signable
                .saturating_add(envelope.saturating_mul(2))
                .saturating_add(path_bytes.saturating_mul(6))
                .saturating_add(links.saturating_mul(PATH_KEY)),
            hashed: envelope.saturating_add(path_bytes.saturating_mul(3)),
            signatures: links.saturating_mul(2).saturating_add(1),
        },
        root_blob: Unit {
            allocated: signed_root,
            hashed: signed_root,
            signatures: 0,
        },
        edges: Unit {
            allocated: edge_bytes,
            hashed: edge_bytes,
            signatures: 0,
        },
    })
}

/// Every record the root retains: the predecessor, rotation evidence, the
/// state and authority records it commits, and every transition evidence
/// record its ledger names (removal and explicit-record admission included:
/// a retained admission or retirement record does not retain the payload
/// whose identity it carries). Distinct and ordered, so the generated
/// edges are deterministic; the list is charged before it is built.
fn retained_targets(
    predecessor: Option<&EpochRoot>,
    rotation_record: Option<&VerifiedContent>,
    committed: &CommittedState,
    mutations: &[EpochMutation],
    meter: &mut WorkMeter,
) -> Result<Vec<Kappa>, StoreError> {
    let count = mutations
        .len()
        .saturating_add(2)
        .saturating_add(usize::from(predecessor.is_some()))
        .saturating_add(usize::from(rotation_record.is_some()));
    meter.charge(
        Dimension::BytesAllocated,
        (count.saturating_mul(size_of::<Kappa>())) as u64,
    )?;
    let mut targets = Vec::with_capacity(count);
    targets.extend(
        predecessor
            .map(EpochRoot::kappa)
            .into_iter()
            .chain(rotation_record.map(VerifiedContent::kappa))
            .chain([
                committed.state_record().kappa(),
                committed.authority_record().kappa(),
            ])
            .chain(mutations.iter().map(|mutation| &mutation.kappa))
            .cloned(),
    );
    targets.sort_unstable();
    targets.dedup();
    Ok(targets)
}

/// The canonical ledger (the dCBOR array of `mutations`) and its mutation
/// root, admitted at its bound before any element is encoded and consumed
/// as measured. Each element is encoded once: into the ledger, whose
/// slices are the Merkle leaves.
fn encode_ledger(
    mutations: &[EpochMutation],
    meter: &mut WorkMeter,
) -> Result<(VerifiedContent, [u8; 32]), StoreError> {
    let count = mutations.len() as u64;
    let bound = mutations.iter().fold(ARRAY_HEADER, |total, mutation| {
        total
            .saturating_add(MUTATION_FRAMING)
            .saturating_add(kappa_text(&mutation.kappa))
            .saturating_add(mutation.context.as_ref().map_or(0, |c| c.len() as u64))
    });
    let interior = count.saturating_sub(1).saturating_mul(MERKLE_NODE_HASHED);
    let offsets_bytes = count.saturating_mul(2 * size_of::<usize>() as u64);
    meter.admits(&[
        (
            Dimension::BytesAllocated,
            bound.saturating_add(offsets_bytes),
        ),
        (
            Dimension::BytesHashed,
            bound.saturating_mul(2).saturating_add(interior),
        ),
    ])?;
    let mut ledger = array_header(count);
    let mut spans = Vec::with_capacity(mutations.len());
    for mutation in mutations {
        let start = ledger.len();
        ledger.extend_from_slice(&canonical_bytes(mutation));
        spans.push(start..ledger.len());
    }
    let length = ledger.len() as u64;
    if length > bound {
        return Err(StoreError::Internal(
            "ledger encoding exceeds its admitted bound".into(),
        ));
    }
    meter.consume(
        Dimension::BytesAllocated,
        length.saturating_add(offsets_bytes),
    )?;
    meter.consume(
        Dimension::BytesHashed,
        length.saturating_mul(2).saturating_add(interior),
    )?;
    let leaves: Vec<&[u8]> = spans.iter().map(|span| &ledger[span.clone()]).collect();
    let root = kappa_types::merkle::merkle_root(&leaves);
    let ledger = VerifiedContent::compute_owned(Axis::Sha256, ledger)?;
    Ok((ledger, root))
}

/// The canonical (shortest) header of a CBOR array of `count` items: the
/// count inline below 24, otherwise after a one, two, four or eight byte
/// argument marker (additional information 0x18 to 0x1b).
fn array_header(count: u64) -> Vec<u8> {
    const ARRAY: u8 = 0x80;
    const INLINE_MAX: u8 = 0x17;
    let mut out = Vec::with_capacity(9);
    if let Ok(small) = u8::try_from(count) {
        if small <= INLINE_MAX {
            out.push(ARRAY | small);
        } else {
            out.extend_from_slice(&[ARRAY | 0x18, small]);
        }
    } else if let Ok(short) = u16::try_from(count) {
        out.push(ARRAY | 0x19);
        out.extend_from_slice(&short.to_be_bytes());
    } else if let Ok(word) = u32::try_from(count) {
        out.push(ARRAY | 0x1a);
        out.extend_from_slice(&word.to_be_bytes());
    } else {
        out.push(ARRAY | 0x1b);
        out.extend_from_slice(&count.to_be_bytes());
    }
    out
}

/// Admit persisted epoch evidence before it can drive recovery or
/// publication, on `work`: the one admission of a persisted root and its
/// complete ledger, whose identity `ledger` establishes. The root's
/// authority is admitted (`verify_epoch_authority`, charged at
/// [`predecessor_verification`]); the ledger is decoded once, its
/// mutations folded into their commitment, and both digests compared with
/// the root's (`check_ledger_digests`). Each unit is charged before it
/// runs; the decoded mutations, a symbolic construction, are charged at
/// the ledger's length. Returns them, so no caller decodes the ledger
/// again.
///
/// A content-addressed root alone does not establish authority or
/// correspondence between the signed mutation commitment and the persisted
/// ledger.
pub fn admit_persisted_epoch(
    root: &EpochRoot,
    authority: &EpochAuthority,
    ledger: &VerifiedContent,
    work: &mut dyn Meter,
) -> Result<Vec<EpochMutation>, StoreError> {
    work.charge_all(&predecessor_verification(root, authority).bounds())?;
    verify_epoch_authority(root, authority)?;
    let length = ledger.len() as u64;
    work.charge_all(&[
        (Dimension::BytesDecoded, length),
        (Dimension::BytesAllocated, length),
    ])?;
    let mutations: Vec<EpochMutation> = from_canonical(ledger.content())?;
    // `mutations_merkle_root`: each mutation re-encoded (at most the
    // ledger's bytes in all), its leaf and reference buffers, each leaf
    // hashed with its separator, and each interior node.
    let count = mutations.len() as u64;
    let references = count.saturating_mul((size_of::<Vec<u8>>() + size_of::<&[u8]>()) as u64);
    work.charge_all(&[
        (Dimension::Entries, count),
        (Dimension::BytesAllocated, length.saturating_add(references)),
        (
            Dimension::BytesHashed,
            length
                .saturating_add(count.saturating_mul(kappa_types::merkle::LEAF_HASH_OVERHEAD))
                .saturating_add(count.saturating_sub(1).saturating_mul(MERKLE_NODE_HASHED)),
        ),
    ])?;
    check_ledger_digests(root, ledger.kappa(), &mutations_merkle_root(&mutations))?;
    Ok(mutations)
}

/// [`admit_persisted_epoch`] over ledger bytes the caller has not yet
/// identified, on `work`: the bytes are hashed, and copied into the
/// identified content, before the admission.
pub fn verify_persisted_epoch(
    root: &EpochRoot,
    authority: &EpochAuthority,
    ledger_bytes: &[u8],
    work: &mut dyn Meter,
) -> Result<(), StoreError> {
    let length = ledger_bytes.len() as u64;
    work.charge_all(&[
        (Dimension::BytesHashed, length),
        (Dimension::BytesAllocated, length),
    ])?;
    let ledger = VerifiedContent::compute(root.ledger_root().axis(), ledger_bytes)?;
    admit_persisted_epoch(root, authority, &ledger, work).map(drop)
}

/// Correspondence of a persisted root to ledger digests its caller computed:
/// `ledger` must equal the root's ledger identity and `mutations_root` its
/// signed mutation commitment.
///
/// This compares the supplied values with the root's and nothing else. It
/// does not establish that they were computed from the persisted ledger,
/// and it does not admit the root's authority. A caller reading a ledger
/// incrementally owns the remaining checks, each separately required:
/// every persisted ledger byte, in order, hashed on the axis of
/// `root.ledger_root()` into `ledger`; every element decoded as a canonical
/// `EpochMutation`, with nothing after the last; the `canonical_bytes` of
/// each decoded mutation folded, in ledger order, into the `merkle_root`
/// tree that yields `mutations_root`; and `verify_epoch_authority` on the
/// root. `verify_persisted_epoch` performs all of it over complete ledger
/// bytes.
pub fn check_ledger_digests(
    root: &EpochRoot,
    ledger: &Kappa,
    mutations_root: &[u8; 32],
) -> Result<(), StoreError> {
    if ledger != root.ledger_root() {
        return Err(StoreError::Rejected(format!(
            "persisted ledger hashes to {ledger}, the epoch commits {}",
            root.ledger_root()
        )));
    }
    if mutations_root.as_slice() != root.mutations_root() {
        return Err(StoreError::Rejected(
            "epoch mutation commitment does not match persisted ledger".into(),
        ));
    }
    Ok(())
}

/// What admitting `root`'s authority against `authority`
/// ([`verify_epoch_authority`]) may take: the one bound every caller
/// charges before verifying, whether it admits a whole persisted epoch
/// ([`admit_persisted_epoch`]) or reads its ledger incrementally.
pub fn authority_verification(
    root: &EpochRoot,
    authority: &EpochAuthority,
) -> [(Dimension, u64); 3] {
    predecessor_verification(root, authority).bounds()
}

/// Admission of one persisted root against the store's authority history.
///
/// Its signer must be an authority of this store whose window contains the
/// root's timestamp, any rotation evidence it names must be a path of this
/// store's own transitions ending at that signer, and its signature must
/// verify under that authority's key. It says nothing about the root's
/// ledger (`check_ledger_digests`, `verify_persisted_epoch`).
///
/// Position in a namespace's chain (which predecessor, which path) is
/// enforced when an epoch is published and re-established by authenticated
/// replay; both apply `check_successor`.
pub fn verify_epoch_authority(
    root: &EpochRoot,
    authority: &EpochAuthority,
) -> Result<(), StoreError> {
    if root.epoch_number() == 0 || (root.epoch_number() == 1) != root.prev_identifier().is_none() {
        return Err(StoreError::Rejected(
            "invalid epoch predecessor structure".into(),
        ));
    }
    let key = authority
        .verification_key(root.signer_anchor(), root.timestamp_ms())
        .ok_or_else(|| {
            StoreError::Rejected(
                "persisted epoch signer is not an authority of this store at its timestamp".into(),
            )
        })?;
    if let Some(reference) = root.rotation_kappa() {
        let transitions = authority.transitions();
        let end = transitions
            .iter()
            .position(|transition| transition.incoming().anchor() == root.signer_anchor())
            .ok_or_else(|| {
                StoreError::Rejected("rotation evidence names no transition of this store".into())
            })?;
        let named = (0..=end).any(|start| {
            let links: Vec<_> = transitions[start..=end]
                .iter()
                .map(|transition| transition.succession().clone())
                .collect();
            &succession_path_identity(&links) == reference
        });
        if !named {
            return Err(StoreError::Rejected(
                "rotation evidence is not a path of this store's transitions".into(),
            ));
        }
    }
    verify_epoch(root, key.public_key())
        .map_err(|error| StoreError::Rejected(format!("persisted epoch signature: {error}")))
}

#[cfg(test)]
#[path = "epoch_publication_tests.rs"]
mod tests;
