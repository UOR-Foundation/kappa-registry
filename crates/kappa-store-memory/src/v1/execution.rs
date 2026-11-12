//! Operation-owned execution over a private candidate namespace view.
//!
//! An execution holds its namespace's writer gate for its whole life and
//! writes a clone of the namespace's published view, which shares every
//! node it does not change. Nothing is visible until publication stores
//! the candidate into the namespace's slot with one pointer store. Dropping
//! or aborting discards the candidate, releases its claims and succession
//! reservations, and drops the allocations it held, whose files are then
//! owed to cleanup.
//!
//! An execution owns one allowance from its start (`MemoryExecution::meter`,
//! the store's publication limit, its deadline brought forward to the
//! execution's): every metered write (succession admission) and every unit
//! of its publication is charged on it, and custody continues on what it
//! left. No step of an execution meters on an allowance of its own.
//!
//! Publication, in order:
//!
//! 1. hold the authority the epoch is signed under: the installed one under
//!    the shared activation gate, or an activation's candidate under the
//!    exclusive gate that activation holds;
//! 2. apply the operation receipt's transition to the candidate;
//! 3. hold the stripes of every authorization key the execution depends on
//!    or writes, and validate every dependency it recorded at its time;
//! 4. check the deadline;
//! 5. prepare the seal, compute the projection changes, and reserve the
//!    retention every record the signed root generates will hold;
//! 6. transfer the candidate and every obligation to the namespace slot's
//!    custody (`Pending`), then consume the namespace's signing coordinate;
//! 7. from custody, one unit at a time, each admitted before it runs: sign
//!    and generate the signed root's evidence, install each generated
//!    record and the head, attach the receipt lookup, and register the keys
//!    the candidate gained;
//! 8. store the candidate: the publication decision;
//! 9. settle claims and succession reservations, unregister the keys the
//!    view lost, raise the lineage summary and, for an activation, install
//!    its authority, then release the stripes, the activation gate and, with
//!    the execution, the writer gate.
//!
//! A refusal before step 6 consumes nothing and aborts the attempt. A
//! publication stopped after it stays in custody, unpublished, and fences
//! its namespace: `StoreError::PublicationRetained` reports what exists,
//! and resolution (`ExecutionStore::resolve_publication`) continues it from
//! its recorded progress under fresh work authorization, the authority and
//! authorization in force and the current time, never invoking the signer
//! again for its coordinate. Settlement after the view store only moves
//! obligations the store already decided; none of it can fail.

use std::cell::{Cell, RefCell};
use std::mem;
use std::sync::atomic::Ordering;
use std::sync::{Arc, MutexGuard};
use std::time::Instant;

use kappa_store::epoch_publication::{EpochCandidate, GeneratedRecord, SigningReservation};
use kappa_store::time::Clock;
use kappa_store::transition::{
    PreparedTransition, PreparedWrite, PrivatePayload, RecordTransition, TransitionDomain,
};
use kappa_store::{
    Axis, ClockMs, EpochAuthority, Execution, Kappa, NamespaceRef, PublicationResolution,
    Published, StoreError, VerifiedContent,
};
use kappa_types::capacity::Reservation;
use kappa_types::epoch_root::EpochRoot;
use kappa_types::identity::Succession;
use kappa_types::work::{Dimension, Meter, Work, WorkMeter};
use kappa_types::{MetadataSubject, PublicationPhase, RecoveryDisposition, RetainedPublication};

use super::claims::{ClaimKey, Holder};
use super::content::MemoryPrepared;
use super::dependency::{
    Dependency, HeldStripes, Stripes, dependencies_hold, guarded, protected_keys, protection_work,
};
use super::epoch::{
    ActivationAuthority, GENERATED_RECORD_ROWS, HEAD_ROWS, RECEIPT_ROWS, RECORD_OVERHEAD,
    reserve_coordinate, retention_bound,
};
use super::projection::Changes;
use super::view::NamespaceView;
use super::writers::WriterToken;
use super::{InMemoryStore, Slot};

/// The memory store's prepared-write payload: the shared pairing of
/// transitions to private resources, with memory's prepared content.
pub type MemoryPayload = PrivatePayload<Box<MemoryPrepared>>;

/// What one publication attempt owns in the shared structures.
pub struct Attempt {
    pub id: u64,
    pub holder: Holder,
    /// Claims this attempt reserved or released.
    claims: Vec<ClaimKey>,
    /// Old anchors of the succession links this attempt reserved.
    successions: Vec<Kappa>,
    /// Authorization keys this attempt writes, whose stripes it holds
    /// across its store.
    guarded: Vec<ClaimKey>,
}

impl Attempt {
    /// Move this attempt's obligations (claims, succession reservations,
    /// guarded keys) into a new owner, leaving this one with its identity
    /// and nothing to settle.
    fn take_obligations(&mut self) -> Self {
        Self {
            id: self.id,
            holder: self.holder,
            claims: mem::take(&mut self.claims),
            successions: mem::take(&mut self.successions),
            guarded: mem::take(&mut self.guarded),
        }
    }

    /// Settle every claim and succession reservation this attempt holds:
    /// committed with its publication's store, or aborted when it never
    /// consumed a signing coordinate.
    fn settle(&self, store: &InMemoryStore, committed: bool) {
        store
            .claims
            .settle(&self.claims, self.holder, self.id, committed);
        if committed {
            store
                .successions
                .commit(&self.successions, self.holder.namespace, self.id);
        } else {
            store
                .successions
                .abort(&self.successions, self.holder.namespace, self.id);
        }
    }
}

/// A write against the candidate view, on the execution's allowance.
pub struct WriteCx<'e> {
    pub store: &'e InMemoryStore,
    pub view: &'e mut NamespaceView,
    pub ns: &'e NamespaceRef,
    pub now: ClockMs,
    attempt: &'e mut Attempt,
    dependencies: &'e RefCell<Vec<Dependency>>,
    /// The execution's one allowance (`MemoryExecution::meter`), borrowed
    /// for this write.
    pub(super) meter: &'e mut WorkMeter,
}

impl<'e> WriteCx<'e> {
    /// A writer over `view`, the candidate of `attempt`, recording
    /// authorization observations into `dependencies` and charging its work
    /// to `meter`.
    const fn new(
        store: &'e InMemoryStore,
        view: &'e mut NamespaceView,
        ns: &'e NamespaceRef,
        now: ClockMs,
        attempt: &'e mut Attempt,
        dependencies: &'e RefCell<Vec<Dependency>>,
        meter: &'e mut WorkMeter,
    ) -> Self {
        Self {
            store,
            view,
            ns,
            now,
            attempt,
            dependencies,
            meter,
        }
    }
}

impl WriteCx<'_> {
    /// The incarnation encoding of this candidate's namespace instance
    /// (`NamespaceView::incarnation_bytes`).
    pub(super) fn incarnation_bytes(&self) -> [u8; 16] {
        self.view.incarnation_bytes()
    }

    /// The transition domain of this execution's namespace instance: the
    /// candidate's protected current instance.
    pub(super) fn domain(&self) -> TransitionDomain {
        TransitionDomain::new(*self.ns.id(), self.view.logical_incarnation())
    }

    /// Apply a complete prepared write to this candidate. Checks
    /// namespace/incarnation, dispatches the authoritative row/reference
    /// effect with ownership transfer, installs retained evidence,
    /// appends the derived mutation, and queues the derived index
    /// change. Any error makes the execution unpublishable through the
    /// existing failure latch in `MemoryExecution::write`.
    pub fn apply_write(
        &mut self,
        prepared: PreparedWrite<MemoryPayload>,
    ) -> Result<(), StoreError> {
        let incarnation = self.view.logical_incarnation();
        let (record, evidence, mutation, change, payload) =
            prepared.into_parts(self.ns, &incarnation)?;
        // Install evidence through the restricted non-recursive path:
        // evidence is retained content, not a logical admission that
        // produces another transition.
        self.install_evidence(&evidence)?;
        self.apply_row_effect(record, evidence.kappa(), payload)?;
        self.view.ledger.push_back(mutation);
        self.view.pending_state_changes.push(change);
        Ok(())
    }

    /// Bind `record` to its canonical evidence in this execution's
    /// namespace instance, check `payload` against it, and apply it
    /// through `apply_write`. Returns the evidence identity the ledger
    /// names.
    pub(super) fn apply_record_transition(
        &mut self,
        record: RecordTransition,
        payload: MemoryPayload,
    ) -> Result<Kappa, StoreError> {
        let evidence = VerifiedContent::compute(Axis::Sha256, &record.canonical_bytes())?;
        let identity = evidence.kappa().clone();
        let transition = PreparedTransition::bind(self.domain(), record, evidence, self.now)?;
        let prepared = PreparedWrite::bind(transition, payload, self.store)?;
        self.apply_write(prepared)?;
        Ok(identity)
    }

    /// Dispatch the authoritative row and reference change of a transition
    /// whose evidence is `evidence`, consuming owned resources from the
    /// payload. This changes the candidate's private state; it emits no
    /// mutation or index effect, which `apply_write` completes once.
    fn apply_row_effect(
        &mut self,
        record: RecordTransition,
        evidence: &Kappa,
        payload: MemoryPayload,
    ) -> Result<(), StoreError> {
        match (record, payload) {
            (RecordTransition::TagSet(entry), MemoryPayload::NoResources) => {
                self.apply_tag_set(entry)?;
            }
            (RecordTransition::TagDelete(entry), MemoryPayload::NoResources) => {
                self.apply_tag_delete(&entry)?;
            }
            (RecordTransition::EdgePut(input), MemoryPayload::NoResources) => {
                self.apply_edge_put(evidence, input)?;
            }
            (RecordTransition::EdgeDelete(_), MemoryPayload::NoResources) => {
                self.apply_edge_delete(evidence)?;
            }

            (RecordTransition::Sequence(record), MemoryPayload::NoResources) => {
                self.apply_sequence(record);
            }
            (RecordTransition::Metadata(meta), MemoryPayload::NoResources) => {
                match meta.subject() {
                    MetadataSubject::Namespace => {
                        self.apply_namespace_meta(meta.key(), meta.value());
                    }
                    MetadataSubject::Blob(identity) => {
                        self.apply_blob_meta(identity, meta.key(), meta.value());
                    }
                }
            }
            (RecordTransition::Assertion(assertion), MemoryPayload::NoResources) => {
                self.apply_assertion(evidence, assertion);
            }
            (RecordTransition::Revocation(revocation), MemoryPayload::NoResources) => {
                self.apply_revocation(evidence, revocation);
            }
            (RecordTransition::Watermark(watermark), MemoryPayload::NoResources) => {
                self.apply_watermark(evidence, watermark);
            }
            (RecordTransition::Succession(succession), MemoryPayload::NoResources) => {
                self.apply_succession(succession);
            }
            (RecordTransition::Session(session), MemoryPayload::SessionMetadata(metadata)) => {
                self.apply_session_set(session, metadata);
            }
            (RecordTransition::Session(session), MemoryPayload::NoResources) => {
                self.apply_session_delete(&session);
            }
            (
                RecordTransition::Credential(credential),
                MemoryPayload::CredentialSecrets {
                    secret_hash,
                    grace_secret_hash,
                },
            ) => {
                self.apply_credential_set(credential, secret_hash, grace_secret_hash);
            }
            (RecordTransition::Credential(credential), MemoryPayload::NoResources) => {
                self.apply_credential_delete(&credential);
            }
            (RecordTransition::Trust(position), MemoryPayload::NoResources) => {
                self.apply_trust(position);
            }
            (RecordTransition::NamespaceUpdate(info), MemoryPayload::NoResources) => {
                self.apply_namespace_record(info);
            }
            (RecordTransition::Member(member), MemoryPayload::NoResources) => {
                self.apply_member(member);
            }
            (RecordTransition::ContentAlias(record), MemoryPayload::NoResources) => {
                self.apply_alias_admission(&record)?;
            }
            (RecordTransition::ContentCompose(record), MemoryPayload::NoResources) => {
                self.apply_composite_admission(&record)?;
            }
            (RecordTransition::ContentRetire(record), MemoryPayload::NoResources) => {
                self.apply_retirement(&record)?;
            }
            (
                RecordTransition::ContentPublish(record),
                MemoryPayload::PreparedContent(prepared),
            ) => {
                self.apply_prepared_admission(&record, *prepared)?;
            }
            (
                RecordTransition::ContentPublish(record) | RecordTransition::RecordPublish(record),
                MemoryPayload::ExplicitRecord(content),
            ) => {
                self.apply_record_admission(&record, &content)?;
            }
            // Operation receipt: no additional row effects; the
            // root-to-receipt lookup is attached after sealing.
            (RecordTransition::OperationPublish(_), MemoryPayload::NoResources) => {}
            // Invalid pairing: should have been caught by validate_for
            (_, _) => {
                return Err(StoreError::Internal(
                    "invalid transition/payload pairing reached application".into(),
                ));
            }
        }
        Ok(())
    }

    /// Reserve `key` for this attempt. An absence of `key` this execution
    /// observed must still hold when it reserves, since the reservation
    /// then excludes every other writer and replaces the observation.
    pub fn reserve(&mut self, key: ClaimKey) -> Result<(), StoreError> {
        {
            let mut dependencies = self.dependencies.borrow_mut();
            if let Some(index) = dependencies.iter().position(|dependency| {
                matches!(dependency, Dependency::Unowned { key: observed, .. } if *observed == key)
            }) {
                if let Dependency::Unowned { at, .. } = dependencies[index]
                    && !self.store.claims.unchanged(at)
                {
                    return Err(StoreError::Conflict(format!(
                        "{key:?} changed after this execution observed it absent"
                    )));
                }
                dependencies.swap_remove(index);
            }
        }
        if self
            .store
            .claims
            .reserve(&key, self.attempt.holder, self.attempt.id)?
        {
            self.attempt.claims.push(key.clone());
        }
        if guarded(&key) {
            self.attempt.guarded.push(key);
        }
        Ok(())
    }

    /// Reserve the namespace alias `name` in `protocol` (empty for global)
    /// under the alias admission rule.
    pub fn reserve_alias(&mut self, name: &str, protocol: &str) -> Result<(), StoreError> {
        self.store
            .claims
            .reserve_alias(name, protocol, self.attempt.holder, self.attempt.id)?;
        self.attempt.claims.push(ClaimKey::Alias {
            name: name.to_owned(),
            protocol: protocol.to_owned(),
        });
        Ok(())
    }

    /// Release `key`, which this namespace holds, with the publication.
    pub fn release(&mut self, key: ClaimKey) {
        if self
            .store
            .claims
            .release(&key, self.attempt.holder, self.attempt.id)
        {
            self.attempt.claims.push(key.clone());
        }
        if guarded(&key) {
            self.attempt.guarded.push(key);
        }
    }

    /// Hold `key`'s stripe across this attempt's store: the attempt
    /// rewrites a row of `key` it already holds.
    pub fn attempt_guard(&mut self, key: ClaimKey) {
        if guarded(&key) {
            self.attempt.guarded.push(key);
        }
    }

    /// Reserve the succession link `record` for this attempt, on the
    /// execution's allowance.
    pub fn reserve_succession(&mut self, record: &Succession) -> Result<(), StoreError> {
        if self.store.successions.reserve(
            record,
            self.attempt.holder.namespace,
            self.attempt.id,
            self.meter,
            &self.store.encoding_storage,
        )? {
            self.attempt.successions.push(record.old_anchor.clone());
        }
        Ok(())
    }
}

/// A read against the candidate view.
pub struct ReadCx<'e> {
    pub store: &'e InMemoryStore,
    pub view: &'e NamespaceView,
    pub ns: &'e NamespaceRef,
    pub now: ClockMs,
    pub holder: Holder,
    dependencies: &'e RefCell<Vec<Dependency>>,
}

impl ReadCx<'_> {
    /// Record an authorization dependency for validation at publication.
    pub fn depend(&self, dependency: Dependency) {
        self.dependencies.borrow_mut().push(dependency);
    }
}

/// Private namespace execution. Dropping it aborts every write.
#[must_use = "publish the execution or drop it to abort"]
pub struct MemoryExecution<'a> {
    store: &'a InMemoryStore,
    clock: Arc<dyn Clock>,
    slot: Arc<Slot>,
    base: Arc<NamespaceView>,
    candidate: NamespaceView,
    namespace: NamespaceRef,
    now: ClockMs,
    failed: Cell<bool>,
    operation: Option<([u8; 32], Kappa)>,
    deadline: Option<Instant>,
    /// The execution's one allowance: the store's publication limit, its
    /// deadline brought forward to the execution's. Reads through `&self`
    /// borrow it ([`Self::lend`]); writes and publication take it through
    /// `&mut self`.
    meter: RefCell<WorkMeter>,
    attempt: Attempt,
    dependencies: RefCell<Vec<Dependency>>,
    /// Who owns the attempt's claims, reservations and resources.
    lifecycle: Lifecycle,
    // Declared last: the writer gate is released after everything above,
    // so no other execution of the namespace starts before this one's
    // bookkeeping is done.
    _writer: WriterToken,
}

/// Who owns an execution's obligations.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    /// The execution owns them unsigned; dropping it aborts them.
    Active,
    /// They moved to the namespace slot's custody (`Pending`) before the
    /// signing coordinate was consumed; the slot owns them until the
    /// publication is settled.
    Transferred,
}

impl Drop for MemoryExecution<'_> {
    fn drop(&mut self) {
        if self.lifecycle == Lifecycle::Active {
            self.attempt.settle(self.store, false);
        }
    }
}

/// A publication whose signing coordinate is consumed and which is not
/// published, owned by its namespace slot (`Slot::pending`) with everything
/// it needs to complete or to stay retained: the exact candidate view and
/// its base, the attempt's claims and succession reservations, the recorded
/// dependencies, the receipt lookup, the authority it is signed under (and,
/// for an activation, the outgoing authority it succeeds), its stage with
/// the resources that stage owns, the projection changes, the retention its
/// generated records will hold, and all the work spent on it.
pub struct Pending {
    namespace: NamespaceRef,
    now: ClockMs,
    base: Arc<NamespaceView>,
    candidate: NamespaceView,
    attempt: Attempt,
    dependencies: RefCell<Vec<Dependency>>,
    receipt: Option<([u8; 32], Kappa)>,
    authority: Arc<EpochAuthority>,
    installs: Option<Kappa>,
    /// The unsigned root naming the candidate.
    identity: Kappa,
    /// The coordinate the publication consumes.
    epoch_number: u64,
    /// Absent only while a stage hands its resources to the next inside
    /// [`Pending::advance`]; observing it absent is a custody fault.
    stage: Option<Stage>,
    changes: Changes,
    /// The retention every generated record will hold, reserved before the
    /// coordinate was consumed; each installed record takes its share.
    retention: Reservation,
    /// All the work spent on this publication: its execution's, and every
    /// resolution attempt's, failed ones included.
    work: Work,
    /// Why the publication can never be installed, once resolution found
    /// it so.
    terminal: Option<String>,
}

/// How far a pending publication progressed. Each stage owns what the rest
/// of the publication needs.
enum Stage {
    /// In custody; its coordinate is not yet consumed.
    Unreserved { epoch: EpochCandidate },
    /// Signing and generating the signed root's evidence at the consumed
    /// coordinate `reservation`.
    Signing {
        epoch: EpochCandidate,
        reservation: SigningReservation,
    },
    /// Installing the signed publication into the candidate: `records` are
    /// the generated records not yet installed; `head` once the root is the
    /// candidate's head; `receipt` once the receipt lookup is attached (or
    /// there is none).
    Installing {
        root: EpochRoot,
        records: Vec<GeneratedRecord>,
        head: bool,
        receipt: bool,
    },
    /// Registering the candidate's projection changes; `next` is the first
    /// registration not yet made.
    Registering { root: Kappa, next: usize },
}

impl Pending {
    fn lost(&self) -> StoreError {
        StoreError::Internal(format!(
            "the retained publication of epoch {} of {} lost its stage",
            self.epoch_number, self.namespace
        ))
    }

    /// The signing candidate, while the publication is signing.
    #[cfg(test)]
    pub(crate) const fn epoch(&self) -> Option<&EpochCandidate> {
        match &self.stage {
            Some(Stage::Unreserved { epoch } | Stage::Signing { epoch, .. }) => Some(epoch),
            Some(Stage::Installing { .. } | Stage::Registering { .. }) | None => None,
        }
    }

    /// The signed root, once one was formed.
    #[cfg(test)]
    pub(crate) fn signed_root(&self) -> Option<Kappa> {
        match &self.stage {
            Some(Stage::Unreserved { epoch } | Stage::Signing { epoch, .. }) => {
                epoch.signed_root().map(|root| root.kappa().clone())
            }
            Some(Stage::Installing { root, .. }) => Some(root.kappa().clone()),
            Some(Stage::Registering { root, .. }) => Some(root.clone()),
            None => None,
        }
    }

    /// All the work spent on this publication so far.
    #[cfg(test)]
    pub(crate) const fn work(&self) -> &Work {
        &self.work
    }

    /// The retention still held by the publication for records it has not
    /// installed.
    #[cfg(test)]
    pub(crate) const fn retention(&self) -> u64 {
        self.retention.amount()
    }

    /// Hold the stripes of every authorization key this publication depends
    /// on or writes, the protection work admitted against `meter` first and
    /// what it consumed added to the publication's work.
    fn hold_stripes<'s>(
        &mut self,
        stripes: &'s Stripes,
        meter: &mut WorkMeter,
    ) -> Result<HeldStripes<'s>, StoreError> {
        let before = *meter.used();
        let charged = meter.charge_all(&protection_work(
            &self.dependencies.borrow(),
            &self.attempt.guarded,
        ));
        self.work = self.work.saturating_add(&meter.used().since(&before));
        charged?;
        Ok(stripes.hold(protected_keys(
            &self.dependencies.borrow(),
            &self.attempt.guarded,
        )))
    }

    /// Why this publication can no longer be installed at `now`, if it
    /// cannot: its namespace no longer holds the instance and predecessor
    /// it was prepared on, the authority it is signed under (for an
    /// activation, the outgoing authority it succeeds) is no longer the
    /// installed one, or an authorization it depends on changed or expired.
    /// None of these can revert. Called under the writer, the activation
    /// gate and the dependency stripes.
    fn standing(&self, store: &InMemoryStore, slot: &Slot, now: ClockMs) -> Option<String> {
        let published = slot.view.load();
        if published.incarnation != self.base.incarnation
            || published.revision != self.base.revision
            || published.epoch != self.base.epoch
        {
            return Some(format!(
                "{} no longer holds the instance and predecessor this publication was prepared on",
                self.namespace
            ));
        }
        let installed = store.authority.load();
        let expected = self
            .installs
            .as_ref()
            .unwrap_or_else(|| self.authority.anchor());
        if installed.anchor() != expected {
            return Some(format!(
                "the installed authority is {}, not {expected}, which this publication requires",
                installed.anchor()
            ));
        }
        if !dependencies_hold(store, &self.dependencies.borrow(), now) {
            return Some(
                "an authorization this publication depends on changed or expired before it could be installed"
                    .into(),
            );
        }
        None
    }

    /// Charge protected observations before checking them. Both a continuation
    /// and its final publication check contribute to retained cumulative work.
    fn check_standing(
        &mut self,
        store: &InMemoryStore,
        slot: &Slot,
        meter: &mut WorkMeter,
        clock: &dyn Clock,
    ) -> Result<(), StoreError> {
        meter.charge(
            Dimension::Entries,
            (self.dependencies.borrow().len() as u64).saturating_add(2),
        )?;
        if let Some(reason) = self.standing(store, slot, clock.now()?) {
            self.terminal = Some(reason.clone());
            return Err(StoreError::Conflict(reason));
        }
        Ok(())
    }

    /// What a caller observes of this retained publication after `cause`
    /// stopped it, derived from what it owns: the coordinate, the
    /// candidate, a signed root only once one was formed, its phase, and
    /// whether resolution can still publish it. A publication whose stage is
    /// lost is a custody fault, reported as such.
    fn outcome(&self, cause: &StoreError) -> StoreError {
        let (phase, signed_root, disposition) = match &self.stage {
            None => return self.lost(),
            Some(Stage::Unreserved { .. }) => {
                return StoreError::Internal(format!(
                    "epoch {} of {} is in custody without its consumed coordinate: {cause}",
                    self.epoch_number, self.namespace
                ));
            }
            Some(Stage::Signing { epoch, .. }) => (
                epoch.phase(),
                epoch.signed_root().map(|root| root.kappa().clone()),
                epoch.disposition(),
            ),
            Some(Stage::Installing { root, .. }) => (
                PublicationPhase::Installing,
                Some(root.kappa().clone()),
                RecoveryDisposition::Resumable,
            ),
            Some(Stage::Registering { root, .. }) => (
                PublicationPhase::Registering,
                Some(root.clone()),
                RecoveryDisposition::Resumable,
            ),
        };
        let (disposition, cause) = self.terminal.as_ref().map_or_else(
            || (disposition, cause.to_string()),
            |reason| (RecoveryDisposition::Terminal, reason.clone()),
        );
        StoreError::PublicationRetained(Box::new(RetainedPublication {
            namespace: *self.namespace.id(),
            incarnation: self.base.incarnation_bytes(),
            epoch_number: self.epoch_number,
            candidate: self.identity.clone(),
            signed_root,
            phase,
            disposition,
            cause,
        }))
    }

    /// Continue this publication from its recorded progress, each unit of
    /// work admitted against `meter` before it runs, and publish it. What
    /// the attempt spent, failed or not, is added to the publication's work.
    fn advance(
        &mut self,
        store: &InMemoryStore,
        slot: &Slot,
        meter: &mut WorkMeter,
        clock: &dyn Clock,
    ) -> Result<Published, StoreError> {
        let before = *meter.used();
        let advanced = self.run(store, slot, meter, clock);
        self.work = self.work.saturating_add(&meter.used().since(&before));
        advanced
    }

    fn run(
        &mut self,
        store: &InMemoryStore,
        slot: &Slot,
        meter: &mut WorkMeter,
        clock: &dyn Clock,
    ) -> Result<Published, StoreError> {
        if let Some(reason) = &self.terminal {
            return Err(StoreError::Conflict(reason.clone()));
        }
        self.check_standing(store, slot, meter, clock)?;
        loop {
            match self.stage.take() {
                None => return Err(self.lost()),
                Some(Stage::Unreserved { epoch }) => {
                    self.stage = Some(Stage::Unreserved { epoch });
                    return Err(StoreError::Internal(format!(
                        "epoch {} of {} is in custody without its consumed coordinate",
                        self.epoch_number, self.namespace
                    )));
                }
                Some(Stage::Signing {
                    mut epoch,
                    reservation,
                }) => {
                    if let Err(error) = epoch.sign(&self.authority, &reservation, meter) {
                        self.stage = Some(Stage::Signing { epoch, reservation });
                        return Err(error);
                    }
                    match epoch.into_publication(reservation) {
                        Ok(publication) => {
                            let (root, records) = publication.into_generated();
                            self.stage = Some(Stage::Installing {
                                root,
                                records,
                                head: false,
                                receipt: self.receipt.is_none(),
                            });
                        }
                        Err(returned) => {
                            let (epoch, reservation) = *returned;
                            self.stage = Some(Stage::Signing { epoch, reservation });
                            return Err(StoreError::Internal(
                                "a completely signed candidate did not yield its publication"
                                    .into(),
                            ));
                        }
                    }
                }
                Some(Stage::Installing {
                    root,
                    mut records,
                    mut head,
                    mut receipt,
                }) => {
                    let installed =
                        self.install(store, &root, &mut records, &mut head, &mut receipt, meter);
                    if let Err(error) = installed {
                        self.stage = Some(Stage::Installing {
                            root,
                            records,
                            head,
                            receipt,
                        });
                        return Err(error);
                    }
                    // Every record holds its share; what the bound admitted
                    // beyond them is released.
                    if let Err(error) = self.retention.shrink(0) {
                        self.stage = Some(Stage::Installing {
                            root,
                            records,
                            head,
                            receipt,
                        });
                        return Err(StoreError::Internal(format!(
                            "publication retention: {error}"
                        )));
                    }
                    self.stage = Some(Stage::Registering {
                        root: root.kappa().clone(),
                        next: 0,
                    });
                }
                Some(Stage::Registering { root, mut next }) => {
                    let registered =
                        store
                            .projections
                            .register_from(&self.changes, &mut next, meter);
                    self.stage = Some(Stage::Registering {
                        root: root.clone(),
                        next,
                    });
                    registered?;
                    self.check_standing(store, slot, meter, clock)?;
                    return Ok(self.publish(store, slot, root));
                }
            }
        }
    }

    /// Install the signed publication into the candidate, one unit at a
    /// time, each charged before it runs and recorded once it is done:
    /// each generated record (its bytes moved in, its share of the
    /// retention split off before it leaves `records`), the head, and the
    /// receipt lookup. A refused unit leaves every completed one recorded
    /// and the rest owned.
    fn install(
        &mut self,
        store: &InMemoryStore,
        root: &EpochRoot,
        records: &mut Vec<GeneratedRecord>,
        head: &mut bool,
        receipt: &mut bool,
        meter: &mut WorkMeter,
    ) -> Result<(), StoreError> {
        while let Some(record) = records.last() {
            let length = record.content.len() as u64;
            let share = length.saturating_add(RECORD_OVERHEAD);
            let charge = self.retention.split(share).map_err(|error| {
                StoreError::Internal(format!(
                    "a generated record exceeds the retention reserved for it: {error}"
                ))
            })?;
            if let Err(error) = meter.charge_all(&[
                (Dimension::BytesHashed, length),
                (Dimension::BytesAllocated, RECORD_OVERHEAD),
                (Dimension::Entries, GENERATED_RECORD_ROWS),
            ]) {
                self.retention.merge(charge).map_err(|merge| {
                    StoreError::Internal(format!("publication retention: {merge}"))
                })?;
                return Err(error.into());
            }
            let Some(record) = records.pop() else {
                return Err(StoreError::Internal(
                    "a generated record left custody before its installation".into(),
                ));
            };
            WriteCx::new(
                store,
                &mut self.candidate,
                &self.namespace,
                self.now,
                &mut self.attempt,
                &self.dependencies,
                meter,
            )
            .install_generated(record, charge, &self.base, &mut self.changes);
        }
        if !*head {
            meter.charge(Dimension::Entries, HEAD_ROWS)?;
            WriteCx::new(
                store,
                &mut self.candidate,
                &self.namespace,
                self.now,
                &mut self.attempt,
                &self.dependencies,
                meter,
            )
            .install_head(root, &mut self.changes);
            *head = true;
        }
        if !*receipt {
            meter.charge(Dimension::Entries, RECEIPT_ROWS)?;
            if let Some((identity, receipt_identity)) = &self.receipt {
                self.candidate
                    .operations
                    .insert(*identity, (root.kappa().clone(), receipt_identity.clone()));
            }
            *receipt = true;
        }
        Ok(())
    }

    /// Store the candidate (the publication decision) and settle what the
    /// store decided: claims and succession reservations committed, lost
    /// projection keys unregistered, the lineage summary raised and, for an
    /// activation, its authority installed under the exclusive gate the
    /// caller holds. Nothing here can fail.
    fn publish(&mut self, store: &InMemoryStore, slot: &Slot, root: Kappa) -> Published {
        let sealed_ms = self.candidate.latest_epoch_ms;
        slot.view.store(Arc::new(mem::take(&mut self.candidate)));
        self.attempt.settle(store, true);
        store.projections.unregister(&self.changes);
        if let Some(sealed_ms) = sealed_ms {
            store.latest_epoch_ms.fetch_max(sealed_ms, Ordering::AcqRel);
        }
        if self.installs.is_some() {
            store.authority.store(Arc::clone(&self.authority));
            store.activation_unresolved.store(false, Ordering::SeqCst);
        }
        Published {
            epoch_number: self.epoch_number,
            root,
        }
    }
}

impl InMemoryStore {
    fn custody(slot: &Slot) -> Result<MutexGuard<'_, Option<Pending>>, StoreError> {
        slot.pending
            .lock()
            .map_err(|_| StoreError::Internal("publication custody lock poisoned".into()))
    }

    /// Continue the publication `namespace` retains, if any
    /// (`ExecutionStore::resolve_publication`).
    ///
    /// The namespace's writer, then the activation gate (exclusive for an
    /// activation, shared otherwise), then the stripes of every
    /// authorization key the publication depends on or writes are taken,
    /// in the order every publication takes them. Under them the current
    /// time is read from `clock`, and the publication is checked against
    /// the instance and predecessor it was prepared on, the installed
    /// authority, and every dependency at that time; one that can no longer
    /// hold makes it terminal. Otherwise it continues from its recorded
    /// progress, each unit admitted against `meter`, and is published with
    /// the root it was signed with. The signer is never invoked again.
    pub(crate) fn resolve_retained(
        &self,
        namespace: &NamespaceRef,
        clock: &dyn Clock,
        meter: &mut WorkMeter,
    ) -> Result<PublicationResolution, StoreError> {
        let slot = self.slot(namespace.id())?;
        let _writer = slot.gate.acquire();
        let installs = match Self::custody(&slot)?.as_ref() {
            None => return Ok(PublicationResolution::Clear),
            Some(pending) => pending.installs.clone(),
        };
        let poisoned = || StoreError::Internal("authority activation lock poisoned".into());
        let exclusive = match &installs {
            Some(_) => Some(self.activation.write().map_err(|_| poisoned())?),
            None => None,
        };
        let shared = match &installs {
            Some(_) => None,
            None => Some(self.activation.read().map_err(|_| poisoned())?),
        };
        let mut custody = Self::custody(&slot)?;
        let Some(pending) = custody.as_mut() else {
            return Ok(PublicationResolution::Clear);
        };
        let stripes = match pending.hold_stripes(&self.stripes, meter) {
            Ok(stripes) => stripes,
            Err(cause) => {
                return match pending.outcome(&cause) {
                    StoreError::PublicationRetained(retained) => {
                        Ok(PublicationResolution::Retained(retained))
                    }
                    fault => Err(fault),
                };
            }
        };
        let resolution = match pending.advance(self, &slot, meter, clock) {
            Ok(published) => Ok(PublicationResolution::Published(published)),
            Err(cause) => match pending.outcome(&cause) {
                StoreError::PublicationRetained(retained) => {
                    Ok(PublicationResolution::Retained(retained))
                }
                fault => Err(fault),
            },
        };
        if matches!(resolution, Ok(PublicationResolution::Published(_))) {
            *custody = None;
        }
        drop(stripes);
        drop(custody);
        drop(shared);
        drop(exclusive);
        resolution
    }
}

impl<'a> MemoryExecution<'a> {
    pub(crate) fn new(
        store: &'a InMemoryStore,
        writer: WriterToken,
        slot: Arc<Slot>,
        namespace: &NamespaceRef,
        now: ClockMs,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, StoreError> {
        let base = slot.view.load_full();
        let mut candidate = NamespaceView::clone(&base);
        candidate.revision = base.next_revision()?;
        let holder = Holder {
            namespace: *namespace.id(),
            incarnation: base.incarnation,
        };
        Ok(Self {
            store,
            clock,
            slot,
            base,
            candidate,
            namespace: namespace.clone(),
            now,
            failed: Cell::new(false),
            operation: None,
            deadline: None,
            meter: RefCell::new(WorkMeter::new(store.publication_work)),
            attempt: Attempt {
                id: store.attempt()?,
                holder,
                claims: Vec::new(),
                successions: Vec::new(),
                guarded: Vec::new(),
            },
            dependencies: RefCell::new(Vec::new()),
            lifecycle: Lifecycle::Active,
            _writer: writer,
        })
    }

    pub(crate) const fn candidate(&self) -> &NamespaceView {
        &self.candidate
    }

    pub(super) const fn namespace_ref(&self) -> &NamespaceRef {
        &self.namespace
    }

    pub(super) const fn issued_at(&self) -> ClockMs {
        self.now
    }

    /// Bind this execution to an operation identity; publication then
    /// requires a persisted result.
    pub(crate) const fn with_operation(mut self, identity: [u8; 32], request: Kappa) -> Self {
        self.operation = Some((identity, request));
        self
    }

    fn ensure_active(&self) -> Result<(), StoreError> {
        if self.failed.get() {
            return Err(StoreError::Conflict("epoch execution has failed".into()));
        }
        Ok(())
    }

    fn admit<T>(&self, result: Result<T, StoreError>) -> Result<T, StoreError> {
        if result.is_err() {
            self.failed.set(true);
        }
        result
    }

    const fn read_cx(&self) -> ReadCx<'_> {
        ReadCx {
            store: self.store,
            view: &self.candidate,
            ns: &self.namespace,
            now: self.now,
            holder: self.attempt.holder,
            dependencies: &self.dependencies,
        }
    }

    pub(super) fn read<T>(
        &self,
        read: impl FnOnce(&ReadCx<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.ensure_active()?;
        self.admit(read(&self.read_cx()))
    }

    /// Keyed read: absence is a value and does not latch the execution.
    pub(super) fn lookup<T>(
        &self,
        read: impl FnOnce(&ReadCx<'_>) -> Result<T, StoreError>,
    ) -> Result<Option<T>, StoreError> {
        self.ensure_active()?;
        self.admit(kappa_store::absent(read(&self.read_cx())))
    }

    /// Run `operation` on this execution's allowance. An operation already
    /// holding the allowance cannot take it again: that is a defect,
    /// refused. Latching is the caller's: a read decides what absence is
    /// before a failure latches.
    pub(super) fn lend<T>(
        &self,
        operation: impl FnOnce(&mut dyn Meter) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        match self.meter.try_borrow_mut() {
            Ok(mut meter) => operation(&mut *meter),
            Err(_) => Err(StoreError::Internal(
                "an execution lent its allowance twice".into(),
            )),
        }
    }

    pub(super) fn write<T>(
        &mut self,
        write: impl FnOnce(&mut WriteCx<'_>) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        self.ensure_active()?;
        let result = write(&mut WriteCx::new(
            self.store,
            &mut self.candidate,
            &self.namespace,
            self.now,
            &mut self.attempt,
            &self.dependencies,
            self.meter.get_mut(),
        ));
        self.admit(result)
    }

    /// The execution's namespace after a rename inside it.
    pub(super) fn set_namespace(&mut self, namespace: NamespaceRef) {
        self.namespace = namespace;
    }

    /// Validate at fresh time under the stripes of every dependency key.
    fn dependencies_hold(&self) -> Result<bool, StoreError> {
        Ok(dependencies_hold(
            self.store,
            &self.dependencies.borrow(),
            self.clock.now()?,
        ))
    }

    /// Publish this execution as the governing epoch of an authority
    /// activation: sealed by the activation's candidate, under the
    /// exclusive gate the activation holds.
    pub(crate) fn publish_under_activation(
        self,
        activation: &ActivationAuthority<'_, '_>,
    ) -> Result<Published, StoreError> {
        self.finish(None, Some(activation))
    }

    /// Seal and publish the candidate (see the module documentation).
    fn finish(
        mut self,
        result: Option<Vec<u8>>,
        activation: Option<&ActivationAuthority<'_, '_>>,
    ) -> Result<Published, StoreError> {
        self.ensure_active()?;
        // Preserve the execution deadline outcome before the work meter
        // can turn an already-expired deadline into a generic work refusal.
        self.check_deadline()?;
        let store = self.store;
        // The authority this epoch is signed under stays in force until the
        // candidate is stored: an activation's candidate under the exclusive
        // gate its activation holds, otherwise the installed authority under
        // the shared gate, which no activation can pass.
        let shared =
            match activation {
                Some(_) => None,
                None => Some(store.activation.read().map_err(|_| {
                    StoreError::Internal("authority activation lock poisoned".into())
                })?),
            };
        if activation.is_none() && store.activation_unresolved.load(Ordering::SeqCst) {
            return Err(StoreError::AuthorityUnresolved {
                outgoing: Box::new(store.authority.load().anchor().clone()),
            });
        }
        let (authority, installs) = activation.map_or_else(
            || (store.authority.load_full(), None),
            |activation| {
                (
                    Arc::clone(activation.candidate()),
                    Some(activation.outgoing().clone()),
                )
            },
        );
        let receipt = self.persist_receipt(result)?;
        // Every dependency is protected from here until the store and
        // validated before the seal, so no revocation can slip between the
        // validation the signature attests and the publication.
        self.meter.get_mut().charge_all(&protection_work(
            &self.dependencies.borrow(),
            &self.attempt.guarded,
        ))?;
        let stripes = store.stripes.hold(protected_keys(
            &self.dependencies.borrow(),
            &self.attempt.guarded,
        ));
        if !self.dependencies_hold()? {
            return Err(StoreError::Conflict(
                "an authorization row this execution depends on changed before it published".into(),
            ));
        }
        self.check_deadline()?;
        let epoch = self.write(|cx| cx.prepare_seal(&authority, None))?;
        let (changes, retention) = self.reserve_completion(&epoch)?;
        let outcome = self.publish_from_custody(Sealed {
            epoch,
            authority,
            installs,
            receipt,
            changes,
            retention,
        });
        drop(stripes);
        drop(shared);
        outcome
    }

    /// Apply the operation receipt's transition, when the execution is bound
    /// to an operation; returns the operation identity and the receipt's.
    fn persist_receipt(
        &mut self,
        result: Option<Vec<u8>>,
    ) -> Result<Option<([u8; 32], Kappa)>, StoreError> {
        match (self.operation.clone(), result) {
            (Some((identity, request)), Some(result)) => {
                let receipt = self.write(|cx| cx.publish_receipt(identity, request, result))?;
                Ok(Some((identity, receipt)))
            }
            (Some(_), None) => Err(StoreError::Conflict(
                "operation execution requires a persisted result".into(),
            )),
            (None, Some(_)) => Err(StoreError::Conflict(
                "execution has no operation identity".into(),
            )),
            (None, None) => Ok(None),
        }
    }

    /// A caller that has already timed out must not observe a publication it
    /// was told had failed; past the seal nothing can refuse, so the
    /// deadline is decided before it.
    fn check_deadline(&self) -> Result<(), StoreError> {
        let Some(deadline) = self.deadline else {
            return Ok(());
        };
        let overrun = Instant::now().saturating_duration_since(deadline);
        if overrun.is_zero() {
            return Ok(());
        }
        Err(StoreError::DeadlineExceeded {
            namespace: *self.namespace.id(),
            overrun_ms: u64::try_from(overrun.as_millis()).unwrap_or(u64::MAX),
        })
    }

    /// The projection changes of everything but the evidence the signed root
    /// generates, charged and given room for that evidence, and the retention
    /// every generated record will hold: both reserved before the coordinate
    /// is consumed.
    fn reserve_completion(
        &mut self,
        epoch: &EpochCandidate,
    ) -> Result<(Changes, Reservation), StoreError> {
        let meter = self.meter.get_mut();
        let changes = Changes::between(*self.namespace.id(), &self.base, &self.candidate, meter)
            .and_then(|mut changes| {
                changes.reserve_generated(epoch.generated_records(), meter)?;
                Ok(changes)
            });
        let changes = self.admit(changes)?;
        let retention = self.admit(
            self.store
                .publication_retention
                .reserve(retention_bound(epoch))
                .map_err(|error| StoreError::CapacityExceeded(error.to_string())),
        )?;
        Ok((changes, retention))
    }

    /// Transfer the sealed candidate and every obligation to the slot's
    /// custody, consume the coordinate, and continue the publication from
    /// custody on what remains of the execution's allowance (steps 6 to 9 of
    /// the module documentation).
    fn publish_from_custody(&mut self, sealed: Sealed) -> Result<Published, StoreError> {
        let Sealed {
            epoch,
            authority,
            installs,
            receipt,
            changes,
            retention,
        } = sealed;
        let store = self.store;
        let base = Arc::clone(&self.base);
        // Custody: the slot takes the candidate and every obligation before
        // the coordinate is consumed, in storage it already holds. A slot
        // already holding a retained publication is fenced by it, and the
        // caller is told which one.
        let slot = Arc::clone(&self.slot);
        let mut custody = self.admit(InMemoryStore::custody(&slot))?;
        if let Some(retained) = custody.as_ref() {
            let fenced = retained.outcome(&StoreError::Conflict(format!(
                "{} is fenced until its retained publication is resolved",
                self.namespace
            )));
            return self.admit(Err(fenced));
        }
        let number = epoch.epoch_number();
        let timestamp_ms = epoch.timestamp_ms();
        let pending = custody.insert(Pending {
            namespace: self.namespace.clone(),
            now: self.now,
            base,
            candidate: mem::take(&mut self.candidate),
            attempt: self.attempt.take_obligations(),
            dependencies: RefCell::new(self.dependencies.take()),
            receipt,
            authority,
            installs,
            identity: epoch.unsigned_identity().clone(),
            epoch_number: number,
            stage: Some(Stage::Unreserved { epoch }),
            changes,
            retention,
            work: *self.meter.get_mut().used(),
            terminal: None,
        });
        self.lifecycle = Lifecycle::Transferred;

        // The coordinate. A refusal here consumed nothing: the obligations
        // come back out of custody and are aborted, and the candidate and
        // its retention are released with it.
        match reserve_coordinate(&slot.signed, &pending.namespace, number) {
            Ok(reservation) => match pending.stage.take() {
                Some(Stage::Unreserved { epoch }) => {
                    pending.stage = Some(Stage::Signing { epoch, reservation });
                    store
                        .latest_epoch_ms
                        .fetch_max(timestamp_ms, Ordering::AcqRel);
                    if pending.installs.is_some() {
                        store.activation_unresolved.store(true, Ordering::SeqCst);
                    }
                }
                other => {
                    // The coordinate is consumed: whatever custody holds
                    // stays there, reported as the fault it is.
                    pending.stage = other;
                    let fault = pending.lost();
                    return Err(fault);
                }
            },
            Err(error) => {
                if let Some(pending) = custody.take() {
                    pending.attempt.settle(store, false);
                }
                return Err(error);
            }
        }

        // Sign, generate, install, register and publish from custody; a
        // publication stopped on the way stays there and is reported as it
        // is.
        let meter = self.meter.get_mut();
        let clock = self.clock.as_ref();
        let advanced = custody.as_mut().map(|pending| {
            pending
                .advance(store, &slot, meter, clock)
                .map_err(|cause| pending.outcome(&cause))
        });
        match advanced {
            Some(Ok(published)) => {
                *custody = None;
                Ok(published)
            }
            Some(Err(retained)) => Err(retained),
            None => Err(StoreError::Internal("publication custody emptied".into())),
        }
    }
}

/// A prepared seal and what reaches custody with it.
struct Sealed {
    epoch: EpochCandidate,
    authority: Arc<EpochAuthority>,
    installs: Option<Kappa>,
    receipt: Option<([u8; 32], Kappa)>,
    changes: Changes,
    retention: Reservation,
}

impl Execution for MemoryExecution<'_> {
    fn set_deadline(&mut self, deadline: Instant) {
        self.deadline = Some(deadline);
        self.meter.get_mut().tighten_deadline(deadline);
    }
    fn publish(self: Box<Self>) -> Result<Published, StoreError> {
        (*self).finish(None, None)
    }
    fn publish_result(self: Box<Self>, result: Vec<u8>) -> Result<Published, StoreError> {
        (*self).finish(Some(result), None)
    }
    fn abort(self: Box<Self>) -> Result<(), StoreError> {
        drop(self);
        Ok(())
    }
}
