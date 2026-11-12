//! Durable epoch signing authority: activation as a governing epoch of the
//! control namespace, and recovery of the authority from that evidence.
//!
//! An activation commits exactly when its governing epoch commits: the
//! control namespace's epoch, sealed and signed under the exclusive
//! activation gate by the private candidate, records the transition under
//! `_authority/{position}`. The candidate is installed only after that
//! commit, still under the gate; the gate then opens, and the registry's
//! history row is projected from the evidence afterwards, so a slow
//! registry never holds ordinary publication behind the gate. The durable
//! intent stays until that projection lands: it is the projection's
//! maintenance obligation, and the next activation completes it under its
//! own gate before it records another. Restart recovers the authority from
//! the evidence: every history row is verified against it, and an
//! activation whose outcome the previous handle never learned is resolved
//! from it (`authority_evidence`).

use std::sync::Arc;

use kappa_store::error::StoreError;
use kappa_store::{
    Activation, ActivationDomain, AuthorityKey, AuthorityRotationError, AuthorityTransition, Axis,
    EpochAuthority, ExecutionReads, Kappa, NamespaceRef, VerifiedContent, VerifiedSuccession,
    WitnessEvidence, witness_standing,
};

use crate::PersistentStore;
use crate::epoch_execution::ActivationOutcome;
use crate::storage::IncarnationUse;

#[path = "authority_custody.rs"]
mod custody_recovery;
#[path = "authority_evidence.rs"]
mod evidence;
pub use evidence::{ActivationHold, ActivationIntent, activation_tag};

/// Prefix of the control namespace's tags naming each admitted transition.
pub const AUTHORITY_TAG_PREFIX: &str = "_authority/";

/// Value-encryption context of authority history rows, bound to the row
/// position so a transition cannot be moved within the chain.
fn row_context(position: u64) -> String {
    crate::encrypted::bound("authority", &position.to_be_bytes())
}

/// Public verification material of `authority`.
fn key_of(authority: &kappa_crypto::SigningAuthority) -> Result<AuthorityKey, StoreError> {
    let signer = authority.signer();
    AuthorityKey::new(signer.algorithm(), signer.public_key())
}

impl PersistentStore {
    /// Restore the authority from its governing evidence and select its
    /// current authority: the one among `configured` and `alternates` whose
    /// key is the evidenced chain's last. A database without history records
    /// `configured` as its origin, unless `require_history` refuses that.
    ///
    /// Every history row is re-admitted and must be the record its control
    /// namespace committed; the open is refused otherwise, and nothing is
    /// changed, so the database and the key custody stay as they were. The
    /// refusal says which recovery the operator faces:
    ///
    /// - `NotSupported`: the control namespace holds no record for the row.
    ///   The row predates governed activation, or its evidence was lost; a
    ///   history row is never promoted into governing evidence, so only an
    ///   explicit authenticated transition can adopt it.
    /// - `Unavailable`: the control namespace's storage is missing or
    ///   cannot be read; the evidence may exist.
    /// - `Rejected`: the evidence exists and contradicts the row.
    ///
    /// An activation intent left by a handle that never learned its outcome
    /// is resolved from the evidence: a committed record is projected into
    /// the history and selected, an absent one withdraws the intent. Any
    /// persisted epoch this history does not admit fails the subsequent
    /// epoch recovery.
    pub(crate) fn restore_authority(
        &self,
        configured: kappa_crypto::SigningAuthority,
        alternates: Vec<kappa_crypto::SigningAuthority>,
        require_history: bool,
    ) -> Result<(), StoreError> {
        let (rows, intent) = self.authority_rows()?;
        let Some((origin, projected)) = rows.split_first() else {
            if intent.is_some() {
                return Err(StoreError::Internal(
                    "an activation intent is recorded without an authority origin".into(),
                ));
            }
            if require_history {
                return Err(StoreError::AuthorityHistoryAbsent {
                    offered: alternates.len() + 1,
                });
            }
            let authority = EpochAuthority::new(configured)?;
            self.record_origin(&authority.origin().to_bytes()?)?;
            self.authority.store(Arc::new(authority));
            return Ok(());
        };
        let origin = AuthorityKey::from_bytes(origin)?;
        let mut transitions = Vec::with_capacity(projected.len() + 1);
        for (index, row) in projected.iter().enumerate() {
            let position = index as u64 + 1;
            let transition = AuthorityTransition::from_bytes(row, origin.anchor())?;
            let domain = &transition.activation().domain;
            match self.activation_evidence(position, domain, origin.anchor()) {
                Ok(Some((bytes, _))) if bytes == *row => {}
                Ok(Some(_)) => {
                    return Err(StoreError::Rejected(format!(
                        "authority history row {position} contradicts the record its control namespace committed"
                    )));
                }
                Ok(None) => {
                    return Err(StoreError::NotSupported(format!(
                        "authority history row {position} has no governing activation evidence in control namespace {}; a history without that evidence is adopted only by an explicit authenticated transition",
                        hex::encode(domain.control)
                    )));
                }
                Err(StoreError::NotFound(detail)) => {
                    return Err(StoreError::Unavailable(format!(
                        "the storage of control namespace {} holding authority transition {position} is missing: {detail}",
                        hex::encode(domain.control)
                    )));
                }
                Err(error) => return Err(error),
            }
            transitions.push(transition);
        }
        if let Some(intent) = &intent {
            if let Some(transition) =
                self.resolve_activation_intent(intent, transitions.len() as u64, origin.anchor())?
            {
                transitions.push(transition);
            }
        }
        let head = transitions
            .last()
            .map_or(&origin, AuthorityTransition::incoming)
            .clone();
        if let Some(intent) = &intent {
            self.restore_retained_authority(
                intent,
                &origin,
                &transitions,
                std::iter::once(&configured).chain(alternates.iter()),
            )?;
        }
        // At most one candidate holds the chain's last key; when none does,
        // `restore` refuses the configured authority naming both anchors.
        let mut current = configured;
        for alternate in alternates {
            if head == key_of(&alternate)? {
                current = alternate;
                break;
            }
        }
        let restored = EpochAuthority::restore(origin, transitions, current)?;
        self.authority.store(Arc::new(restored));
        Ok(())
    }

    /// Resolve the pending `intent` against a history of `projected`
    /// transitions: the transition it committed, projected now, or `None`
    /// once it is withdrawn (its epoch never committed, or its row is
    /// already projected).
    fn resolve_activation_intent(
        &self,
        intent: &ActivationIntent,
        projected: u64,
        origin: &Kappa,
    ) -> Result<Option<AuthorityTransition>, StoreError> {
        if intent.position <= projected {
            // Projected with the row whose removal of the intent did not
            // land; the row was verified against its evidence above.
            self.withdraw_activation_intent(intent)?;
            return Ok(None);
        }
        if intent.position != projected + 1 {
            return Err(StoreError::Internal(format!(
                "activation intent {} is beyond the history's next position {}",
                intent.position,
                projected + 1
            )));
        }
        match self.activation_evidence(intent.position, &intent.domain, origin)? {
            Some((bytes, transition)) => {
                if Kappa::compute(Axis::Sha256, &bytes)? != intent.record {
                    return Err(StoreError::Rejected(format!(
                        "the record of authority transition {} is not the one its intent names",
                        intent.position
                    )));
                }
                self.project_activation(intent.position, &bytes, Some(intent))?;
                Ok(Some(transition))
            }
            None => {
                if self.activation_has_custody(intent)? {
                    self.authority_unresolved
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    return Ok(None);
                }
                self.withdraw_activation_intent(intent)?;
                Ok(None)
            }
        }
    }

    /// Hand epoch signing from the current authority to `next` through the
    /// admitted dual-signed `succession`, activated by a governing epoch of
    /// `control`.
    ///
    /// The control namespace's writer is taken first, then the exclusive
    /// activation gate: the order every publication takes them, the
    /// namespace's writer, then the gate shared. Under the gate a projection
    /// an earlier activation left unfinished is completed first, the
    /// succession is admitted against the installed authority, an intent is
    /// recorded durably, and the governing epoch, recording the transition
    /// under `_authority/{position}`, is sealed and committed by the
    /// private candidate, bound to that instance and its predecessor. The
    /// outcome owns the gate in every case: a committed candidate is
    /// installed, or an unknown outcome is recorded, before the gate opens,
    /// so each epoch is signed by the authority in force and none by an
    /// authority this call retired. The history row is projected from the
    /// committed evidence after the gate opens; until it lands the intent
    /// stays, owned by projection maintenance ([`Self::project_activations`],
    /// the next activation, or the next open).
    ///
    /// The succession must be effective by the governing epoch's time and
    /// strictly after every epoch the store has sealed, because an outgoing
    /// authority's window ends, exclusively, at its successor's effective
    /// time; every published epoch therefore stays admissible.
    ///
    /// # Errors
    ///
    /// [`AuthorityRotationError::NotCommitted`] for every failure before the
    /// governing commit and for a commit known not to have happened: the
    /// outgoing authority stays installed, and the intent is withdrawn.
    /// [`AuthorityRotationError::Indeterminate`] when the governing commit's
    /// outcome is unknown: this handle stops sealing (`authority_unresolved`)
    /// until the store is reopened and the evidence decides.
    /// [`AuthorityRotationError::Retained`] when the governing epoch's
    /// signing coordinate was consumed and its publication is held in the
    /// control namespace's custody (`StoreError::PublicationRetained`): this
    /// handle stops sealing and the intent stays until resolution
    /// (`ExecutionStore::resolve_publication`) decides it.
    pub fn rotate_authority(
        &self,
        next: kappa_crypto::SigningAuthority,
        succession: VerifiedSuccession,
        witnesses: Vec<WitnessEvidence>,
        control: &NamespaceRef,
        clock: &dyn kappa_store::time::Clock,
    ) -> Result<(), AuthorityRotationError> {
        let not_committed = AuthorityRotationError::NotCommitted;
        // Refused first, before any storage access: an unresolved handle
        // reports its authority state whether or not its database still
        // admits write transactions. The flag is only ever set, so it is
        // checked again under the gate below.
        self.refuse_if_unresolved().map_err(not_committed)?;
        let domain = self.activation_domain(control).map_err(not_committed)?;
        let mut execution = self
            .begin_epoch_execution(control, clock, None)
            .map_err(not_committed)?;
        if !execution
            .controller()
            .logical_incarnation(IncarnationUse::ActivationDomain)
            .is_ok_and(|incarnation| incarnation.names(&domain.incarnation))
        {
            return Err(not_committed(StoreError::Conflict(format!(
                "control namespace {control} was replaced before its activation began"
            ))));
        }
        let predecessor = execution.head_in_transaction().map_err(not_committed)?;
        #[cfg(test)]
        self.hooks
            .reach(crate::test_hooks::Point::RotationWriterHeld);
        let gate = self.activation.write().map_err(|_| {
            not_committed(StoreError::Internal(
                "authority activation lock poisoned".into(),
            ))
        })?;
        self.refuse_if_unresolved().map_err(not_committed)?;
        // A committed activation whose projection did not land is finished
        // here, under this gate, so this activation's intent never overtakes
        // it.
        self.project_installed().map_err(not_committed)?;
        let governed = Activation { domain, witnesses };
        let (candidate, transition, position) = self
            .prepare_rotation(next, succession, governed, execution.now())
            .map_err(not_committed)?;
        let bytes = transition.to_bytes().map_err(not_committed)?;
        let record = VerifiedContent::compute(Axis::Sha256, &bytes)
            .map_err(|error| not_committed(error.into()))?;
        let intent = ActivationIntent {
            position,
            domain,
            record: record.kappa().clone(),
        };
        self.record_activation_intent(&intent)
            .map_err(not_committed)?;
        if let Err(error) = execution.record_activation(position, &record) {
            drop(execution);
            self.withdraw_after_noncommit(&intent);
            return Err(not_committed(error));
        }
        let outgoing = self.authority.load().anchor().clone();
        let hold = ActivationHold::new(gate, candidate, intent.clone(), predecessor, outgoing);
        match execution.publish_governing(hold) {
            ActivationOutcome::Committed { publication, hold } => {
                // Installed before the gate opens: the next epoch sealed
                // anywhere is signed by the incoming authority.
                self.authority.store(Arc::clone(hold.candidate()));
                drop(hold);
                // Projected after the gate opens. A failure is not the
                // activation's, which its evidence already makes durable;
                // the intent stays, and the next projection completes it.
                if let Err(error) = self.project_activation(position, &bytes, Some(&intent)) {
                    tracing::warn!(
                        position,
                        epoch = publication.0,
                        root = %publication.1,
                        %error,
                        "committed activation not yet projected into the authority history"
                    );
                }
                Ok(())
            }
            ActivationOutcome::Indeterminate { error, hold } => {
                self.retained_authority
                    .store(Some(Arc::clone(hold.candidate())));
                // Set while the hold still carries the gate, so no epoch is
                // sealed under either authority until a reopen decides; the
                // intent and the candidate's evidence stay for that reopen.
                self.authority_unresolved
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                drop(hold);
                Err(AuthorityRotationError::Indeterminate(error))
            }
            ActivationOutcome::Retained { error, hold } => {
                self.retained_authority
                    .store(Some(Arc::clone(hold.candidate())));
                // The governing epoch's coordinate is consumed and its
                // publication is in the control namespace's custody: it may
                // still publish and install the candidate, so no epoch is
                // sealed under either authority, and the intent stays, until
                // resolution publishes it or finds it terminal.
                self.authority_unresolved
                    .store(true, std::sync::atomic::Ordering::SeqCst);
                drop(hold);
                Err(AuthorityRotationError::Retained(error))
            }
            ActivationOutcome::NotCommitted { error, hold } => {
                drop(hold);
                self.withdraw_after_noncommit(&intent);
                Err(not_committed(error))
            }
        }
    }

    /// Withdraw the intent of an activation whose governing epoch is known
    /// not to have committed. A withdrawal that fails leaves the intent,
    /// which refuses the next activation until [`Self::project_activations`]
    /// or the next open finds no evidence for it and withdraws it: the
    /// outcome is already decided, so nothing is lost by deferring it.
    fn withdraw_after_noncommit(&self, intent: &ActivationIntent) {
        if let Err(error) = self.withdraw_activation_intent(intent) {
            tracing::warn!(
                position = intent.position,
                %error,
                "the intent of an activation that did not commit is withdrawn later"
            );
        }
    }

    /// Complete the authority history's projection of the governing
    /// evidence under the exclusive activation gate, so no activation
    /// interleaves ([`Self::project_installed`]). Refused while this
    /// handle's last activation outcome is unknown: only a reopen reads
    /// that outcome.
    pub fn project_activations(&self) -> Result<(), StoreError> {
        let gate = self
            .activation
            .write()
            .map_err(|_| StoreError::Internal("authority activation lock poisoned".into()))?;
        self.refuse_if_unresolved()?;
        self.project_installed()?;
        drop(gate);
        Ok(())
    }

    /// Give every installed transition its history row and resolve a
    /// pending intent: one already installed is withdrawn with its row
    /// projected, one whose control namespace holds no record never
    /// committed and is withdrawn, and one whose record is committed but not
    /// installed on this handle is refused for a reopen to decide. Called
    /// only under the exclusive activation gate.
    fn project_installed(&self) -> Result<(), StoreError> {
        let installed = self.authority.load_full();
        let (rows, intent) = self.authority_rows()?;
        let projected = rows.len().saturating_sub(1);
        for (index, transition) in installed.transitions().iter().enumerate().skip(projected) {
            let position = index as u64 + 1;
            self.project_activation(position, &transition.to_bytes()?, None)?;
        }
        if let Some(intent) = intent {
            let installed_count = installed.transitions().len() as u64;
            if intent.position <= installed_count {
                self.withdraw_activation_intent(&intent)?;
            } else if self
                .activation_evidence(intent.position, &intent.domain, installed.origin().anchor())?
                .is_none()
            {
                if self.activation_has_custody(&intent)? {
                    self.authority_unresolved
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    return Err(StoreError::AuthorityUnresolved {
                        outgoing: Box::new(installed.anchor().clone()),
                    });
                }
                self.withdraw_activation_intent(&intent)?;
            } else {
                return Err(StoreError::Internal(format!(
                    "activation {} committed without being installed; reopen the store",
                    intent.position
                )));
            }
        }
        Ok(())
    }

    /// Whether `namespace` holds the governing evidence of an installed or
    /// pending activation: its storage is what the store's authority is
    /// recovered from, so it is never retired.
    pub(crate) fn holds_activation_evidence(
        &self,
        namespace: &[u8; 16],
    ) -> Result<bool, StoreError> {
        if self
            .authority
            .load()
            .transitions()
            .iter()
            .any(|transition| transition.activation().domain.control == *namespace)
        {
            return Ok(true);
        }
        let (_, intent) = self.authority_rows()?;
        Ok(intent.is_some_and(|intent| intent.domain.control == *namespace))
    }

    /// The origin anchor of this store's authority lineage, which every
    /// rotation witness binds.
    pub fn authority_origin(&self) -> Kappa {
        self.authority.load().origin().anchor().clone()
    }

    /// The domain an activation in `control` binds: the control namespace
    /// and its logical incarnation (`NamespaceController::logical_incarnation`).
    /// Witnesses sign it. Storage that records no incarnation cannot host an
    /// activation and is refused as `Rejected`.
    pub fn activation_domain(
        &self,
        control: &NamespaceRef,
    ) -> Result<ActivationDomain, StoreError> {
        let active = self.namespaces.admit_read(control.id())?;
        let incarnation = active
            .controller()
            .logical_incarnation(IncarnationUse::ActivationDomain)?;
        Ok(ActivationDomain {
            control: *control.id(),
            incarnation: *incarnation.as_bytes(),
        })
    }

    /// `AuthorityUnresolved` naming the installed (outgoing) authority when
    /// an activation's commit outcome on this handle is unknown.
    fn refuse_if_unresolved(&self) -> Result<(), StoreError> {
        if self
            .authority_unresolved
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(StoreError::AuthorityUnresolved {
                outgoing: Box::new(self.authority.load().anchor().clone()),
            });
        }
        Ok(())
    }

    /// Admit the rotation against the installed authority at `now`, the
    /// governing epoch's time. Returns the candidate authority, the admitted
    /// transition and its history position. Called under the exclusive
    /// activation gate.
    fn prepare_rotation(
        &self,
        next: kappa_crypto::SigningAuthority,
        succession: VerifiedSuccession,
        activation: Activation,
        now: kappa_store::clock::ClockMs,
    ) -> Result<(EpochAuthority, AuthorityTransition, u64), StoreError> {
        let effective = succession.inner().effective_at_ms;
        self.require_clear_publication_custody()?;
        // The bound covers every committed epoch once recovery has visited
        // every instance a restart found unsettled: settled epochs are in
        // the durable bound restored at open, and each visit joins its
        // instance's head (`settlement_driver::bounding_head`). Before
        // that, an epoch of an unvisited instance could fall inside the
        // outgoing authority's window this rotation would close.
        if let Some(refusal) = self
            .discovery_coverage()
            .unavailable("the published-time bound of an authority rotation")
        {
            return Err(refusal);
        }
        if self
            .latest_epoch_ms
            .load(std::sync::atomic::Ordering::SeqCst)
            >= effective
        {
            return Err(StoreError::Rejected(
                "authority transition must take effect after every published epoch".into(),
            ));
        }
        // Under the exclusive activation gate: no epoch, and with it no
        // revocation of a witness, commits between this check and the
        // governing commit.
        witness_standing(self, &activation, effective)?;
        #[cfg(test)]
        self.hooks
            .reach(crate::test_hooks::Point::RotationStandingChecked);
        let (candidate, transition) = self
            .authority
            .load()
            .rotate(next, succession, activation, now)?;
        let position = u64::try_from(candidate.transitions().len())
            .map_err(|_| StoreError::CapacityExceeded("authority history".into()))?;
        Ok((candidate, transition, position))
    }

    /// Number of persisted authority history rows: the origin plus one per
    /// projected transition.
    #[cfg(test)]
    pub(crate) fn persisted_authority_rows(&self) -> Result<u64, StoreError> {
        Ok(self.authority_rows()?.0.len() as u64)
    }

    /// Whether an activation intent is pending.
    #[cfg(test)]
    pub(crate) fn activation_intent_pending(&self) -> Result<bool, StoreError> {
        Ok(self.authority_rows()?.1.is_some())
    }
}

#[cfg(test)]
#[path = "authority_tests.rs"]
mod tests;
