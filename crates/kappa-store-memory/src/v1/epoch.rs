//! Epochs of a namespace view: sealing into the candidate and authority
//! rotation. Epoch reads are `epoch_read`.

use std::mem;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLockWriteGuard};

use kappa_store::epoch_publication::{
    EpochCandidate, EpochPublication, EpochPublicationInput, GeneratedRecord, SigningReservation,
};
use kappa_store::namespace_commitment::{StateInput, seal_index};
use kappa_store::time::Clock;
use kappa_store::traits::namespace::NamespaceInfo;
use kappa_store::{
    Activation, AuthorityRotationError, EpochAuthority, VerifiedSuccession, WitnessEvidence,
    witness_standing,
};
use kappa_types::capacity::Reservation;
use kappa_types::edge::Edge;
use kappa_types::epoch::EpochMutation;
use kappa_types::epoch_root::EpochRoot;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::tag::TagUpdate;
use kappa_types::work::{Dimension, WorkMeter};
use kappa_types::{ActivationDomain, Axis, VerifiedContent};

use super::InMemoryStore;
use super::execution::WriteCx;
use super::projection::Changes;
use super::view::{Admission, NamespaceView};

impl InMemoryStore {
    /// The domain an activation published in `control` binds: the control
    /// namespace and its incarnation. Witnesses sign it.
    pub fn activation_domain(
        &self,
        control: &NamespaceRef,
    ) -> Result<ActivationDomain, StoreError> {
        Ok(ActivationDomain {
            control: *control.id(),
            incarnation: self.slot(control.id())?.view.load().incarnation_bytes(),
        })
    }

    /// Hand epoch signing from the current authority to `next` through the
    /// admitted dual-signed `succession`, activated by `witnesses` and
    /// published in the control namespace `control`.
    ///
    /// The control namespace's writer is taken first, then the exclusive
    /// activation gate, the order every publication takes its writer and
    /// then the gate shared, so the rotation is ordered against every
    /// publication: each epoch is signed by the authority in force when it
    /// sealed, and none by an authority this call retired. Under the gate
    /// the witnesses' standing is checked and the transition record is
    /// published in `control` as the incoming authority's first epoch,
    /// carrying the succession path and signed by the private candidate.
    /// The candidate is installed only after that publication, before the
    /// gate is released; if the publication fails nothing is installed and
    /// no other seal ever observed the candidate.
    ///
    /// The succession must be effective by the authority clock's time and
    /// strictly after the newest epoch any namespace sealed, so every
    /// published epoch stays admissible. Namespaces do not need to publish
    /// first: an idle namespace's next epoch carries the whole succession
    /// path from its head's signer.
    ///
    /// # Errors
    ///
    /// [`AuthorityRotationError::NotCommitted`] for a failure before the
    /// control namespace's signing coordinate was consumed: nothing is
    /// installed. [`AuthorityRotationError::Retained`] once it was and the
    /// governing publication is retained unpublished
    /// (`StoreError::PublicationRetained`): it and its incoming authority
    /// are in the control namespace's custody, every seal is refused until
    /// resolution publishes it and installs the authority or finds it
    /// terminal, and the outgoing authority stays installed meanwhile.
    pub fn rotate_authority(
        &self,
        next: kappa_crypto::SigningAuthority,
        succession: VerifiedSuccession,
        witnesses: Vec<WitnessEvidence>,
        control: &NamespaceRef,
        clock: &dyn Clock,
    ) -> Result<(), AuthorityRotationError> {
        self.rotate_under_gate(next, succession, witnesses, control, clock)
            .map_err(|error| match error {
                StoreError::PublicationRetained(_) => AuthorityRotationError::Retained(error),
                StoreError::PublicationIndeterminate { .. } => {
                    AuthorityRotationError::Indeterminate(error)
                }
                other => AuthorityRotationError::NotCommitted(other),
            })
    }

    fn rotate_under_gate(
        &self,
        next: kappa_crypto::SigningAuthority,
        succession: VerifiedSuccession,
        witnesses: Vec<WitnessEvidence>,
        control: &NamespaceRef,
        clock: &dyn Clock,
    ) -> Result<(), StoreError> {
        let mut execution = self.open_execution(control, clock)?;
        if execution
            .candidate()
            .record
            .as_ref()
            .is_none_or(|record| record.tombstoned)
        {
            return Err(StoreError::NotFound(format!("control namespace {control}")));
        }
        let gate = self
            .activation
            .write()
            .map_err(|_| StoreError::Internal("authority activation lock poisoned".into()))?;
        let effective = succession.inner().effective_at_ms;
        if self
            .latest_epoch()
            .is_some_and(|latest| latest >= effective)
        {
            return Err(StoreError::Rejected(
                "authority transition must take effect after every published epoch".into(),
            ));
        }
        let activation = Activation {
            domain: self.activation_domain(control)?,
            witnesses,
        };
        witness_standing(self, &activation, effective)?;
        let outgoing = self.authority.load_full();
        let (rotated, transition) =
            outgoing.rotate(next, succession, activation, execution.issued_at())?;
        let rotated = Arc::new(rotated);
        let position = rotated.transitions().len();
        let record = VerifiedContent::compute(Axis::Sha256, &transition.to_bytes()?)?;
        execution.write(|cx| {
            cx.publish_record(&record)?;
            cx.tag_put(
                &format!("{AUTHORITY_TAG_PREFIX}{position:020}"),
                &TagUpdate::CreateIfAbsent {
                    kappa: record.kappa().clone(),
                },
            )
            .map(drop)
        })?;
        // The candidate signs its own governing epoch under the exclusive
        // gate; it is installed only once that epoch is published, before
        // the gate is released. A publication that fails before its
        // coordinate is consumed installs nothing; one that fails after it
        // is retained with the candidate in the control namespace's custody.
        // Publishing the governing epoch installs `rotated` (`Pending`'s
        // settlement) while this exclusive gate is held.
        execution.publish_under_activation(&ActivationAuthority {
            candidate: rotated,
            outgoing: outgoing.anchor().clone(),
            _gate: &gate,
        })?;
        drop(gate);
        Ok(())
    }
}

/// Prefix of the control namespace's tags naming each admitted transition.
pub const AUTHORITY_TAG_PREFIX: &str = "_authority/";

/// The candidate authority of an activation, the outgoing authority it
/// succeeds, and the exclusive activation gate it seals under. Only
/// `rotate_under_gate` constructs one, so no other publication can seal
/// under an authority that is not installed.
pub struct ActivationAuthority<'a, 'g> {
    candidate: Arc<EpochAuthority>,
    outgoing: Kappa,
    _gate: &'a RwLockWriteGuard<'g, ()>,
}

impl ActivationAuthority<'_, '_> {
    /// The candidate authority, shared so a retained publication can own it.
    pub const fn candidate(&self) -> &Arc<EpochAuthority> {
        &self.candidate
    }

    /// The anchor of the authority the candidate succeeds: what must still
    /// be installed when a retained activation is resolved.
    pub const fn outgoing(&self) -> &Kappa {
        &self.outgoing
    }
}

/// Consume the signing coordinate `number` of `ns` in its slot's `signed`
/// counter. Only the successor of the last consumed coordinate can be
/// reserved, so a coordinate consumed by a seal that never published fences
/// every later seal of the slot.
pub fn reserve_coordinate(
    signed: &AtomicU64,
    ns: &NamespaceRef,
    number: u64,
) -> Result<SigningReservation, StoreError> {
    let previous = number
        .checked_sub(1)
        .ok_or_else(|| StoreError::Internal("epoch number zero".into()))?;
    signed
        .compare_exchange(previous, number, Ordering::AcqRel, Ordering::Acquire)
        .map_err(|consumed| {
            StoreError::Conflict(format!(
                "epoch {number} of {ns} cannot be signed: coordinates are consumed through {consumed}; the namespace is fenced"
            ))
        })?;
    Ok(SigningReservation::recorded(*ns.id(), number))
}

impl WriteCx<'_> {
    /// Prepare the candidate's next epoch under `authority`, whose
    /// protection the caller holds from before this until the candidate is
    /// stored: apply the final index effects, build the epoch candidate, and
    /// retain everything known before the signature (ledger, rotation path,
    /// state and authority records, history). Every check the epoch's
    /// completion depends on runs here, so a refusal consumes no
    /// coordinate. Every buffer is charged to the execution's meter before
    /// it is built.
    pub fn prepare_seal(
        &mut self,
        authority: &EpochAuthority,
        signer_override: Option<&Kappa>,
    ) -> Result<EpochCandidate, StoreError> {
        let predecessor = self
            .view
            .epoch
            .clone()
            .map(|kappa| self.store.epoch_in(self.view, &kappa, &mut *self.meter))
            .transpose()?;

        self.meter.charge(
            Dimension::BytesAllocated,
            (self.view.ledger.len() * size_of::<EpochMutation>()) as u64,
        )?;
        let mutations: Vec<EpochMutation> = self.view.ledger.iter().cloned().collect();
        let authority_state = NamespaceInfo::authority_state(
            self.view.record.as_ref(),
            *self.ns.id(),
            self.incarnation_bytes(),
        )?;
        let changes = mem::take(&mut self.view.pending_state_changes);
        let update = seal_index(
            &*self.view,
            self.view.state_index_root,
            changes,
            &authority_state,
            self.meter,
        )?;
        for node in &update.created {
            self.view.state_nodes.insert(node.hash(), *node);
        }
        self.view.state_index_root = update.root;

        let state_input = StateInput {
            authority: &authority_state,
            index_root: self.view.state_index_root,
            index: &*self.view,
            predecessor: self.view.committed_state.as_ref(),
            history: &self.view.history,
        };
        let candidate = EpochPublication::prepare(
            EpochPublicationInput {
                namespace: self.ns,
                predecessor: predecessor.as_ref(),
                state_root: *self.view.digest.value(),
                tag_count: self.view.tags.len() as u64,
                mutations: &mutations,
                now: self.now,
                signer_override,
                state: state_input,
            },
            authority,
            self.meter,
        )?;

        // What completion changes must hold, checked now.
        let number = candidate.epoch_number();
        if self.view.epochs.contains_key(&number) {
            return Err(StoreError::Internal(format!(
                "epoch {number} of {} sealed twice",
                self.ns
            )));
        }
        if let Some(previous) = &self.view.epoch
            && !self.view.references.contains_key(previous)
        {
            return Err(StoreError::Internal(format!(
                "reference index lacked the epoch head {previous}"
            )));
        }

        // Everything known before the signature is retained before it.
        self.install_evidence(candidate.ledger())?;
        if let Some(path) = candidate.rotation_record() {
            self.install_evidence(path)?;
        }
        let committed = candidate.committed();
        self.install_evidence(committed.state_record())?;
        self.install_evidence(committed.authority_record())?;
        self.view.history = committed.history().clone();
        self.view.committed_state = Some(committed.state().clone());
        for &(position, hash) in committed.history_nodes() {
            self.view.history_nodes.insert(position, hash);
        }
        admit_installation(&candidate, self.meter)?;
        candidate.admit(self.meter)?;
        Ok(candidate)
    }

    /// Install one record generated from the signed root into the
    /// candidate: its bytes, moved in with `charge`, and the edge it
    /// encodes, recording its identity in `changes` within the room
    /// `Changes::reserve_generated` made. The caller charged the work and
    /// split `charge` from the publication's retention before the record
    /// left its owner.
    pub(super) fn install_generated(
        &mut self,
        record: GeneratedRecord,
        charge: Reservation,
        base: &NamespaceView,
        changes: &mut Changes,
    ) {
        let GeneratedRecord { edge, content } = record;
        let identity = content.kappa().clone();
        if let Some(input) = edge {
            self.view.edges.insert(Edge {
                kappa: identity.clone(),
                input,
            });
        }
        self.retain_generated(content, charge);
        changes.gain_generated(base, &identity);
    }

    /// Make the signed `root` the candidate's epoch head: its epoch index
    /// entry, the head reference that replaces its predecessor's, the latest
    /// epoch time and the cleared ledger, with the root recorded in
    /// `changes`. `prepare_seal` checked the index was free and the
    /// predecessor's head reference held.
    pub(super) fn install_head(&mut self, root: &EpochRoot, changes: &mut Changes) {
        let number = root.epoch_number();
        changes.gain_epoch(root.kappa());
        self.view.epochs.insert(number, root.kappa().clone());
        let sealed_ms = root.timestamp_ms();
        self.view.latest_epoch_ms = Some(
            self.view
                .latest_epoch_ms
                .map_or(sealed_ms, |latest| latest.max(sealed_ms)),
        );
        if let Some(previous) = self.view.epoch.replace(root.kappa().clone()) {
            // Checked held by `prepare_seal`; the release cannot miss.
            let released = self.view.release(&previous);
            debug_assert!(released, "prepare_seal checked the head reference");
        }
        self.view.reference(root.kappa());
        self.view.ledger.clear();
    }
}

/// Bytes each installed record holds beyond its encoding: its evidence
/// row, its edge record and the digest of its one segment.
pub const RECORD_OVERHEAD: u64 =
    (size_of::<Admission>() + size_of::<Edge>() + size_of::<[u8; 32]>()) as u64;

/// Rows one generated record writes: its evidence row, its edge record and
/// the edge's four index postings.
pub const GENERATED_RECORD_ROWS: u64 = 6;

/// Rows the epoch head writes: its index entry and its head reference.
pub const HEAD_ROWS: u64 = 2;

/// Rows the receipt lookup writes.
pub const RECEIPT_ROWS: u64 = 1;

/// The retention a publication reserves before its coordinate is consumed:
/// every generated record's bytes at their bound and its overhead.
pub const fn retention_bound(candidate: &EpochCandidate) -> u64 {
    (candidate.generated_records() as u64)
        .saturating_mul(RECORD_OVERHEAD)
        .saturating_add(candidate.generated_bytes_bound())
}

/// Admit, before the signature, the installation of what the signed root
/// of `candidate` generates: each record's segment digests over its bytes,
/// its overhead, and the rows it and the head write. Each installation unit
/// charges its own work when it runs.
fn admit_installation(candidate: &EpochCandidate, meter: &WorkMeter) -> Result<(), StoreError> {
    let records = candidate.generated_records() as u64;
    meter.admits(&[
        (Dimension::BytesHashed, candidate.generated_bytes_bound()),
        (
            Dimension::BytesAllocated,
            records.saturating_mul(RECORD_OVERHEAD),
        ),
        (
            Dimension::Entries,
            records
                .saturating_mul(GENERATED_RECORD_ROWS)
                .saturating_add(HEAD_ROWS)
                .saturating_add(RECEIPT_ROWS),
        ),
    ])?;
    Ok(())
}
