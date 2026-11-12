//! The seal of one namespace epoch inside the namespace's write
//! transaction, on the shared publication machinery.
//!
//! The seal runs in two parts around the reservation of the publication's
//! unsettled ownership (`epoch_execution_publish`):
//!
//! 1. [`PersistentStore::prepare_seal`]: the transitions the boundary
//!    buffered (`transition_apply`), their index effects reduced with the
//!    final authority record into the current-state index
//!    (`namespace_commitment::seal_index`) over the namespace's own nodes
//!    (`state_nodes`), the predecessor's committed state read from the
//!    head's root, the history resumed from its peaks and checked against
//!    it, the candidate prepared by the shared policy
//!    (`EpochPublication::prepare`), and everything known before the
//!    signature installed: the ledger, rotation path, state and authority
//!    records, the index and history nodes. Every refusal here consumes no
//!    coordinate.
//! 2. [`PersistentStore::complete_seal`]: the custody record stored durably
//!    (`custody`), which consumes the coordinate; signing recorded into it
//!    as it progresses (`EpochCandidate::sign_recorded`), with the work
//!    spent by then; then the records the signed root generates, the
//!    commitment coordinates of external content, the receipt coordinates
//!    of operations, and the head. From the custody record on, a failure is
//!    the retained publication's, reported as `PublicationRetained`, and
//!    the record stays for resolution.
//!
//! Everything the seal writes is derived from the buffered transitions and
//! the candidate alone, so resolution (`custody_resolve`), which rebuilds
//! the transitions from custody, seals exactly what the execution sealed.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::clock::ClockMs;
use kappa_store::epoch::{EpochMutation, MutationOp};
use kappa_store::epoch_publication::{
    EpochCandidate, EpochPublication, EpochPublicationInput, SigningEvent, SigningReservation,
};
use kappa_store::epoch_root::EpochRoot;
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::namespace_commitment::{StateInput, seal_index};
use kappa_store::traits::namespace::NamespaceInfo;
use kappa_store::transition::{PreparedTransition, RecordTransition, TransitionDomain};
use kappa_store::work::{Dimension, Meter, Work, WorkMeter};
use kappa_store::{EpochAuthority, LogicalIncarnation, OperationReceipt, VerifiedContent};
use kappa_types::NamespaceState;
use kappa_types::content::ContentAdmissionEvidence;
use kappa_types::state_index;

use crate::PersistentStore;
use crate::allocation::Pin;
use crate::authority::ActivationHold;
use crate::commitments::{COMMITMENTS_CONTEXT, commitment_entry};
use crate::content_read::ReadView;
use crate::control_plane::ASSIGNMENT_KEY;
use crate::custody::{
    CustodyActivation, CustodyParts, CustodyRead, CustodyRecord, CustodySigning, CustodyTransition,
};
use crate::encrypted::bound;
use crate::epoch_blob::install_record_in_txn;
use crate::state_nodes::{HISTORY_NODES, Nodes, STATE_NODES};
use crate::storage::{IncarnationUse, NamespaceController, WriterToken};
use crate::storage_instance::StorageInstance;
use crate::tables::{BLOB_INDEX, COMMITMENTS, MUTATION_BUFFER};

/// The first part of a seal: a prepared candidate whose pre-signature
/// evidence the transaction holds. The pins of that evidence are returned
/// beside it, so their ownership passes to the publication explicitly.
pub(crate) struct SealPreparation {
    pub(crate) candidate: EpochCandidate,
    pub(crate) predecessor: Option<Kappa>,
    /// Whether the ledger admits a control-plane assignment.
    pub(crate) assigns: bool,
    /// The view the seal reads its own evidence through: under an
    /// activation, the candidate authority's.
    view: ReadView,
    mutations: Vec<EpochMutation>,
    transitions: Vec<CustodyTransition>,
    incarnation: LogicalIncarnation,
    now: ClockMs,
}

/// A candidate whose coordinate is consumed, with what installing its
/// signed root needs: the seal's read view and the ledger it commits.
struct Signed {
    candidate: EpochCandidate,
    view: ReadView,
    mutations: Vec<EpochMutation>,
}

/// The completed seal: the signed root, the pins of the records it
/// generated, and the custody record, signed, that the commit discharges.
pub(crate) struct SealCompletion {
    pub(crate) root: EpochRoot,
    pub(crate) pins: Vec<Pin>,
    pub(crate) custody: CustodyRecord,
}

impl PersistentStore {
    /// The authority a seal signs under: an activation's candidate, or the
    /// installed one. Refused while an activation's outcome is unresolved on
    /// this handle: `authority_unresolved` is set only under the exclusive
    /// gate, so either reading observes every unresolved activation that
    /// completed before this seal. The caller's guard keeps the authority in
    /// force from here through the commit's classification.
    pub(crate) fn sealing_authority(
        &self,
        activation: Option<&ActivationHold<'_>>,
    ) -> Result<Arc<EpochAuthority>, StoreError> {
        if self.authority_unresolved.load(Ordering::SeqCst) {
            return Err(StoreError::AuthorityUnresolved {
                outgoing: Box::new(self.authority.load().anchor().clone()),
            });
        }
        Ok(activation.map_or_else(
            || self.authority.load_full(),
            |hold| Arc::clone(hold.candidate()),
        ))
    }

    /// The committed state `root` names, read through `view` and verified
    /// against the identity the root signs.
    fn committed_state_of(
        txn: &redb::WriteTransaction,
        view: &ReadView,
        root: &EpochRoot,
        work: &mut dyn Meter,
    ) -> Result<kappa_store::canonical::Record<NamespaceState>, StoreError> {
        let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
        view.namespace_state_from_index(&index, root.state(), work)
    }

    /// The first part of the seal (see the module documentation), every
    /// unit charged to `meter`. Returns the preparation and the pins of the
    /// evidence it installed.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_seal(
        &self,
        txn: &redb::WriteTransaction,
        controller: &NamespaceController,
        ns: &NamespaceRef,
        now: ClockMs,
        signer_override: Option<&Kappa>,
        activation: Option<&ActivationHold<'_>>,
        authority: &EpochAuthority,
        meter: &mut WorkMeter,
    ) -> Result<(SealPreparation, Vec<Pin>), StoreError> {
        let uuid = ns.id();
        if controller.id != *uuid {
            return Err(StoreError::Conflict(
                "execution namespace differs from its controller".into(),
            ));
        }
        let incarnation = controller.logical_incarnation(IncarnationUse::Seal)?;
        let view = self.sealing_view(controller, activation);
        let (digest, tag_count) = self.tag_state_in_txn(txn, ns)?;
        // The predecessor is selected while the namespace writer is held:
        // no other epoch of this namespace can be sealed meanwhile.
        let predecessor_kappa = self.head_pointer(txn, uuid)?;
        if let Some(hold) = activation {
            hold.admits(controller, predecessor_kappa.as_ref())?;
        }
        let predecessor = predecessor_kappa
            .as_ref()
            .map(|key| {
                let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
                view.epoch_root_from_index(&index, key, meter)
            })
            .transpose()?;
        let predecessor_state = predecessor
            .as_ref()
            .map(|root| Self::committed_state_of(txn, &view, root, meter))
            .transpose()?;

        let buffered = self.buffered_transitions(txn, uuid, meter)?;
        let mut mutations = Vec::with_capacity(buffered.len());
        let mut assigns = false;
        let mut changes = Vec::with_capacity(buffered.len() + 1);
        let mut transitions = Vec::with_capacity(buffered.len());
        for row in buffered {
            // A blob metadata key named `_assign` is not a namespace
            // assignment. Interpret the exact evidence at the same boundary
            // used by application, replay and settlement.
            if row.mutation.op == MutationOp::MetadataUpdate {
                let evidence = VerifiedContent::verify(&row.mutation.kappa, &row.evidence)?;
                let transition = PreparedTransition::decode(
                    TransitionDomain::new(*uuid, incarnation),
                    &row.mutation,
                    evidence,
                )?;
                if let RecordTransition::Metadata(record) = transition.record() {
                    assigns |= matches!(record.subject(), kappa_store::MetadataSubject::Namespace)
                        && record.key() == ASSIGNMENT_KEY;
                }
            }
            let mutation = canonical_bytes(&row.mutation);
            meter.charge(Dimension::BytesAllocated, mutation.len() as u64)?;
            transitions.push(CustodyTransition {
                mutation,
                evidence: row.evidence,
                payload: row.payload,
            });
            changes.push(row.change);
            mutations.push(row.mutation);
        }
        let record = kappa_store::absent(Self::namespace_info_in_txn(txn, ns))?;
        let authority_state =
            NamespaceInfo::authority_state(record.as_ref(), *uuid, *incarnation.as_bytes())?;
        let base = predecessor_state
            .as_ref()
            .map_or(state_index::EMPTY, |state| *state.value().index_root());
        let update = {
            let nodes = Nodes {
                store: self,
                table: txn.open_table(STATE_NODES).map_err(crate::error::redb)?,
            };
            seal_index(&nodes, base, changes, &authority_state, meter)?
        };
        let number = predecessor.as_ref().map_or(Ok(1), |root| {
            root.epoch_number()
                .checked_add(1)
                .ok_or_else(|| StoreError::CapacityExceeded("epoch number exhausted".into()))
        })?;
        self.write_index_update(txn, number, &update, meter)?;
        self.reclaim_index_nodes(txn, ns, meter)?;
        let history = self.resume_history(
            &txn.open_table(HISTORY_NODES).map_err(crate::error::redb)?,
            predecessor_state.as_ref().map(|state| state.value()),
            meter,
        )?;
        let candidate = {
            let nodes = Nodes {
                store: self,
                table: txn.open_table(STATE_NODES).map_err(crate::error::redb)?,
            };
            EpochPublication::prepare(
                EpochPublicationInput {
                    namespace: ns,
                    predecessor: predecessor.as_ref(),
                    state_root: digest.into_bytes(),
                    tag_count,
                    mutations: &mutations,
                    now,
                    signer_override,
                    state: StateInput {
                        authority: &authority_state,
                        index_root: update.root,
                        index: &nodes,
                        predecessor: predecessor_state.as_ref().map(|state| state.value()),
                        history: &history,
                    },
                },
                authority,
                meter,
            )?
        };
        if candidate.epoch_number() != number {
            return Err(StoreError::Internal(format!(
                "the candidate of {ns} is epoch {}, not its successor {number}",
                candidate.epoch_number()
            )));
        }

        // Everything known before the signature is installed before it.
        let committed = candidate.committed();
        let mut pins = Vec::new();
        for content in [
            Some(candidate.ledger()),
            candidate.rotation_record(),
            Some(committed.state_record()),
            Some(committed.authority_record()),
        ]
        .into_iter()
        .flatten()
        {
            let (_, pin) = install_record_in_txn(self, txn, ns, content)?;
            pins.extend(pin);
        }
        self.write_history_nodes(txn, committed.history_nodes(), meter)?;
        Ok((
            SealPreparation {
                candidate,
                predecessor: predecessor_kappa,
                assigns,
                view,
                mutations,
                transitions,
                incarnation,
                now,
            },
            pins,
        ))
    }

    /// The second part of the seal (see the module documentation), under
    /// `writer`, the instance's writer gate. `reads` are the authorization
    /// rows the execution read, `activation` what the epoch governs.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn complete_seal(
        &self,
        writer: &WriterToken,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        preparation: SealPreparation,
        authority: &EpochAuthority,
        activation: Option<CustodyActivation>,
        reads: Vec<CustodyRead>,
        meter: &mut WorkMeter,
    ) -> Result<SealCompletion, StoreError> {
        let SealPreparation {
            candidate,
            predecessor,
            view,
            mutations,
            transitions,
            incarnation,
            now,
            ..
        } = preparation;
        let instance = *writer.instance();
        let number = candidate.epoch_number();
        let mut custody = CustodyRecord::new(CustodyParts {
            namespace: *ns.id(),
            incarnation: *incarnation.as_bytes(),
            epoch_number: number,
            predecessor,
            unsigned: candidate.unsigned_identity().clone(),
            now_ms: now.as_i64(),
            activation,
            transitions,
            reads,
            work: *meter.used(),
        });
        // The durable record is what consumes the coordinate. Its store can
        // fail after the record became visible (a failed directory sync
        // after the rename), so a failure is classified by what is held
        // now: a record that is held, or whose presence cannot be decided,
        // retains the publication; only one that is absent consumed none.
        if let Err(error) = self.store_custody(writer, &instance, &custody) {
            return match self.holds_custody(&instance) {
                Ok(false) => Err(error),
                Ok(true) | Err(_) => Err(self.retain(writer, &instance, &mut custody, &error)),
            };
        }
        self.latest_epoch_ms
            .fetch_max(candidate.timestamp_ms(), Ordering::SeqCst);
        self.sign_in_custody(
            writer,
            txn,
            ns,
            Signed {
                candidate,
                view,
                mutations,
            },
            authority,
            custody,
            Work::default(),
            meter,
        )
    }

    /// The second part of a seal resumed from `custody`, the record of the
    /// publication `preparation` rebuilt from it under `writer`: the
    /// rebuilt candidate must be the custodied one, signing continues from
    /// where the record says it stood (`EpochCandidate::restore`), never
    /// invoking the signer again for the coordinate, and the work this
    /// attempt does is added to what the record holds. Every failure
    /// retains the publication in the same record.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resume_seal(
        &self,
        writer: &WriterToken,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        preparation: SealPreparation,
        authority: &EpochAuthority,
        mut custody: CustodyRecord,
        meter: &mut WorkMeter,
    ) -> Result<SealCompletion, StoreError> {
        let SealPreparation {
            mut candidate,
            view,
            mutations,
            transitions,
            predecessor,
            incarnation,
            now,
            ..
        } = preparation;
        let instance = *writer.instance();
        let earlier = custody.work()?;
        custody.set_work(&earlier.saturating_add(meter.used()));
        if custody.retained()?.disposition == kappa_store::RecoveryDisposition::Terminal {
            let refused = StoreError::Rejected(custody.retained()?.cause);
            return Err(self.retain(writer, &instance, &mut custody, &refused));
        }
        if candidate.unsigned_identity() != &custody.unsigned
            || candidate.epoch_number() != custody.epoch_number
            || predecessor != custody.predecessor
            || !incarnation.names(&custody.incarnation()?)
            || now.as_i64() != custody.now_ms
            || transitions != custody.transitions
        {
            let refused = StoreError::Conflict(format!(
                "the publication rebuilt from the custody of {instance} is not the custodied candidate {}",
                custody.unsigned
            ));
            custody.make_terminal(&refused);
            return Err(self.retain(writer, &instance, &mut custody, &refused));
        }
        if let Err(error) = candidate.restore(custody.signing.clone().recorded()) {
            return Err(self.retain(writer, &instance, &mut custody, &error));
        }
        self.sign_in_custody(
            writer,
            txn,
            ns,
            Signed {
                candidate,
                view,
                mutations,
            },
            authority,
            custody,
            earlier,
            meter,
        )
    }

    /// Sign `signed.candidate` at its consumed coordinate, recording each
    /// signing step and the work spent so far (`earlier`, then this
    /// attempt's) durably in `custody` as it happens, then install what the
    /// signed root generates. A failure retains the publication.
    #[allow(clippy::too_many_arguments)]
    fn sign_in_custody(
        &self,
        writer: &WriterToken,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        signed: Signed,
        authority: &EpochAuthority,
        mut custody: CustodyRecord,
        earlier: Work,
        meter: &mut WorkMeter,
    ) -> Result<SealCompletion, StoreError> {
        let Signed {
            mut candidate,
            view,
            mutations,
        } = signed;
        let instance = *writer.instance();
        let reservation = SigningReservation::recorded(*ns.id(), candidate.epoch_number());
        let recorded =
            candidate.sign_recorded(authority, &reservation, meter, &mut |event, work| {
                custody.signing = match event {
                    SigningEvent::Invoking => CustodySigning::Invoked,
                    SigningEvent::Returned(signature) => CustodySigning::Returned {
                        signature: signature.to_vec(),
                    },
                };
                custody.set_work(&earlier.saturating_add(work));
                self.store_custody(writer, &instance, &custody)
            });
        // Preserve the shared state machine's conclusive refusal before the
        // candidate is consumed. Returned bytes alone do not imply that a
        // malformed signature can resume successfully on another attempt.
        if candidate.disposition() == kappa_store::RecoveryDisposition::Terminal {
            if let Err(cause) = &recorded {
                custody.make_terminal(cause);
            }
        }
        let completed = recorded.and_then(|()| {
            self.install_signed(
                txn,
                ns,
                &view,
                candidate,
                reservation,
                &mutations,
                &custody.transitions,
                TransitionDomain::new(
                    *ns.id(),
                    LogicalIncarnation::from_bytes(custody.incarnation()?),
                ),
                meter,
            )
        });
        custody.set_work(&earlier.saturating_add(meter.used()));
        match completed {
            Ok((root, pins)) => Ok(SealCompletion {
                root,
                pins,
                custody,
            }),
            Err(cause) => Err(self.retain(writer, &instance, &mut custody, &cause)),
        }
    }

    /// Record `cause` in `instance`'s custody under `writer` and report the
    /// publication as retained. A record that cannot be rewritten keeps its
    /// earlier cause; the retained publication is reported either way.
    pub(crate) fn retain(
        &self,
        writer: &WriterToken,
        instance: &StorageInstance,
        custody: &mut CustodyRecord,
        cause: &StoreError,
    ) -> StoreError {
        custody.cause = cause.to_string();
        self.live_custody
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(*instance, custody.clone());
        if let Err(error) = self.store_custody(writer, instance, custody) {
            tracing::warn!(
                instance = %instance,
                %error,
                "the cause of a retained publication was not recorded"
            );
        }
        match custody.retained() {
            Ok(retained) => StoreError::PublicationRetained(Box::new(retained)),
            Err(error) => error,
        }
    }

    /// Install what the signed root generates, the commitment coordinates
    /// of the external content its ledger admits and the receipt
    /// coordinates of its operations, and the head, and drain the buffer.
    /// Returns the root and the pins of the generated records.
    #[allow(clippy::too_many_arguments)]
    fn install_signed(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        view: &ReadView,
        candidate: EpochCandidate,
        reservation: SigningReservation,
        mutations: &[EpochMutation],
        transitions: &[CustodyTransition],
        domain: TransitionDomain,
        meter: &mut WorkMeter,
    ) -> Result<(EpochRoot, Vec<Pin>), StoreError> {
        let publication = candidate.into_publication(reservation).map_err(|_| {
            StoreError::Internal(
                "a completely signed candidate did not yield its publication".into(),
            )
        })?;
        let (_, pin) = install_record_in_txn(self, txn, ns, publication.root_blob())?;
        let pins: Vec<Pin> = pin.into_iter().collect();
        self.edge_put_in_txn(txn, ns, publication.edge(), publication.edge_blob())?;
        for (link, content) in publication.retained_links() {
            self.edge_put_in_txn(txn, ns, link, content)?;
        }
        let root = publication.into_root();
        self.write_commitments(txn, view, mutations, root.kappa(), domain, meter)?;
        for (mutation, transition) in mutations.iter().zip(transitions) {
            if mutation.op == MutationOp::OperationPublish {
                let receipt: OperationReceipt = from_canonical(&transition.evidence)?;
                self.store_operation_coordinates(
                    txn,
                    ns,
                    receipt.operation_id()?,
                    root.kappa(),
                    &mutation.kappa,
                )?;
            }
        }
        let predecessor = root.prev_identifier().cloned();
        self.advance_head(txn, ns, predecessor.as_ref(), &root)?;
        Self::drain_mutation_buffer(txn, ns.id())?;
        self.record_time_in_txn(txn, root.timestamp())?;
        Ok((root, pins))
    }

    /// Record the commitment coordinates of every external admission
    /// `mutations` publish: the epoch `epoch_identity` that authenticates
    /// it and the admission record naming its chunk commitment, both
    /// resolvable from the signed history (`ReadView::resolve_commitment`).
    /// The records are read through `view`, the seal's own.
    fn write_commitments(
        &self,
        txn: &redb::WriteTransaction,
        view: &ReadView,
        mutations: &[EpochMutation],
        epoch_identity: &Kappa,
        domain: TransitionDomain,
        meter: &mut WorkMeter,
    ) -> Result<(), StoreError> {
        let mut entries = Vec::new();
        {
            let index = txn.open_table(BLOB_INDEX).map_err(crate::error::redb)?;
            for mutation in mutations
                .iter()
                .filter(|mutation| mutation.op == MutationOp::ContentPublish)
            {
                let evidence = view.verified_epoch_content(&index, &mutation.kappa, None, meter)?;
                let transition = PreparedTransition::decode(domain, mutation, evidence)?;
                if let RecordTransition::ContentPublish(record) = transition.record()
                    && let ContentAdmissionEvidence::Chunked(commitment) = record.evidence()
                {
                    entries.push((commitment.identity().key_bytes(), mutation.kappa.clone()));
                }
            }
        }
        let mut table = txn.open_table(COMMITMENTS).map_err(crate::error::redb)?;
        for (identity_key, admission) in entries {
            let value = self.encrypt_bytes(
                &bound(COMMITMENTS_CONTEXT, &identity_key),
                &commitment_entry(epoch_identity, &admission)?,
            )?;
            table
                .insert(identity_key.as_slice(), value.as_slice())
                .map_err(crate::error::redb)?;
        }
        Ok(())
    }

    /// Remove every buffered mutation of namespace `uuid`: the seal has
    /// drained them into the ledger.
    fn drain_mutation_buffer(
        txn: &redb::WriteTransaction,
        uuid: &[u8; 16],
    ) -> Result<(), StoreError> {
        let mut buffer = txn
            .open_table(MUTATION_BUFFER)
            .map_err(crate::error::redb)?;
        let prefix = uuid.as_slice();
        match Self::prefix_successor(prefix) {
            Some(end) => buffer
                .retain_in(prefix..end.as_slice(), |_, _| false)
                .map_err(crate::error::redb),
            None => buffer
                .retain_in(prefix.., |_, _| false)
                .map_err(crate::error::redb),
        }
    }
}
