//! The one path from an execution to its prepared, then committed,
//! publication.
//!
//! The authority guard travels with the execution's ownership into the
//! preparation and out of the commit; every failure on the way hands it
//! back to the caller, so an activation's hold is never released by a path
//! that did not classify its outcome.

use std::time::Instant;

use kappa_store::transition::RecordTransition;
use kappa_store::work::WorkMeter;
use kappa_store::{ClockMs, Kappa, NamespaceRef, StoreError};

use super::{
    ActivationOutcome, Creation, EpochExecution, ExecutionOwnership, PreparedEpochPublication,
};
use crate::PersistentStore;
use crate::authority::ActivationHold;
use crate::custody::CustodyRead;
use crate::epoch::AuthorityGuard;
use crate::transition_apply::RedbPayload;

impl<'a> EpochExecution<'a> {
    /// Publish an execution that carries no operation identity.
    pub fn publish(self) -> Result<(u64, Kappa), StoreError> {
        let guard = self.store.shared_authority()?;
        self.into_publication(None, guard)
            .map_err(|(error, _)| error)?
            .publish()
    }

    /// Publish an operation execution with its durable `result`.
    pub fn publish_result(self, result: Vec<u8>) -> Result<(u64, Kappa), StoreError> {
        let guard = self.store.shared_authority()?;
        self.into_publication(Some(result), guard)
            .map_err(|(error, _)| error)?
            .publish()
    }

    /// The head this execution's epoch will extend, as its own transaction
    /// reads it: the predecessor an activation binds its governing epoch to.
    pub(crate) fn head_in_transaction(&self) -> Result<Option<Kappa>, StoreError> {
        self.store
            .head_pointer(&self.transaction, self.namespace.id())
    }

    /// Publish this execution as the governing epoch of the activation
    /// `hold` binds, sealed and committed under its candidate. The outcome
    /// owns the hold in every variant; an epoch that could not be prepared
    /// consumed no coordinate and is `NotCommitted`.
    pub(crate) fn publish_governing(self, hold: ActivationHold<'a>) -> ActivationOutcome<'a> {
        match self.into_publication(None, hold) {
            Ok(prepared) => prepared.publish_governing(),
            Err((error, hold)) => ActivationOutcome::NotCommitted { error, hold },
        }
    }

    /// Apply the operation receipt of `result` in this execution's
    /// transaction: refused when an operation execution has no result or a
    /// plain one has one. The seal records the receipt's coordinates once
    /// it names the root (`epoch_seal`).
    fn install_receipt(&self, result: Option<Vec<u8>>) -> Result<(), StoreError> {
        match (&self.operation, result) {
            (None, None) => Ok(()),
            (Some(_), None) => Err(StoreError::Conflict(
                "operation execution requires a persisted result".into(),
            )),
            (None, Some(_)) => Err(StoreError::Conflict(
                "execution has no operation identity".into(),
            )),
            (Some((identity, request)), Some(result)) => self.with_writer(|writer| {
                let receipt = kappa_store::OperationReceipt::new(
                    writer.ns,
                    writer.incarnation(),
                    identity,
                    request.clone(),
                    result,
                )?;
                writer.apply(
                    RecordTransition::OperationPublish(receipt),
                    RedbPayload::NoResources,
                )?;
                Ok(())
            }),
        }
    }

    /// The one path from an execution to its prepared publication under
    /// `guard`. Refused when the execution failed, when its receipt cannot
    /// be applied, and when an authorization row it read changed; every
    /// refusal aborts the transaction and returns `guard`. The execution's
    /// ownership (gate, grant, release grant), deadline, what remains of its
    /// allowance, the authorization rows it read and its pins move into the
    /// publication.
    fn into_publication<G: AuthorityGuard<'a>>(
        self,
        result: Option<Vec<u8>>,
        guard: G,
    ) -> Result<PreparedEpochPublication<'a, G>, (StoreError, G)> {
        let checked = self
            .ensure_active()
            .and_then(|()| {
                if let Some(deadline) = self.deadline {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(StoreError::DeadlineExceeded {
                            namespace: *self.namespace.id(),
                            overrun_ms: u64::try_from(now.duration_since(deadline).as_millis())
                                .unwrap_or(u64::MAX),
                        });
                    }
                }
                Ok(())
            })
            .and_then(|()| self.authorization_holds())
            .and_then(|()| self.install_receipt(result));
        if let Err(error) = checked {
            // The execution ends unpublished: its transaction aborts, then
            // its directory changes resolve on its own allowance.
            if let Err(abort) = self.abandon() {
                tracing::warn!(%abort, "refused execution's transaction abort failed");
            }
            return Err((error, guard));
        }
        let reads = self
            .authorization_reads
            .borrow()
            .iter()
            .map(CustodyRead::of)
            .collect();
        let Self {
            store,
            transaction,
            directory,
            writer,
            active,
            release,
            namespace,
            creation,
            now,
            signer_override,
            deadline,
            meter,
            clock,
            ..
        } = self;
        store.prepare_epoch_transaction(
            ExecutionOwnership {
                guard,
                directory,
                writer,
                active,
                release,
            },
            transaction,
            Preparation {
                namespace: &namespace,
                creation,
                now,
                signer_override: signer_override.as_ref(),
                deadline,
                meter: meter.into_inner(),
                reads,
                clock,
            },
        )
    }
}

/// What an execution's preparation is made of besides its ownership and
/// transaction.
pub(crate) struct Preparation<'p> {
    pub(crate) namespace: &'p NamespaceRef,
    pub(crate) creation: Creation,
    pub(crate) now: ClockMs,
    pub(crate) signer_override: Option<&'p Kappa>,
    pub(crate) deadline: Option<Instant>,
    /// What remains of the execution's allowance: the publication's
    /// preparation, signing and commit continue on it.
    pub(crate) meter: WorkMeter,
    pub(crate) reads: Vec<CustodyRead>,
    pub(crate) clock: std::sync::Arc<dyn kappa_store::time::Clock>,
}

impl PersistentStore {
    /// Prepare `transaction` as its namespace's next epoch under the
    /// authority `ownership.guard` keeps in force, taking over `ownership`:
    /// the first part of the seal (`epoch_seal::prepare_seal`), on what
    /// remains of the execution's allowance, whose admission deadline is the
    /// execution's. No signing coordinate is consumed. The guard travels
    /// with the prepared epoch to its commit; a refusal aborts the
    /// transaction before the rest of the ownership ends, and returns the
    /// guard.
    pub(crate) fn prepare_epoch_transaction<'s, G: AuthorityGuard<'s>>(
        &'s self,
        ownership: ExecutionOwnership<'s, G>,
        transaction: redb::WriteTransaction,
        preparation: Preparation<'_>,
    ) -> Result<PreparedEpochPublication<'s, G>, (StoreError, G)> {
        let ExecutionOwnership {
            guard,
            directory,
            writer,
            active,
            release,
        } = ownership;
        let Preparation {
            namespace,
            creation,
            now,
            signer_override,
            deadline,
            mut meter,
            reads,
            clock,
        } = preparation;
        let controller = std::sync::Arc::clone(active.controller());
        let prepared = (|| {
            self.admit_creation_assignment(
                &transaction,
                &controller,
                namespace,
                creation,
                now,
                &mut meter,
            )?;
            let authority = self.sealing_authority(guard.activation())?;
            let (sealed, mut pins) = self.prepare_seal(
                &transaction,
                &controller,
                namespace,
                now,
                signer_override,
                guard.activation(),
                &authority,
                &mut meter,
            )?;
            let mut parked = controller
                .writer_pins
                .lock()
                .map_err(|_| StoreError::Internal("writer pin set poisoned".into()))?;
            pins.append(&mut parked);
            drop(parked);
            Ok::<_, StoreError>((sealed, pins, authority))
        })();
        let (sealed, content_pins, authority) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                // The transaction aborts first, then the directory changes
                // resolve against the record still committed, on what
                // remains of the execution's allowance, under its gate.
                drop(transaction);
                if let Err(resolution) = directory.resolve(&mut meter) {
                    tracing::warn!(
                        namespace = %namespace,
                        error = %resolution,
                        "directory changes of an unprepared publication left to settlement"
                    );
                }
                return Err((error, guard));
            }
        };
        Ok(PreparedEpochPublication {
            store: self,
            transaction,
            preparation: sealed,
            guard,
            authority,
            meter,
            reads,
            directory,
            writer,
            active,
            release,
            namespace: namespace.clone(),
            now,
            deadline,
            content_pins,
            clock,
        })
    }
}
