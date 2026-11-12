//! Resume a retained publication under its instance writer and authority.
//! Rebuild exact named evidence through the consuming transition boundary,
//! then use the initial publication's resource admission and commit machinery.

use std::sync::{Arc, atomic::Ordering};

use kappa_store::canonical::from_canonical;
use kappa_store::epoch::EpochMutation;
use kappa_store::time::Clock;
use kappa_store::transition::{PreparedTransition, PreparedWrite};
use kappa_store::work::{Dimension, WorkMeter};
use kappa_store::{
    ClockMs, NamespaceRef, PublicationResolution, Published, RecoveryDisposition, StoreError,
    VerifiedContent,
};
use redb::{ReadableTable, ReadableTableMetadata};

use crate::PersistentStore;
use crate::authority::ActivationHold;
use crate::custody::CustodyRecord;
use crate::epoch::{AuthorityGuard, SharedAuthority, epoch_idx_key};
use crate::epoch_execution::{ExecutionOwnership, PreparedEpochPublication};
use crate::namespace_write::DirectoryGuard;
use crate::storage::{Opening, WriterGate};
use crate::tables::{BLOB_INDEX, EPOCH_INDEX, MUTATION_BUFFER};
use crate::transition_apply::TxnWriter;

enum Guard<'a> {
    Ordinary(SharedAuthority<'a>),
    Activation(ActivationHold<'a>),
}

impl<'a> AuthorityGuard<'a> for Guard<'a> {
    fn activation(&self) -> Option<&ActivationHold<'a>> {
        match self {
            Self::Ordinary(guard) => guard.activation(),
            Self::Activation(hold) => Some(hold),
        }
    }
}

impl PersistentStore {
    pub(crate) fn resolve_retained_publication(
        &self,
        namespace: &NamespaceRef,
        clock: &dyn Clock,
        meter: &mut WorkMeter,
    ) -> Result<PublicationResolution, StoreError> {
        // Custody stores this attempt's work, not unrelated work already
        // spent by a supervisor on the caller's meter. Retain the deadline
        // and every remaining dimension, then return consumption on all exits.
        let mut limit = *meter.limit();
        for dimension in Dimension::ALL {
            limit = limit.with(dimension, meter.remaining(dimension));
        }
        let mut attempt = WorkMeter::new(limit);
        let result = self.resolve_custody_attempt(namespace, clock, &mut attempt);
        for dimension in Dimension::ALL {
            meter.consume(dimension, attempt.used().get(dimension))?;
        }
        result
    }

    fn resolve_custody_attempt(
        &self,
        namespace: &NamespaceRef,
        clock: &dyn Clock,
        meter: &mut WorkMeter,
    ) -> Result<PublicationResolution, StoreError> {
        meter.charge(Dimension::Handles, 1)?;
        let active = match self
            .namespaces
            .admit_publish(namespace.id(), &Opening::Existing)
        {
            Ok(active) => active,
            Err(StoreError::NotFound(_)) if !self.directory_knows(namespace)? => {
                return Ok(PublicationResolution::Clear);
            }
            Err(error) => return Err(error),
        };
        let writer = WriterGate::acquire(&active)?;
        let controller = Arc::clone(active.controller());
        let instance = controller.instance;
        let Some(mut custody) = self.load_custody(&instance, meter)? else {
            return Ok(PublicationResolution::Clear);
        };
        let earlier = custody.work()?;
        // Even a prepared reservation constrains future authority activation.
        self.latest_epoch_ms
            .fetch_max(custody.now_ms, Ordering::SeqCst);
        let rebuilt = (|| {
            let guard =
                if custody.activation.is_some() && self.retained_authority.load_full().is_some() {
                    Guard::Activation(self.retained_activation(&custody)?)
                } else {
                    Guard::Ordinary(self.shared_authority()?)
                };
            let authority = guard.activation().map_or_else(
                || self.authority.load_full(),
                |hold| Arc::clone(hold.candidate()),
            );
            if controller.fenced() && !controller.fence_resolvable() {
                return Err(StoreError::Unavailable(
                    "publication outcome requires database recovery".into(),
                ));
            }
            let transaction = controller.db.begin_write().map_err(crate::error::redb)?;
            let key = epoch_idx_key(namespace, custody.epoch_number);
            let committed = transaction
                .open_table(EPOCH_INDEX)
                .map_err(crate::error::redb)?
                .get(key.as_slice())
                .map_err(crate::error::redb)?
                .map(|value| kappa_store::Kappa::from_key_bytes(value.value()))
                .transpose()?;
            if let Some(identity) = committed {
                let index = transaction
                    .open_table(BLOB_INDEX)
                    .map_err(crate::error::redb)?;
                let view = self.sealing_view(&controller, guard.activation());
                let root = view.epoch_root_from_index(&index, &identity, meter)?;
                custody.check_committed(&instance, &root, meter, &self.encoding_storage)?;
                // The signed state, not just the custody filename and root's
                // namespace, authenticates the namespace incarnation.
                let decoded = view.namespace_state_from_index(&index, root.state(), meter)?;
                let state = decoded.value();
                if state.namespace() != namespace.id()
                    || state.incarnation() != &custody.incarnation()?
                {
                    return Err(StoreError::Conflict(
                        "committed publication state names another incarnation".into(),
                    ));
                }
                custody.set_work(&earlier.saturating_add(meter.used()));
                // Committed rows still owe settlement. Move reconstructed
                // custody capacity into that obligation before discharge
                // removes the durable custody marker and its map entry.
                let mut parked = controller
                    .unresolved_content
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(debt) = self
                    .custody_debt
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .remove(&instance)
                {
                    parked.append(crate::unsettled::Parked::new(Vec::new(), debt));
                }
                drop(parked);
                if let Err(error) =
                    self.discharge_custody(&writer, &instance, &custody, &root, meter)
                {
                    custody.set_work(&earlier.saturating_add(meter.used()));
                    self.retain(&writer, &instance, &mut custody, &error);
                    tracing::warn!(%error, "committed publication custody cleanup remains pending");
                }
                drop(index);
                drop(transaction);
                return Ok((guard, authority, None, Some(root)));
            }
            if custody.retained()?.disposition == RecoveryDisposition::Terminal {
                return Err(StoreError::Rejected(custody.retained()?.cause));
            }
            if self.head_pointer(&transaction, namespace.id())? != custody.predecessor {
                return Err(StoreError::Conflict(
                    "retained publication predecessor changed".into(),
                ));
            }
            if guard.activation().is_none() && self.authority_unresolved() {
                return Err(StoreError::AuthorityUnresolved {
                    outgoing: Box::new(authority.anchor().clone()),
                });
            }
            self.custody_standing(&custody, &authority, clock, meter)?;
            if !transaction
                .open_table(MUTATION_BUFFER)
                .map_err(crate::error::redb)?
                .is_empty()
                .map_err(crate::error::redb)?
            {
                return Err(StoreError::Conflict(
                    "namespace has mutations outside custody".into(),
                ));
            }
            controller.mutation_seq.store(0, Ordering::Relaxed);
            let now = ClockMs::from_raw(custody.now_ms);
            // Each transition is charged, then applied through a boundary
            // that borrows this attempt's allowance for its row effects.
            for transition in &custody.transitions {
                let bytes = (transition.mutation.len() as u64)
                    .saturating_add(transition.evidence.len() as u64);
                let private = transition.payload.reconstruction_bound();
                meter.charge_all(&[
                    (Dimension::Entries, 1),
                    (Dimension::BytesDecoded, bytes.saturating_add(private)),
                    (
                        Dimension::BytesHashed,
                        bytes.saturating_mul(3).saturating_add(private),
                    ),
                    (
                        Dimension::BytesAllocated,
                        bytes.saturating_mul(8).saturating_add(private),
                    ),
                ])?;
                let mutation: EpochMutation = from_canonical(&transition.mutation)?;
                let evidence = VerifiedContent::verify(&mutation.kappa, &transition.evidence)?;
                let boundary = TxnWriter::new(self, &transaction, namespace, now, meter)?;
                let prepared = PreparedTransition::decode(boundary.domain(), &mutation, evidence)?;
                let payload = transition.payload.clone().restore(self)?;
                boundary.apply_prepared(PreparedWrite::bind(prepared, payload, self)?)?;
            }
            let (preparation, mut pins) = self.prepare_seal(
                &transaction,
                &controller,
                namespace,
                now,
                None,
                guard.activation(),
                &authority,
                meter,
            )?;
            pins.append(
                &mut controller
                    .writer_pins
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            self.custody_standing(&custody, &authority, clock, meter)?;
            Ok((
                guard,
                authority,
                Some((transaction, preparation, pins)),
                None,
            ))
        })();
        let (guard, authority, prepared, committed) = match rebuilt {
            Ok(rebuilt) => rebuilt,
            Err(error) => {
                custody.set_work(&earlier.saturating_add(meter.used()));
                if matches!(error, StoreError::Conflict(_)) {
                    custody.make_terminal(&error);
                }
                return retained(self.retain(&writer, &instance, &mut custody, &error));
            }
        };
        if let Some(root) = committed {
            if let Guard::Activation(hold) = guard {
                self.finish_retained_activation(hold);
            }
            self.raise_committed_floor(root.timestamp());
            let parked = std::mem::take(
                &mut *controller
                    .unresolved_content
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
            controller.park_until_settled(root.epoch_number(), parked);
            if controller.fence_resolvable() {
                if let Err(error) = controller.unfence() {
                    tracing::warn!(%error, "committed publication fence cleanup remains pending");
                }
            }
            // The publication is committed either way; directory changes
            // left unresolved (an error, or a registry needing recovery)
            // stay journaled under the pending marker, and settlement
            // resolves them at the head.
            match self.reconcile_directory(&controller, meter) {
                Ok(crate::registry::Standing::Ready(
                    crate::namespace_write::Reconciled::Complete,
                )) => {}
                Ok(crate::registry::Standing::Ready(
                    crate::namespace_write::Reconciled::Partial,
                )) => tracing::warn!(
                    "recovered publication directory remains pending: the resolution's meter stopped it"
                ),
                Ok(crate::registry::Standing::RecoveryRequired) => tracing::warn!(
                    "recovered publication directory remains pending: the registry requires recovery"
                ),
                Err(error) => {
                    tracing::warn!(%error, "recovered publication directory remains pending");
                }
            }
            return Ok(PublicationResolution::Published(Published {
                epoch_number: root.epoch_number(),
                root: root.kappa().clone(),
            }));
        }
        let (transaction, preparation, pins) = prepared.ok_or_else(|| {
            StoreError::Internal("custody reconstruction yielded no publication".into())
        })?;
        let mut directory = DirectoryGuard::new(self, controller);
        directory.touch();
        let (outcome, guard) = PreparedEpochPublication::resume(
            self,
            ExecutionOwnership {
                guard,
                directory,
                writer,
                active,
                release: None,
            },
            namespace.clone(),
            transaction,
            preparation,
            authority,
            custody,
            pins,
            meter,
            clock,
        );
        match outcome {
            Ok((epoch_number, root)) => {
                if let Guard::Activation(hold) = guard {
                    self.finish_retained_activation(hold);
                }
                Ok(PublicationResolution::Published(Published {
                    epoch_number,
                    root,
                }))
            }
            Err(error) => retained(error),
        }
    }

    pub(crate) fn custody_standing(
        &self,
        custody: &CustodyRecord,
        authority: &kappa_store::EpochAuthority,
        clock: &dyn Clock,
        meter: &mut WorkMeter,
    ) -> Result<(), StoreError> {
        let now = clock.now()?;
        meter.charge(Dimension::Entries, custody.reads.len() as u64 + 1)?;
        for read in &custody.reads {
            meter.charge_all(&[
                (
                    Dimension::BytesAllocated,
                    read.held_bytes().saturating_mul(3),
                ),
                (Dimension::BytesRead, read.held_bytes()),
                (Dimension::BytesDecoded, read.held_bytes()),
            ])?;
            let read = read.clone().restore()?;
            self.authorization_reads_hold_at(std::slice::from_ref(&read), now)?;
        }
        if let Some(activation) = &custody.activation {
            let transition = authority.transitions().last().ok_or_else(|| {
                StoreError::Conflict("governing authority has no activation transition".into())
            })?;
            if transition.outgoing().anchor() != &activation.outgoing
                || authority.transitions().len() as u64 != activation.position
                || transition.activation().domain.control != custody.namespace()?
                || transition.activation().domain.incarnation != custody.incarnation()?
            {
                return Err(StoreError::Conflict(
                    "governing authority differs from publication activation".into(),
                ));
            }
            kappa_store::witness_standing(self, transition.activation(), now.as_i64())?;
        }
        Ok(())
    }
}

fn retained(error: StoreError) -> Result<PublicationResolution, StoreError> {
    match error {
        StoreError::PublicationRetained(record) => Ok(PublicationResolution::Retained(record)),
        error => Err(error),
    }
}
