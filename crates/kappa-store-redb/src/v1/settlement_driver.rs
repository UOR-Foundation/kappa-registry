//! Settlement of one storage instance towards its head, and the
//! obligations recovery holds for instances whose pre-restart ownership it
//! has not settled: their records, their bounded reconstruction, and the
//! discovery coverage they leave. The step that drives both is
//! `settlement_recovery`.

use std::sync::{Arc, PoisonError};

use kappa_store::work::Meter;
use kappa_store::StoreError;

use super::cursors::{EffectProgress, Element, EpochConsumer, EpochRead, Purpose};
use super::pending::checkpoint_in_write;
use super::stage::Staged;
use super::work::exhausted;
use super::{EpochStep, Origin, SettlementAttempt, SettlementStop};
use crate::instance_record::Kind;
use crate::namespace_write::Reconciled;
use crate::projection_compact::{FoldStop, PressureFold};
use crate::registry::{Attempt, Standing};
use crate::storage::NamespaceController;
use crate::storage_instance::StorageInstance;
use crate::store_access::Coverage;
use crate::unsettled_index::DiscoveryKey;
use crate::PersistentStore;

/// What reconstruction gathers from one read of an epoch: what it made
/// discoverable (the identities it admitted and the predicates its
/// revocations and watermarks answer), to register, and its External rows'
/// entries and bytes, to measure.
#[derive(Default)]
struct Measure {
    restarted: bool,
    entries: u64,
    bytes: u64,
    identities: Vec<DiscoveryKey>,
}

fn measure_overflow() -> StoreError {
    StoreError::Internal("measured unsettled ownership exceeds u64".into())
}

impl EpochConsumer for Measure {
    fn restart(&mut self, _: &mut dyn Meter) -> Result<(), StoreError> {
        *self = Self {
            restarted: true,
            ..Self::default()
        };
        Ok(())
    }

    /// Measure the element whole or not at all: the unit of its
    /// finalization is admitted before anything is measured, the element's
    /// measures are gathered apart and joined to this read's only once it is
    /// finished inside that unit. An identity admitted twice in one epoch is
    /// measured twice: debt is held conservatively rather than by a set of
    /// the epoch's identities.
    fn apply(
        &mut self,
        mut element: Element<'_>,
        work: &mut dyn Meter,
    ) -> Result<EffectProgress, StoreError> {
        let Ok(mut unit) = work.admit(&element.finalization().as_bound()) else {
            return Ok(EffectProgress::Deferred(SettlementStop::Budget));
        };
        let (mut entries, mut bytes) = (self.entries, self.bytes);
        let mut identities = Vec::new();
        for staged in element.effects() {
            match staged {
                Staged::Admitted {
                    identity,
                    allocation,
                    stored,
                } => {
                    if allocation.is_some() {
                        entries = entries.checked_add(1).ok_or_else(measure_overflow)?;
                        bytes = bytes.checked_add(*stored).ok_or_else(measure_overflow)?;
                    }
                    identities.push(DiscoveryKey::Content(identity.clone()));
                }
                Staged::Identity(effect) => {
                    identities.extend(effect.discovery_keys()?.into_iter().flatten());
                }
                Staged::Retired(_) | Staged::Assignment(_) | Staged::Directory(_) => {}
            }
        }
        element.finish(&mut unit)?;
        self.entries = entries;
        self.bytes = bytes;
        self.identities.append(&mut identities);
        Ok(EffectProgress::Applied)
    }
}

/// What one settlement of an instance did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settled {
    /// Epochs examined, settled or found already settled: the work the
    /// budget is charged.
    pub examined: u64,
    /// Epochs whose effects this settlement applied.
    pub applied: u64,
    /// The checkpoint reached the head.
    pub reached: bool,
    /// The instance is a creation proven never to have committed: its
    /// claim was released and its pending entry removed under its writer
    /// gate; its storage is for the caller to retire once it holds no grant
    /// on it (`retire_empty_creation`).
    pub empty_creation: bool,
    /// The resource whose unavailability stopped this settlement short of
    /// the head; nothing about the instance's storage is implied.
    pub deferred: Option<SettlementStop>,
}

/// What a bounded attempt to relieve a namespace's epoch pressure found.
pub(crate) enum AdmissionProgress {
    /// The namespace's established unsettled backlog is below its ceiling.
    Available,
    /// The backlog is still at its ceiling: the resource named was
    /// unavailable, or the allowance is spent.
    Deferred(SettlementStop),
}

impl AdmissionProgress {
    /// The attempt stopped on a registry commit of unknown outcome: only a
    /// reopen decides what persisted, so admission refuses as unavailable
    /// rather than as backpressure a retry can outlast.
    pub(crate) const fn requires_reopen(&self) -> bool {
        matches!(
            self,
            Self::Deferred(SettlementStop::RegistryRecoveryRequired)
        )
    }
}

impl std::fmt::Display for AdmissionProgress {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Available => formatter.write_str("settlement made room"),
            Self::Deferred(stop) => write!(formatter, "settlement deferred: {stop}"),
        }
    }
}

impl PersistentStore {
    /// Settle `controller`'s instance from its established checkpoint
    /// towards its head within `work`, under the instance's settlement
    /// attempt, each epoch read across as many steps as it needs and
    /// completed in one registry transaction with its checkpoint
    /// (`settle_epoch_in`), releasing the parked pins of each epoch as it
    /// completes. An attempt held elsewhere, and every resource the epoch
    /// operation finds unavailable, stops short of the head with the reason
    /// in `deferred`. When the head is reached and maintenance of the
    /// namespace can hold its writer gate, its journaled directory changes
    /// are resolved against its committed record
    /// (`namespace_directory_journal`) and the pending entry is removed; an
    /// execution holding the gate will have marked the instance again
    /// before its commit, so the entry stays, as it does while a retirement
    /// intent holds the namespace (its release removes the storage, and
    /// recovery the entry, under the instance's recorded release).
    ///
    /// A controller fenced by a commit whose outcome this process did not
    /// learn settles nothing: its head may include state redb never made
    /// durable, and projecting it would let the registry run ahead of the
    /// disk. That outcome is resolved by a fresh open, whose recovery reads
    /// what persisted (`NamespaceController::fence_resolvable`).
    ///
    /// A creation proven never to have committed (readable storage holding
    /// no epoch, read under the writer gate while the caller's activity
    /// grant keeps the controller from being evicted or replaced) releases
    /// its directory claim and pending entry with the gate still held:
    /// no execution, and no other instance of the namespace, can claim or
    /// mark between the proof and the release. The claim released is this
    /// instance's: no other instance of the namespace can exist while its
    /// storage does.
    pub(crate) fn settle_namespace(
        &self,
        controller: &Arc<NamespaceController>,
        work: &mut dyn Meter,
    ) -> Result<Settled, StoreError> {
        let mut settled = Settled {
            examined: 0,
            applied: 0,
            reached: false,
            empty_creation: false,
            deferred: None,
        };
        if controller.fenced() && !controller.fence_resolvable() {
            return Ok(settled);
        }
        // Held until this function returns: selection, every epoch, and the
        // discharge the checkpoint authorizes run under it.
        let Some(attempt) = SettlementAttempt::try_acquire(controller) else {
            settled.deferred = Some(SettlementStop::AttemptBusy);
            return Ok(settled);
        };
        let head = self.bounding_head(controller, work)?;
        // A registry commit of unknown outcome is the registry's condition,
        // not this instance's: settlement defers, and nothing about the
        // instance is recorded.
        let checkpoint = match self.established_checkpoint_standing(&controller.instance)? {
            Standing::Ready(checkpoint) => checkpoint.map_or(0, |(number, _)| number),
            Standing::RecoveryRequired => {
                settled.deferred = Some(SettlementStop::RegistryRecoveryRequired);
                return Ok(settled);
            }
        };
        controller.raise_known_settled(checkpoint);
        let mut next = checkpoint;
        while next < head && !exhausted(work) {
            let epoch = next.checked_add(1).ok_or_else(|| {
                StoreError::Internal(format!(
                    "epoch numbers of {} exhausted",
                    controller.instance
                ))
            })?;
            // Compaction, which makes staging headroom, is the recovery
            // step's own part; this traversal stops for it.
            if !self.staging_headroom()? {
                settled.deferred = Some(SettlementStop::StagingCapacity);
                break;
            }
            let txn = match self.registry.write_standing()? {
                Standing::Ready(txn) => txn,
                Standing::RecoveryRequired => {
                    settled.deferred = Some(SettlementStop::RegistryRecoveryRequired);
                    break;
                }
            };
            match self.settle_epoch_in(&attempt, epoch, txn, work)? {
                EpochStep::Completed => {
                    settled.examined += 1;
                    settled.applied += 1;
                    next = epoch;
                }
                // The meter refused the next unit; later steps resume it.
                EpochStep::Partial(SettlementStop::Budget) => break,
                // Another resource stopped the epoch part way; it resumes
                // once that resource is available.
                EpochStep::Partial(stop) => {
                    settled.deferred = Some(stop);
                    break;
                }
                EpochStep::Deferred(stop) => {
                    settled.deferred = Some(stop);
                    break;
                }
            }
        }
        settled.reached = next >= head;
        if !settled.reached {
            return Ok(settled);
        }
        let Some(maintenance) = self.namespaces.try_maintain(&controller.id)? else {
            return Ok(settled);
        };
        // Under the gate no commit can move the head; confirm it is still
        // the one settled to before forgetting the entry. The authenticated
        // head read under the gate decides: its absence is the proof of an
        // empty creation, never an epoch number.
        let current = self
            .head_root(controller, work)?
            .map(|root| root.epoch_number());
        // Reaching the committed head does not discharge an unpublished
        // candidate's allocations, directory claims or pending marker.
        if self.holds_custody(&controller.instance)? {
            maintenance.finish();
            return Ok(settled);
        }
        if current.is_none() {
            // The creation intent owns the storage again before the claim
            // and marker go, so storage whose retirement is then refused
            // (a creation reopened it, the retirement failed) is never
            // owned by nothing.
            let root = self.namespaces.root();
            Kind::Creating.record(root, &controller.instance)?;
            // A registry needing recovery leaves the claim and the marker:
            // the creation intent owns the storage again, and a reopen
            // decides what the claim's release left. A release the meter
            // stops keeps the journal entries it did not resolve, the
            // existence row and the marker, for the next visit.
            match self.release_directory_claim(&controller.id, work)? {
                Standing::Ready(Reconciled::Complete) => {}
                Standing::Ready(Reconciled::Partial) => {
                    maintenance.finish();
                    settled.deferred = Some(SettlementStop::Budget);
                    return Ok(settled);
                }
                Standing::RecoveryRequired => {
                    maintenance.finish();
                    settled.deferred = Some(SettlementStop::RegistryRecoveryRequired);
                    return Ok(settled);
                }
            }
            Kind::Pending.complete(root, &controller.instance)?;
            self.discharge(&controller.instance, "a creation proven never committed");
            maintenance.finish();
            settled.empty_creation = true;
            return Ok(settled);
        }
        // Directory changes an execution journaled and a crash, or an
        // unknown commit outcome, left unresolved follow the committed
        // record; under the gate no execution reserves meanwhile. A
        // registry needing recovery keeps the journal and the marker that
        // makes it discoverable: the committed epochs are settled, and the
        // marker is removed only once the directory follows them.
        match self.reconcile_directory(controller, work)? {
            Standing::Ready(Reconciled::Complete) => {}
            Standing::Ready(Reconciled::Partial) => {
                maintenance.finish();
                settled.deferred = Some(SettlementStop::Budget);
                return Ok(settled);
            }
            Standing::RecoveryRequired => {
                maintenance.finish();
                settled.deferred = Some(SettlementStop::RegistryRecoveryRequired);
                return Ok(settled);
            }
        }
        if current == Some(head) {
            // A fence reaching here was found on disk when this controller
            // opened the database: redb's recovery at that open read what
            // persisted, so the head settled to is the outcome of the
            // commit the fence recorded. The fence is lifted first; only
            // once that is durable is the protection held for the unknown
            // outcome released, so a failed unfence keeps it.
            if controller.fenced() {
                controller.unfence()?;
                let unresolved = std::mem::take(
                    &mut *controller
                        .unresolved_content
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner),
                );
                drop(unresolved);
                tracing::warn!(
                    instance = %controller.instance,
                    head,
                    "publication fence lifted: the outcome recovered at open is settled"
                );
            }
            Kind::Pending.complete(self.namespaces.root(), &controller.instance)?;
            self.discharge(&controller.instance, "settlement reached the head");
        }
        maintenance.finish();
        Ok(settled)
    }

    /// Relieve `controller`'s epoch pressure within `work`: the bounded
    /// settlement an admission at its namespace's ceiling runs, under the
    /// writer gate its publication holds, before it is refused. Nothing
    /// here waits on another holder: the settlement attempt, the registry
    /// writer and the compaction cursor are each taken without waiting,
    /// and the first unavailable defers. Each epoch is selected from the
    /// checkpoint read inside the registry transaction that settles it, so
    /// it is the established checkpoint's successor. Stops as soon as the
    /// established backlog is below the ceiling, on any deferral, and on a
    /// partly read epoch (the meter refused its next unit). A registry
    /// whose commit outcome is unknown, before or by this attempt, defers
    /// it (`RegistryRecoveryRequired`): the admission refuses with that
    /// reason, and no namespace obligation is recorded.
    pub(crate) fn relieve_epoch_pressure(
        &self,
        controller: &Arc<NamespaceController>,
        work: &mut dyn Meter,
    ) -> Result<AdmissionProgress, StoreError> {
        let ceiling = self.max_unsettled_epochs as u64;
        let head = controller
            .epoch_number
            .load(std::sync::atomic::Ordering::Acquire);
        let Some(attempt) = SettlementAttempt::try_acquire(controller) else {
            return Ok(AdmissionProgress::Deferred(SettlementStop::AttemptBusy));
        };
        loop {
            if head.saturating_sub(self.admissible_checkpoint(controller)?) < ceiling {
                return Ok(AdmissionProgress::Available);
            }
            if exhausted(work) {
                return Ok(AdmissionProgress::Deferred(SettlementStop::Budget));
            }
            if !self.staging_headroom()? {
                if let Some(stop) = self.fold_for_pressure(work)? {
                    return Ok(AdmissionProgress::Deferred(stop));
                }
                continue;
            }
            let txn = match self.registry.try_begin_write()? {
                Attempt::Ready(txn) => txn,
                Attempt::Busy => {
                    return Ok(AdmissionProgress::Deferred(SettlementStop::RegistryBusy));
                }
                Attempt::RecoveryRequired => {
                    return Ok(AdmissionProgress::Deferred(
                        SettlementStop::RegistryRecoveryRequired,
                    ));
                }
            };
            let checkpoint =
                checkpoint_in_write(&txn, &controller.instance)?.map_or(0, |(number, _)| number);
            controller.raise_known_settled(checkpoint);
            if head.saturating_sub(checkpoint) < ceiling {
                txn.abort()?;
                return Ok(AdmissionProgress::Available);
            }
            let epoch = checkpoint.checked_add(1).ok_or_else(|| {
                StoreError::Internal(format!(
                    "epoch numbers of {} exhausted",
                    controller.instance
                ))
            })?;
            match self.settle_epoch_in(&attempt, epoch, txn, work)? {
                EpochStep::Completed => {}
                EpochStep::Partial(SettlementStop::StagingCapacity)
                | EpochStep::Deferred(SettlementStop::StagingCapacity) => {
                    if let Some(stop) = self.fold_for_pressure(work)? {
                        return Ok(AdmissionProgress::Deferred(stop));
                    }
                }
                EpochStep::Partial(stop) | EpochStep::Deferred(stop) => {
                    return Ok(AdmissionProgress::Deferred(stop));
                }
            }
        }
    }

    /// One folding step for epoch pressure on the same `work`: `None` when
    /// it made progress, so settlement is tried again with the staging
    /// headroom it rechecks; otherwise why pressure stops. Progress is
    /// released staging, or a committed traversal that has more to examine
    /// (the batch filled with the meter still admitting, or the traversal
    /// reached the end of a suffix and starts again from the log's start).
    /// Staging is the obstruction only when one traversal from the log's
    /// start to its end released nothing: every version still logged then
    /// belongs to an attempt in progress.
    fn fold_for_pressure(
        &self,
        work: &mut dyn Meter,
    ) -> Result<Option<SettlementStop>, StoreError> {
        let compacted = match self.compact_for_pressure(work)? {
            PressureFold::Deferred(stop) => return Ok(Some(stop)),
            PressureFold::Committed(compacted) => compacted,
        };
        if compacted.released_bytes > 0 {
            return Ok(None);
        }
        Ok(match compacted.stopped {
            FoldStop::Budget => Some(SettlementStop::Budget),
            FoldStop::BatchLimit => None,
            FoldStop::End if !compacted.from_start => None,
            FoldStop::End => Some(SettlementStop::StagingCapacity),
        })
    }

    /// The head epoch number of `controller`'s namespace, 0 without one,
    /// with the head's time joined to the published-time bound
    /// (`latest_epoch_ms`): a head bounds every epoch of its chain, so every
    /// instance settlement or recovery visits bounds rotation from the
    /// visit on, and recovery's enumeration completing leaves none a
    /// restart found unbounded.
    fn bounding_head(
        &self,
        controller: &NamespaceController,
        work: &mut dyn Meter,
    ) -> Result<u64, StoreError> {
        // Recovery publishes this flag only after the authenticated head
        // and committed time floor have been installed. Later publications
        // raise the time bounds before publishing epoch_number. Reusing
        // that established lower bound is sufficient for this visit: a
        // concurrent publication retains its marker, and discharge checks
        // the actual head under the namespace writer below.
        if controller
            .head_recovered
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Ok(controller
                .epoch_number
                .load(std::sync::atomic::Ordering::Acquire));
        }
        let Some(root) = self.head_root(controller, work)? else {
            return Ok(0);
        };
        self.latest_epoch_ms
            .fetch_max(root.timestamp_ms(), std::sync::atomic::Ordering::SeqCst);
        self.raise_committed_floor(kappa_store::ClockMs::from_raw(root.timestamp_ms()));
        Ok(root.epoch_number())
    }

    /// Discharge the obligation of `instance`, releasing its debt and
    /// registrations with it, because `why`.
    pub(super) fn discharge(&self, instance: &StorageInstance, why: &str) {
        self.forget_cursors(instance);
        let removed = self.obligations().remove(instance);
        if let Some(obligation) = removed {
            tracing::info!(
                instance = %instance,
                registered = obligation.registered,
                reason = %obligation.reason,
                "recovery obligation discharged: {why}"
            );
        }
    }

    pub(super) fn obligations(&self) -> std::sync::MutexGuard<'_, super::RecoveryObligations> {
        // Every update is a single map or counter change made under the
        // lock; a panic elsewhere cannot leave the record half-written.
        self.recovery_obligations
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Record `instance` as an unresolved obligation from `origin`, or
    /// update the reason of the one already recorded: its ownership closes
    /// the unsettled pool until it is measured or discharged, and its
    /// identities are a discovery gap. The closing charge is taken under
    /// the obligations lock (lock order: obligations, then the budget), so
    /// the record and its charge appear together
    /// (`RecoveryObligations::hold_unresolved`). Crate-visible so a schedule
    /// holds an obligation the way recovery does, not by assembling one.
    pub(crate) fn record_unresolved(
        &self,
        instance: &StorageInstance,
        origin: Origin,
        reason: String,
    ) -> Result<(), StoreError> {
        let mut obligations = self.obligations();
        if obligations
            .update(instance, |obligation| obligation.reason.clone_from(&reason))
            .is_some()
        {
            return Ok(());
        }
        tracing::error!(
            instance = %instance,
            %reason,
            "unresolved recovery obligation: unsettled admission closed and discovery incomplete until it resolves"
        );
        obligations.hold_unresolved(&self.unsettled, *instance, origin, reason)
    }

    /// Make `instance`'s obligation answer for its pending marker, in place
    /// under the obligations lock: an obligation from its creation intent
    /// keeps its closing charge and discovery gap and changes only its
    /// origin; with none recorded, an unregistered marker obligation is
    /// recorded. Called before the intent is relinquished, so coverage
    /// never depends on a marker no obligation answers for yet.
    pub(super) fn hand_to_marker(
        &self,
        instance: &StorageInstance,
        reason: String,
    ) -> Result<(), StoreError> {
        let mut obligations = self.obligations();
        if obligations
            .update(instance, |obligation| {
                obligation.origin = Origin::Marker;
                obligation.reason.clone_from(&reason);
            })
            .is_some()
        {
            return Ok(());
        }
        obligations.hold_unresolved(&self.unsettled, *instance, Origin::Marker, reason)
    }

    /// Reconstruct the next slice of `controller`'s instance's obligation
    /// within `work`: read its unsettled epochs, from where the previous
    /// slice stopped up to the head captured when the reconstruction began,
    /// each across as many slices as it needs (`settlement_ledger`).
    ///
    /// Each slice registers the identities it read, in one bounded batch,
    /// so they are discoverable at once; registering an identity an
    /// unverified read named only widens the candidates lookups confirm
    /// against the instance's rows. The External rows' entries and bytes
    /// accumulate in the obligation across slices and become a measured
    /// debt only when the epoch is verified; a read restarted from the
    /// epoch's start resets them. Reaching the head drops the closing
    /// charge and completes the registration in one update. Returns the
    /// resource whose unavailability stopped the slice before the head (a
    /// registry commit of unknown outcome, cursor or activity capacity), or
    /// `None` when it advanced as far as `work` allowed.
    pub(super) fn reconstruct_slice(
        &self,
        controller: &Arc<NamespaceController>,
        work: &mut dyn Meter,
    ) -> Result<Option<SettlementStop>, StoreError> {
        if exhausted(work) {
            return Ok(None);
        }
        let instance = controller.instance;
        let out_of_numbers =
            || StoreError::Internal(format!("epoch numbers of {instance} exhausted"));
        // Measurement starts after the established checkpoint: an epoch a
        // checkpoint of unknown durability covers is measured, not skipped.
        // A registry commit of unknown outcome leaves the obligation as it
        // is: measuring from an unestablished checkpoint could skip epochs.
        let checkpoint = match self.established_checkpoint_standing(&instance)? {
            Standing::Ready(checkpoint) => checkpoint.map_or(0, |(number, _)| number),
            Standing::RecoveryRequired => {
                return Ok(Some(SettlementStop::RegistryRecoveryRequired));
            }
        };
        let first = checkpoint.checked_add(1).ok_or_else(out_of_numbers)?;
        let head = self.bounding_head(controller, work)?;
        let Some((mut epoch, head)) = self.obligations().update(&instance, |obligation| {
            if obligation.head == 0 {
                obligation.head = head;
                obligation.next_epoch = first;
            }
            if obligation.next_epoch < first {
                obligation.next_epoch = first;
                obligation.measured = (0, 0);
            }
            (obligation.next_epoch, obligation.head)
        }) else {
            return Ok(None);
        };
        while epoch <= head && !exhausted(work) {
            let mut measure = Measure::default();
            // The cursor stays checked out until what it measured is held
            // by the obligation: only then is its position kept.
            let read =
                self.read_epoch(&instance, epoch, Purpose::Reconstruct, work, &mut measure)?;
            let (verified, stopped) = match read.outcome() {
                EpochRead::Verified(_) => (true, None),
                // What was measured before the stop is registered below.
                EpochRead::Pending(SettlementStop::Budget) => (false, None),
                EpochRead::Pending(stop) => (false, Some(*stop)),
                // No read was opened and nothing was measured.
                EpochRead::Deferred(stop) => return Ok(Some(*stop)),
            };
            let registration = if measure.identities.is_empty() {
                None
            } else {
                Some(
                    self.unsettled_index
                        .register_beyond_bound(instance, std::mem::take(&mut measure.identities))?,
                )
            };
            let measured = self.obligations().update(&instance, |obligation| {
                obligation.registrations.extend(registration);
                if measure.restarted {
                    obligation.measured = (0, 0);
                }
                let (entries, bytes) = obligation.measured;
                obligation.measured = (
                    entries
                        .checked_add(measure.entries)
                        .ok_or_else(measure_overflow)?,
                    bytes
                        .checked_add(measure.bytes)
                        .ok_or_else(measure_overflow)?,
                );
                Ok::<_, StoreError>(verified.then(|| std::mem::take(&mut obligation.measured)))
            });
            // Discharged meanwhile: settlement reached the head.
            let Some(measured) = measured else {
                return Ok(None);
            };
            let Some((entries, bytes)) = measured? else {
                // What the read measured is held: its position is kept.
                read.committed()?;
                return Ok(stopped);
            };
            // Verified and measured: the read's cursor ends.
            read.committed()?;
            let debt = self.unsettled.debt(entries, bytes)?;
            let next = epoch.checked_add(1).ok_or_else(out_of_numbers)?;
            let closing = self.obligations().update(&instance, |obligation| {
                obligation.debts.push(debt);
                obligation.next_epoch = next;
                if next > obligation.head {
                    obligation.registered = true;
                    obligation.reason = "reconstructed".into();
                    obligation.unmeasured.take()
                } else {
                    None
                }
            });
            // The closing charge drops outside the lock, after the measured
            // debt that replaces it is held.
            drop(closing);
            epoch = next;
        }
        Ok(None)
    }

    /// Whether `instance` holds a recovery obligation: its pre-restart
    /// unsettled ownership is not yet settled, and it admits nothing until
    /// settlement discharges the obligation.
    pub(crate) fn obligation_held(&self, instance: &StorageInstance) -> bool {
        self.obligations().contains(instance)
    }

    /// Whether the obligation of `instance` is registered: its identities
    /// are discoverable and its ownership measured.
    pub(super) fn obligation_registered(&self, instance: &StorageInstance) -> Option<bool> {
        self.obligations()
            .update(instance, |obligation| obligation.registered)
    }

    /// The origin of `instance`'s obligation, if one is held.
    pub(super) fn obligation_origin(&self, instance: &StorageInstance) -> Option<Origin> {
        self.obligations()
            .update(instance, |obligation| obligation.origin)
    }

    /// Whether identity discovery covers every committed identity: one
    /// coherent read, under the obligations lock, of the enumeration flag
    /// and the count of unregistered obligations. No obligation is visited.
    pub(crate) fn discovery_coverage(&self) -> Coverage {
        let obligations = self.obligations();
        let unregistered = obligations.unregistered();
        let enumerating = obligations.enumerating();
        drop(obligations);
        if unregistered == 0 && !enumerating {
            Coverage::Complete
        } else {
            Coverage::Incomplete {
                unregistered,
                enumerating,
            }
        }
    }

    /// End the enumeration of obligations present at open: every one it
    /// found is recorded, so coverage no longer depends on it.
    pub(super) fn finish_enumeration(&self) {
        self.obligations().finish_enumeration();
    }
}
