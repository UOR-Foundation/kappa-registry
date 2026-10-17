//! Settlement of one storage instance towards its head, and the
//! obligations recovery holds for instances whose pre-restart ownership it
//! has not settled: their records, their bounded reconstruction, and the
//! discovery coverage they leave. The step that drives both is
//! `settlement_recovery`.

use std::sync::{Arc, PoisonError};

use kappa_store::StoreError;

use super::Origin;
use super::cursors::{EpochConsumer, Purpose};
use super::stage::Staged;
use super::work::Work;
use crate::storage::NamespaceController;
use crate::storage_instance::StorageInstance;
use crate::store_access::Coverage;
use crate::unsettled_index::DiscoveryKey;
use crate::{PersistentStore, creation_intent};

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
    fn restart(&mut self) -> Result<(), StoreError> {
        *self = Self {
            restarted: true,
            ..Self::default()
        };
        Ok(())
    }

    /// An identity admitted twice in one epoch is measured twice: debt is
    /// held conservatively rather than by a set of the epoch's identities.
    fn stage(&mut self, staged: Staged) -> Result<(), StoreError> {
        match staged {
            Staged::Admitted {
                identity,
                allocation,
                stored,
            } => {
                if allocation.is_some() {
                    self.entries = self.entries.checked_add(1).ok_or_else(measure_overflow)?;
                    self.bytes = self
                        .bytes
                        .checked_add(stored)
                        .ok_or_else(measure_overflow)?;
                }
                self.identities.push(DiscoveryKey::Content(identity));
            }
            Staged::Identity(effect) => {
                if let Some(key) = effect.discovery_key()? {
                    self.identities.push(key);
                }
            }
            Staged::Retired(_) | Staged::Assignment(_) | Staged::Directory(_) => {}
        }
        Ok(())
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
}

impl PersistentStore {
    /// Settle `controller`'s instance from its checkpoint towards its head
    /// within `work`, each epoch read across as many steps as it needs and
    /// completed in one registry transaction with its checkpoint
    /// (`settle_epoch`), releasing the parked pins of each epoch as it
    /// completes. When the head is reached and maintenance of the
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
        work: &mut Work,
    ) -> Result<Settled, StoreError> {
        let mut settled = Settled {
            examined: 0,
            applied: 0,
            reached: false,
            empty_creation: false,
        };
        if controller.fenced() && !controller.fence_resolvable() {
            return Ok(settled);
        }
        let head = self.bounding_head(controller)?;
        let checkpoint = self
            .settled_epoch(&controller.instance)?
            .map_or(0, |(number, _)| number);
        let mut next = checkpoint;
        while next < head && !work.spent() {
            let epoch = next.checked_add(1).ok_or_else(|| {
                StoreError::Internal(format!(
                    "epoch numbers of {} exhausted",
                    controller.instance
                ))
            })?;
            match self.settle_epoch(controller, epoch, work)? {
                // The budget, the cursor capacity or the staging headroom
                // stopped the epoch; later steps resume it.
                None => break,
                Some(applied) => {
                    settled.examined += 1;
                    if applied {
                        settled.applied += 1;
                    }
                    next = epoch;
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
        // the one settled to before forgetting the entry.
        let current = self
            .head_root(controller)?
            .map_or(0, |root| root.epoch_number());
        if current == 0 {
            // The creation intent owns the storage again before the claim
            // and marker go, so storage whose retirement is then refused
            // (a creation reopened it, the retirement failed) is never
            // owned by nothing.
            creation_intent::record(self.namespaces.root(), &controller.instance)?;
            self.release_directory_claim(&controller.id)?;
            self.clear_unsettled(&controller.instance)?;
            self.discharge(&controller.instance, "a creation proven never committed");
            maintenance.finish();
            settled.empty_creation = true;
            return Ok(settled);
        }
        // Directory changes an execution journaled and a crash, or an
        // unknown commit outcome, left unresolved follow the committed
        // record; under the gate no execution reserves meanwhile.
        self.reconcile_directory(controller)?;
        if current == head {
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
            self.clear_unsettled(&controller.instance)?;
            self.discharge(&controller.instance, "settlement reached the head");
        }
        maintenance.finish();
        Ok(settled)
    }

    /// The head epoch number of `controller`'s namespace, 0 without one,
    /// with the head's time joined to the published-time bound
    /// (`latest_epoch_ms`): a head bounds every epoch of its chain, so every
    /// instance settlement or recovery visits bounds rotation from the
    /// visit on, and recovery's enumeration completing leaves none a
    /// restart found unbounded.
    fn bounding_head(&self, controller: &NamespaceController) -> Result<u64, StoreError> {
        let Some(root) = self.head_root(controller)? else {
            return Ok(0);
        };
        self.latest_epoch_ms
            .fetch_max(root.timestamp_ms(), std::sync::atomic::Ordering::SeqCst);
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
    /// charge and completes the registration in one update.
    pub(super) fn reconstruct_slice(
        &self,
        controller: &Arc<NamespaceController>,
        work: &mut Work,
    ) -> Result<(), StoreError> {
        if work.spent() {
            return Ok(());
        }
        let instance = controller.instance;
        let exhausted = || StoreError::Internal(format!("epoch numbers of {instance} exhausted"));
        let checkpoint = self
            .settled_epoch(&instance)?
            .map_or(0, |(number, _)| number);
        let first = checkpoint.checked_add(1).ok_or_else(exhausted)?;
        let head = self.bounding_head(controller)?;
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
            return Ok(());
        };
        while epoch <= head && !work.spent() {
            let mut measure = Measure::default();
            let verified =
                self.read_epoch(&instance, epoch, Purpose::Reconstruct, work, &mut measure)?;
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
                Ok::<_, StoreError>(
                    verified
                        .is_some()
                        .then(|| std::mem::take(&mut obligation.measured)),
                )
            });
            // Discharged meanwhile: settlement reached the head.
            let Some(measured) = measured else {
                return Ok(());
            };
            let Some((entries, bytes)) = measured? else {
                break;
            };
            let debt = self.unsettled.debt(entries, bytes)?;
            let next = epoch.checked_add(1).ok_or_else(exhausted)?;
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
        Ok(())
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
