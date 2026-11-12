//! A prepared epoch awaiting its signature and commit: the publication of
//! one execution, with the ownership the execution handed over and the
//! guard of the authority it is sealed under.
//!
//! Preparation (`PersistentStore::prepare_epoch_transaction`) runs the first
//! part of the seal (`epoch_seal::prepare_seal`) and consumes no signing
//! coordinate: dropping a prepared publication aborts its transaction and
//! leaves nothing. Its commit, in order:
//!
//! 1. the deadline is decided before consuming a coordinate;
//! 2. the publication's unsettled ownership is reserved, the identities it
//!    wrote are registered for discovery, and its instance is marked
//!    pending, so a refusal here still consumes no coordinate;
//! 3. the second part of the seal (`epoch_seal::complete_seal`) stores the
//!    custody record, which consumes the coordinate, signs, and installs
//!    what the signed root generates; from here a failure retains the
//!    publication (`StoreError::PublicationRetained`);
//! 4. the namespace's plane decides and the transaction commits.
//!
//! The outcome is classified against the custody record: a committed epoch
//! discharges it; a commit known not to have happened leaves it, and the
//! publication is retained for resolution; an unknown outcome fences the
//! namespace and leaves it for recovery. The guard is handed back with the
//! classification: an ordinary publication releases the shared activation
//! guard before any post-commit work; an activation receives
//! [`ActivationOutcome`], which owns the hold in every variant, so it
//! installs its candidate or records its outcome before the exclusive gate
//! opens.

use std::sync::Arc;
use std::time::Instant;

use kappa_store::work::{Meter, WorkMeter};
use kappa_store::{ClockMs, EpochAuthority, Kappa, NamespaceRef, StoreError};

use crate::PersistentStore;
use crate::authority::ActivationHold;
use crate::custody::{CustodyRead, CustodyRecord};
use crate::epoch::{AuthorityGuard, Committed, SealedEpoch, SharedAuthority};
use crate::epoch_seal::{SealCompletion, SealPreparation};
use crate::error::CommitFailure;
use crate::namespace_write::DirectoryGuard;
use crate::settlement::ReleaseGrant;
use crate::storage::{Active, Publish, WriterToken};
use crate::unsettled::{Class, Parked};

#[path = "publication_capacity.rs"]
mod capacity;

/// A prepared, unsigned publication. Dropping it aborts redb's transaction
/// and consumes no signing coordinate; only its commit signs and publishes.
#[must_use = "publish the prepared epoch or drop it to abort its transaction"]
pub struct PreparedEpochPublication<'a, G> {
    pub(super) store: &'a PersistentStore,
    /// Field order as in `EpochExecution`: transaction, then the prepared
    /// seal and the authority guard, then directory changes, then gate,
    /// then activity grant, then release grant. A publication dropped
    /// unpublished aborts its transaction before its guard ends.
    pub(super) transaction: redb::WriteTransaction,
    pub(super) preparation: SealPreparation,
    pub(super) guard: G,
    /// The authority the epoch is signed under: the installed one, or the
    /// activation's candidate, kept in force by `guard`.
    pub(super) authority: Arc<EpochAuthority>,
    /// The publication's work, from its preparation through its custody.
    pub(super) meter: WorkMeter,
    /// The authorization rows the execution read, carried into custody.
    pub(super) reads: Vec<CustodyRead>,
    pub(super) directory: DirectoryGuard<'a>,
    pub(super) writer: WriterToken,
    pub(super) active: Active<Publish>,
    /// Decides the publication's admission class: a governed release
    /// publishing while its instance's obligation closes the pool.
    pub(super) release: Option<ReleaseGrant<'a>>,
    pub(super) namespace: NamespaceRef,
    pub(super) now: ClockMs,
    pub(super) deadline: Option<Instant>,
    pub(super) content_pins: Vec<crate::allocation::Pin>,
    pub(super) clock: Arc<dyn kappa_store::time::Clock>,
}

/// What a publication's commit established.
pub(crate) enum Outcome {
    /// Committed at `(epoch number, root identity)`.
    Committed((u64, Kappa)),
    /// Known not to have committed and no coordinate consumed: nothing of
    /// it persists.
    NotCommitted(StoreError),
    /// Known not to have committed after its coordinate was consumed: held
    /// in its instance's custody until resolution publishes it or finds it
    /// terminal.
    Retained(StoreError),
    /// Whether it committed is unknown: the namespace is fenced and its
    /// dependencies belong to recovery.
    Indeterminate(StoreError),
}

impl Outcome {
    /// The caller-facing result: success only for a committed epoch.
    pub(crate) fn into_result(self) -> Result<(u64, Kappa), StoreError> {
        match self {
            Self::Committed(published) => Ok(published),
            Self::NotCommitted(error) | Self::Retained(error) | Self::Indeterminate(error) => {
                Err(error)
            }
        }
    }
}

/// The classified outcome of an activation's governing epoch, each variant
/// owning the activation's hold: the activation decides what follows its
/// outcome (install the candidate, record an unknown or retained outcome,
/// withdraw its intent) before the exclusive gate opens.
#[must_use = "an activation outcome must be acted on before its hold is released"]
pub(crate) enum ActivationOutcome<'a> {
    Committed {
        publication: (u64, Kappa),
        hold: ActivationHold<'a>,
    },
    NotCommitted {
        error: StoreError,
        hold: ActivationHold<'a>,
    },
    Retained {
        error: StoreError,
        hold: ActivationHold<'a>,
    },
    Indeterminate {
        error: StoreError,
        hold: ActivationHold<'a>,
    },
}

impl<'a> ActivationOutcome<'a> {
    pub(crate) fn of(outcome: Outcome, hold: ActivationHold<'a>) -> Self {
        match outcome {
            Outcome::Committed(publication) => Self::Committed { publication, hold },
            Outcome::NotCommitted(error) => Self::NotCommitted { error, hold },
            Outcome::Retained(error) => Self::Retained { error, hold },
            Outcome::Indeterminate(error) => Self::Indeterminate { error, hold },
        }
    }
}

/// What a classified publication still owns: its post-commit obligations
/// and the ownership they run under. Fields drop in declaration order:
/// the stage (a noncommit's parked pins release here), then the directory
/// resolves under the writer gate, then the gate opens, then the activity
/// grant ends, then the release grant.
struct Classified<'a> {
    stage: Stage,
    directory: DirectoryGuard<'a>,
    _writer: WriterToken,
    active: Active<Publish>,
    _release: Option<ReleaseGrant<'a>>,
    store: &'a PersistentStore,
    namespace: NamespaceRef,
    now: ClockMs,
}

enum Stage {
    NotCommitted(StoreError),
    Retained(StoreError, Parked),
    Indeterminate(StoreError, Parked),
    Committed((u64, Kappa), Parked),
}

impl Classified<'_> {
    /// Discharge the post-commit obligations of the stage under the writer
    /// gate, on `work`, what remains of the publication's allowance, and
    /// report the outcome. The stage is consumed first, then the directory
    /// resolves under the writer gate, then the gate opens, then the
    /// activity grant ends, then the release grant.
    fn finish(self, work: &mut dyn Meter) -> Outcome {
        let Self {
            stage,
            directory,
            _writer: writer,
            active,
            _release: release,
            store,
            namespace,
            now,
        } = self;
        let outcome = match stage {
            // Known noncommit: nothing persisted; dropping the parked pins
            // released their charge before classification reached here.
            // The directory follows the record still committed, which
            // releases the reservations the publication made.
            Stage::NotCommitted(error) => {
                if let Err(resolution) = directory.resolve(work) {
                    tracing::warn!(
                        namespace = %namespace,
                        error = %resolution,
                        "directory changes of an uncommitted publication left to settlement"
                    );
                }
                Outcome::NotCommitted(error)
            }
            Stage::Retained(error, parked) => {
                active
                    .controller()
                    .unresolved_content
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .append(parked);
                directory.disarm();
                Outcome::Retained(error)
            }
            // Unknown: the namespace is fenced; every allocation dependency,
            // and its charge, belongs to recovery until it resolves, and so
            // do the directory changes, which settlement resolves against
            // the outcome a fresh open recovers.
            Stage::Indeterminate(error, parked) => {
                active
                    .controller()
                    .unresolved_content
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .append(parked);
                directory.disarm();
                Outcome::Indeterminate(error)
            }
            Stage::Committed(published, mut parked) => {
                store.raise_committed_floor(now);
                parked.append(std::mem::take(
                    &mut *active
                        .controller()
                        .unresolved_content
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                ));
                // The installed allocations are owned by their rows in the
                // namespace database, and by the registry's projection once
                // this epoch settles. The pins and their charge stay parked
                // until then; the retired rows' allocations are reclaimed by
                // that settlement.
                active.controller().park_until_settled(published.0, parked);
                // The directory follows the committed record under the gate,
                // so a reader resolves the publication's aliases once it
                // returns. A failure is not the publication's: the epoch is
                // committed, its journal durable and its instance pending,
                // so settlement resolves the directory at the head; until
                // then a reservation resolves to nothing and a released
                // alias still resolves.
                if let Err(error) = directory.resolve(work) {
                    tracing::warn!(
                        namespace = %namespace,
                        epoch = published.0,
                        %error,
                        "directory changes of a committed epoch left to settlement"
                    );
                }
                Outcome::Committed(published)
            }
        };
        drop(writer);
        drop(active);
        drop(release);
        outcome
    }
}

/// The parts of a prepared publication its commit consumes; the rest of its
/// ownership goes to its classification.
struct Commit<'s, 'b, G> {
    store: &'s PersistentStore,
    transaction: redb::WriteTransaction,
    preparation: SealPreparation,
    guard: G,
    authority: Arc<EpochAuthority>,
    meter: &'b mut WorkMeter,
    custody: Option<CustodyRecord>,
    clock: &'b dyn kappa_store::time::Clock,
    reads: Vec<CustodyRead>,
    writer: &'b WriterToken,
    active: &'b Active<Publish>,
    release: Option<&'b ReleaseGrant<'s>>,
    namespace: &'b NamespaceRef,
    deadline: Option<Instant>,
    content_pins: Vec<crate::allocation::Pin>,
}

impl<'s, G: AuthorityGuard<'s>> Commit<'s, '_, G> {
    /// Steps 1 to 4 of the module documentation, classified. The guard is
    /// returned with the stage.
    fn run(self) -> (Stage, G) {
        let Self {
            store,
            transaction,
            preparation,
            guard,
            authority,
            meter,
            mut custody,
            clock,
            reads,
            writer,
            active,
            release,
            namespace,
            deadline,
            content_pins,
        } = self;
        // A deadline refusal here consumes no coordinate. After signing,
        // failed standing retains the candidate instead of discarding it.
        if let Some(deadline) = deadline {
            let overrun = Instant::now().saturating_duration_since(deadline);
            if !overrun.is_zero() {
                drop(transaction);
                return (
                    Stage::NotCommitted(StoreError::DeadlineExceeded {
                        namespace: *namespace.id(),
                        overrun_ms: u64::try_from(overrun.as_millis()).unwrap_or(u64::MAX),
                    }),
                    guard,
                );
            }
        }
        let controller = Arc::clone(active.controller());
        // Unsettled ownership is reserved before the coordinate is consumed:
        // a publication the node-wide bound cannot hold is refused here,
        // with its transaction dropped and so aborted, and nothing charged.
        // From here the charge travels with the pins, and is released only
        // when they drop. A governed release carrying its grant takes no
        // charge and is admitted while its obligation closes the pool.
        let class = release.map_or(Class::Ordinary, Class::Resolving);
        let reserved = (|| {
            let charge = if custody.is_some() {
                store.reserve_reconstructed_pins(
                    &controller,
                    &content_pins,
                    custody.as_ref(),
                    meter,
                )?
            } else {
                store.unsettled.reserve(&content_pins, class)?
            };
            // Every identity this transaction wrote a row for is registered
            // before the commit, so a read by identity alone finds it from
            // the commit on; the registration is parked with the ownership
            // and dropped when this epoch settles into the catalog, at once
            // on a noncommit, and by recovery for an unknown outcome.
            let installed = take_installed(&controller)?;
            let registration = store
                .unsettled_index
                .register(controller.instance, installed)?;
            // Durable before the commit, under the gate: a crash after the
            // commit finds the instance pending and recovery settles it.
            store.mark_unsettled(&controller.instance)?;
            Ok::<_, StoreError>((charge, registration))
        })();
        let (charge, registration) = match reserved {
            Ok(reserved) => reserved,
            Err(error) => {
                drop(transaction);
                if let Some(record) = custody.as_mut() {
                    if let Ok(earlier) = record.work() {
                        record.set_work(&earlier.saturating_add(meter.used()));
                    }
                    let error = store.retain(writer, &controller.instance, record, &error);
                    return (Stage::Retained(error, Parked::default()), guard);
                }
                return (Stage::NotCommitted(error), guard);
            }
        };
        let mut pins = content_pins;
        let predecessor = preparation.predecessor.clone();
        let assigns = preparation.assigns;
        let activation = guard.activation().map(ActivationHold::custody);
        let completion = if let Some(custody) = custody {
            store.resume_seal(
                writer,
                &transaction,
                namespace,
                preparation,
                &authority,
                custody,
                meter,
            )
        } else {
            store.complete_seal(
                writer,
                &transaction,
                namespace,
                preparation,
                &authority,
                activation,
                reads,
                meter,
            )
        };
        let SealCompletion {
            root,
            pins: generated,
            mut custody,
        } = match completion {
            Ok(completion) => completion,
            Err(error) => {
                drop(transaction);
                let stage = match error {
                    StoreError::PublicationRetained(_) => Stage::Retained(
                        error,
                        Parked::new(pins, charge).with_registration(registration),
                    ),
                    other => Stage::NotCommitted(other),
                };
                return (stage, guard);
            }
        };
        // The records the signed root generated: their pins carry the
        // charge their preparation reserved, and their rows are registered
        // as committed-to-be ownership, which no bound refuses once the
        // coordinate is consumed.
        pins.extend(generated);
        let instance = controller.instance;
        let generated_rows = take_pins(&controller)
            .map(|parked| pins.extend(parked))
            .and_then(|()| take_installed(&controller))
            .and_then(|rows| store.unsettled_index.register_beyond_bound(instance, rows));
        let generated_rows = match generated_rows {
            Ok(registration) => registration,
            Err(error) => {
                drop(transaction);
                let retained = store.retain(writer, &instance, &mut custody, &error);
                return (
                    Stage::Retained(
                        retained,
                        Parked::new(pins, charge).with_registration(registration),
                    ),
                    guard,
                );
            }
        };
        let mut parked = Parked::new(pins, charge)
            .with_registration(registration)
            .with_registration(generated_rows);
        if let Some(debt) = store
            .custody_debt
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&instance)
        {
            parked.append(Parked::new(Vec::new(), debt));
        }
        {
            let before = *meter.used();
            let standing = store.custody_standing(&custody, &authority, clock, meter);
            let accounted = custody.work().map(|earlier| {
                custody.set_work(&earlier.saturating_add(&meter.used().since(&before)));
            });
            if let Err(error) = standing.and(accounted) {
                drop(transaction);
                if matches!(error, StoreError::Conflict(_) | StoreError::Rejected(_)) {
                    custody.make_terminal(&error);
                }
                let retained = store.retain(writer, &instance, &mut custody, &error);
                return (Stage::Retained(retained, parked), guard);
            }
        }
        // A governing epoch refused at the last point before its commit:
        // the activation's known-noncommit schedule.
        #[cfg(test)]
        if guard.activation().is_some() && store.hooks.activation_commit_refused() {
            drop(transaction);
            let refused = StoreError::Unavailable("activation commit refused by test hook".into());
            let retained = store.retain(writer, &instance, &mut custody, &refused);
            return (Stage::Retained(retained, parked), guard);
        }
        // The writer gate is held across the commit and its classification,
        // so an unknown outcome fences the namespace before the next
        // admission can observe the gate open.
        let committed_root = root.clone();
        let before = *meter.used();
        let Committed { outcome, guard } = store.commit_epoch_transaction(
            transaction,
            &controller,
            namespace,
            SealedEpoch {
                root,
                predecessor,
                assigns,
                guard,
            },
            &mut *meter,
        );
        // The commit's verification and resolution are the publication's
        // work: a retained or indeterminate outcome records them in custody.
        if let Ok(earlier) = custody.work() {
            custody.set_work(&earlier.saturating_add(&meter.used().since(&before)));
        }
        let stage = match outcome {
            Ok(published) => {
                discharge(
                    store,
                    writer,
                    &instance,
                    &mut custody,
                    &committed_root,
                    meter,
                );
                Stage::Committed(published, parked)
            }
            Err(CommitFailure::Known(error)) => Stage::Retained(
                store.retain(writer, &instance, &mut custody, &error),
                parked,
            ),
            Err(CommitFailure::Unknown(error)) => {
                // Preserve the final standing work and signing progress even
                // when commit classification cannot determine durability.
                store.retain(writer, &instance, &mut custody, &error);
                Stage::Indeterminate(error, parked)
            }
        };
        (stage, guard)
    }
}

/// Discharge the custody of a committed epoch. A discharge that fails is
/// not the publication's: the record stays, admission refuses the instance
/// until resolution finds the custodied candidate committed at its
/// coordinate and discharges it.
fn discharge(
    store: &PersistentStore,
    writer: &WriterToken,
    instance: &crate::storage_instance::StorageInstance,
    custody: &mut CustodyRecord,
    root: &kappa_store::EpochRoot,
    work: &mut dyn Meter,
) {
    let before = *work.used();
    let outcome = store.discharge_custody(writer, instance, custody, root, work);
    if let Ok(earlier) = custody.work() {
        custody.set_work(&earlier.saturating_add(&work.used().since(&before)));
    }
    if let Err(error) = outcome {
        // Keep work and progress from after the final signing callback even
        // when removal of the committed candidate's custody fails.
        store.retain(writer, instance, custody, &error);
        tracing::warn!(
            instance = %instance,
            epoch = root.epoch_number(),
            %error,
            "custody of a committed epoch not discharged; resolution discharges it"
        );
    }
}

/// The identities the open transaction made discoverable, taken.
fn take_installed(
    controller: &crate::storage::NamespaceController,
) -> Result<Vec<crate::unsettled_index::DiscoveryKey>, StoreError> {
    Ok(std::mem::take(
        &mut *controller
            .installed_rows
            .lock()
            .map_err(|_| StoreError::Internal("installed row set poisoned".into()))?,
    ))
}

/// The pins write helpers parked on the controller in the open
/// transaction, taken.
fn take_pins(
    controller: &crate::storage::NamespaceController,
) -> Result<Vec<crate::allocation::Pin>, StoreError> {
    Ok(std::mem::take(
        &mut *controller
            .writer_pins
            .lock()
            .map_err(|_| StoreError::Internal("writer pin set poisoned".into()))?,
    ))
}

impl<'a, G: AuthorityGuard<'a>> PreparedEpochPublication<'a, G> {
    /// Continue custody through the same resource admission, seal, decision,
    /// commit classification and settlement handoff as an initial publication.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn resume(
        store: &'a PersistentStore,
        ownership: super::ExecutionOwnership<'a, G>,
        namespace: NamespaceRef,
        transaction: redb::WriteTransaction,
        preparation: SealPreparation,
        authority: Arc<EpochAuthority>,
        custody: CustodyRecord,
        content_pins: Vec<crate::allocation::Pin>,
        meter: &mut WorkMeter,
        clock: &dyn kappa_store::time::Clock,
    ) -> (Result<(u64, Kappa), StoreError>, G) {
        let super::ExecutionOwnership {
            guard,
            directory,
            writer,
            active,
            release,
        } = ownership;
        let now = ClockMs::from_raw(custody.now_ms);
        let (stage, guard) = Commit {
            store,
            transaction,
            preparation,
            guard,
            authority,
            meter,
            custody: Some(custody),
            clock,
            reads: Vec::new(),
            writer: &writer,
            active: &active,
            release: release.as_ref(),
            namespace: &namespace,
            deadline: None,
            content_pins,
        }
        .run();
        let outcome = Classified {
            stage,
            directory,
            _writer: writer,
            active,
            _release: release,
            store,
            namespace,
            now,
        }
        .finish(meter)
        .into_result();
        (outcome, guard)
    }

    /// The ledger the prepared epoch commits: installed in its transaction
    /// before any coordinate is consumed.
    #[cfg(test)]
    pub(crate) fn ledger(&self) -> &Kappa {
        self.preparation.candidate.ledger().kappa()
    }

    /// The one commit of a prepared publication. The guard is held until
    /// the commit's outcome is classified, and is returned with the
    /// classification and what remains of the publication's allowance,
    /// which the classification's post-commit work continues on.
    fn commit(self) -> (Classified<'a>, G, WorkMeter) {
        let Self {
            store,
            transaction,
            preparation,
            guard,
            authority,
            mut meter,
            reads,
            clock,
            directory,
            writer,
            active,
            release,
            namespace,
            now,
            deadline,
            content_pins,
        } = self;
        let (stage, guard) = Commit {
            store,
            transaction,
            preparation,
            guard,
            authority,
            meter: &mut meter,
            custody: None,
            clock: clock.as_ref(),
            reads,
            writer: &writer,
            active: &active,
            release: release.as_ref(),
            namespace: &namespace,
            deadline,
            content_pins,
        }
        .run();
        (
            Classified {
                stage,
                directory,
                _writer: writer,
                active,
                _release: release,
                store,
                namespace,
                now,
            },
            guard,
            meter,
        )
    }
}

impl<'a> PreparedEpochPublication<'a, SharedAuthority<'a>> {
    /// Commit under the installed authority the epoch was sealed under:
    /// every ordinary publication. The shared activation guard ends as soon
    /// as the outcome is classified, before any post-commit work.
    pub(crate) fn publish(self) -> Result<(u64, Kappa), StoreError> {
        let (classified, guard, mut meter) = self.commit();
        guard.release();
        classified.finish(&mut meter).into_result()
    }
}

impl<'a> PreparedEpochPublication<'a, ActivationHold<'a>> {
    /// Commit an activation's governing epoch. The outcome owns the hold
    /// that sealed it in every variant.
    pub(crate) fn publish_governing(self) -> ActivationOutcome<'a> {
        let (classified, hold, mut meter) = self.commit();
        ActivationOutcome::of(classified.finish(&mut meter), hold)
    }
}

impl PreparedEpochPublication<'_, SharedAuthority<'_>> {
    /// Commit a sealed root against a transaction without its seal: the
    /// crate-private seam tests drive to show that a root from another
    /// transaction, or a transaction changed after sealing, is refused.
    #[cfg(test)]
    pub(crate) fn commit_test_transaction(
        store: &PersistentStore,
        writer: crate::test_support::TestWriter,
        ns: &NamespaceRef,
        root: kappa_store::EpochRoot,
    ) -> Result<(u64, Kappa), StoreError> {
        let predecessor = root.prev_identifier().cloned();
        let controller = Arc::clone(writer.active.controller());
        let guard = store.shared_authority()?;
        // This seam is the publication: its allowance is the store's
        // configured publication limit, as an execution's admission takes.
        let mut meter = WorkMeter::new(store.publication_work);
        let Committed { outcome, guard } = store.commit_epoch_transaction(
            writer.txn,
            &controller,
            ns,
            SealedEpoch {
                root,
                predecessor,
                assigns: true,
                guard,
            },
            &mut meter,
        );
        drop(guard);
        drop(writer.writer);
        drop(writer.active);
        match outcome {
            Ok(published) => Ok(published),
            Err(CommitFailure::Known(error) | CommitFailure::Unknown(error)) => Err(error),
        }
    }
}
