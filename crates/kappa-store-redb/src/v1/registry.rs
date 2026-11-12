//! The registry database and the one slot every registry writer holds:
//! acquisition (waiting, [`Standing`], and non-waiting, [`Attempt`]),
//! commit classification and the unknown-outcome fence, and abort.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, PoisonError, TryLockError};

use redb::Database;

use kappa_store::error::StoreError;

use crate::error;

#[cfg(test)]
#[path = "registry_tests.rs"]
mod registry_tests;

/// The registry database and the slot every registry writer holds.
///
/// The database is private: a registry write transaction exists only as a
/// [`RegistryWrite`], which holds the slot from before redb's writer is
/// taken until after it is released. Every registry write acquires this
/// slot before calling redb; once acquired, no other registry write
/// transaction can hold redb's writer. This excludes writer contention at
/// that boundary ([`Registry::try_begin_write`] reports it without
/// waiting); it does not bound storage I/O or establish the lock order of
/// callers holding other resources.
///
/// A commit whose outcome redb leaves unknown makes the registry
/// recovery-required for the life of this handle: its effects may or may
/// not be durable, and a read of this handle may show them either way.
/// From then on no writer is admitted and no read establishes committed
/// state ([`Registry::established_read_standing`]); a reopen recovers what
/// persisted. Plain reads ([`Registry::begin_read`]) take no slot and
/// establish nothing beyond what they show.
pub(crate) struct Registry {
    database: Database,
    gate: Arc<RegistryGate>,
}

/// Whether a registry writer holds the slot, the wakeup of a writer waiting
/// for it, and whether a commit of this handle has an unknown outcome.
#[derive(Default)]
struct RegistryGate {
    held: Mutex<bool>,
    released: Condvar,
    /// Set, before the slot of the commit is released, when a commit's
    /// outcome is unknown; never cleared on this handle.
    recovery_required: AtomicBool,
    /// The outcome the next commit reports instead of its own.
    #[cfg(test)]
    commit_fault: Mutex<Option<crate::test_hooks::CommitFault>>,
    /// Run once by the next commit of unknown outcome after it marks the
    /// registry recovery-required and before it releases the slot.
    #[cfg(test)]
    fenced_pause: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

/// What a non-waiting registry acquisition obtained, or why it obtained
/// nothing now. Callers that own work across either condition keep the
/// type; neither is an error of the work they were doing.
pub(crate) enum Attempt<T> {
    /// Acquired while holding the writer slot of a handle with no commit of
    /// unknown outcome: a writer, or a snapshot of known committed state.
    Ready(T),
    /// Another writer holds the slot or is taking it.
    Busy,
    /// A commit of this handle has an unknown outcome; only a reopen
    /// establishes what persisted.
    RecoveryRequired,
}

/// What a waiting registry acquisition obtained, or that a commit of this
/// handle has an unknown outcome and only a reopen establishes what
/// persisted. Callers that own work across that condition (settlement,
/// recovery) keep the type; operations that report it convert it at their
/// boundary ([`Self::or_unavailable`]).
pub(crate) enum Standing<T> {
    Ready(T),
    RecoveryRequired,
}

impl<T> Standing<T> {
    /// The acquired value, or the refusal an operation that depends on
    /// established registry state reports.
    pub(crate) fn or_unavailable(self) -> Result<T, StoreError> {
        match self {
            Self::Ready(value) => Ok(value),
            Self::RecoveryRequired => Err(StoreError::Unavailable(
                "a registry commit's outcome is unknown on this handle; reopen the store to recover what persisted"
                    .into(),
            )),
        }
    }
}

/// Ownership of the registry writer slot; released when dropped.
struct RegistrySlot {
    gate: Arc<RegistryGate>,
}

impl Drop for RegistrySlot {
    fn drop(&mut self) {
        // The flag is one bool written under the lock; a panic elsewhere
        // cannot leave it half-written.
        let mut held = self
            .gate
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *held = false;
        drop(held);
        self.gate.released.notify_one();
    }
}

/// A registry write transaction holding the registry writer slot. Fields
/// drop in declaration order: an uncommitted transaction is aborted and
/// redb's writer released before the slot is.
pub(crate) struct RegistryWrite {
    txn: redb::WriteTransaction,
    slot: RegistrySlot,
}

// A registry transaction moves with the work that owns it, across threads.
const _: () = {
    const fn send<T: Send>() {}
    send::<RegistryWrite>();
};

impl Registry {
    /// The registry over `database`, no writer holding its slot.
    pub(crate) fn new(database: Database) -> Self {
        Self {
            database,
            gate: Arc::new(RegistryGate::default()),
        }
    }

    /// A snapshot of the registry, concurrent with any writer. It shows
    /// what this handle can read, which after a commit of unknown outcome
    /// is not established committed state.
    pub(crate) fn begin_read(&self) -> Result<redb::ReadTransaction, StoreError> {
        redb::ReadableDatabase::begin_read(&self.database).map_err(error::redb)
    }

    /// Whether a commit of this handle has an unknown outcome.
    pub(crate) fn recovery_required(&self) -> bool {
        self.gate.recovery_required.load(Ordering::Acquire)
    }

    /// Hold the writer slot, waiting while another holds it.
    fn hold_slot(&self) -> Result<RegistrySlot, StoreError> {
        let mut held = self
            .gate
            .held
            .lock()
            .map_err(|_| StoreError::Internal("registry writer slot poisoned".into()))?;
        while *held {
            held = self
                .gate
                .released
                .wait(held)
                .map_err(|_| StoreError::Internal("registry writer slot poisoned".into()))?;
        }
        *held = true;
        drop(held);
        Ok(RegistrySlot {
            gate: Arc::clone(&self.gate),
        })
    }

    /// Hold the writer slot when it is free now; `None`, without waiting,
    /// while another holds it or is taking it.
    fn try_hold_slot(&self) -> Result<Option<RegistrySlot>, StoreError> {
        let mut held = match self.gate.held.try_lock() {
            Ok(held) => held,
            Err(TryLockError::WouldBlock) => return Ok(None),
            Err(TryLockError::Poisoned(_)) => {
                return Err(StoreError::Internal("registry writer slot poisoned".into()));
            }
        };
        if *held {
            return Ok(None);
        }
        *held = true;
        drop(held);
        Ok(Some(RegistrySlot {
            gate: Arc::clone(&self.gate),
        }))
    }

    /// The registry writer, waiting for the slot while another holds it;
    /// `RecoveryRequired` once a commit's outcome is unknown, decided
    /// before and after the wait.
    pub(crate) fn write_standing(&self) -> Result<Standing<RegistryWrite>, StoreError> {
        if self.recovery_required() {
            return Ok(Standing::RecoveryRequired);
        }
        let slot = self.hold_slot()?;
        if self.recovery_required() {
            return Ok(Standing::RecoveryRequired);
        }
        self.write_holding(slot).map(Standing::Ready)
    }

    /// [`Self::write_standing`] for an operation that reports recovery as
    /// its refusal (`Unavailable`).
    pub(crate) fn begin_write(&self) -> Result<RegistryWrite, StoreError> {
        self.write_standing()?.or_unavailable()
    }

    /// The registry writer when its slot is free now, without waiting;
    /// `RecoveryRequired` once a commit's outcome is unknown, decided
    /// before and after taking the slot.
    pub(crate) fn try_begin_write(&self) -> Result<Attempt<RegistryWrite>, StoreError> {
        if self.recovery_required() {
            return Ok(Attempt::RecoveryRequired);
        }
        let Some(slot) = self.try_hold_slot()? else {
            return Ok(Attempt::Busy);
        };
        if self.recovery_required() {
            return Ok(Attempt::RecoveryRequired);
        }
        self.write_holding(slot).map(Attempt::Ready)
    }

    /// Begin redb's write transaction under `slot`. Every registry writer
    /// holds the slot, so no other registry transaction holds redb's
    /// writer; a failure releases the slot with `slot`.
    fn write_holding(&self, slot: RegistrySlot) -> Result<RegistryWrite, StoreError> {
        let txn = self.database.begin_write().map_err(error::redb)?;
        Ok(RegistryWrite { txn, slot })
    }

    /// A snapshot of established committed state, waiting for the writer
    /// slot: taken while the slot is held, so no commit is in flight, after
    /// confirming no commit of this handle has an unknown outcome. The
    /// snapshot is immutable once taken; the slot is released with it
    /// taken. `RecoveryRequired` while a commit's outcome is unknown.
    pub(crate) fn established_read_standing(
        &self,
    ) -> Result<Standing<redb::ReadTransaction>, StoreError> {
        let slot = self.hold_slot()?;
        if self.recovery_required() {
            return Ok(Standing::RecoveryRequired);
        }
        let read = self.begin_read()?;
        drop(slot);
        Ok(Standing::Ready(read))
    }

    /// [`Self::established_read_standing`] without waiting.
    pub(crate) fn try_begin_established_read(
        &self,
    ) -> Result<Attempt<redb::ReadTransaction>, StoreError> {
        if self.recovery_required() {
            return Ok(Attempt::RecoveryRequired);
        }
        let Some(slot) = self.try_hold_slot()? else {
            return Ok(Attempt::Busy);
        };
        if self.recovery_required() {
            return Ok(Attempt::RecoveryRequired);
        }
        let read = self.begin_read()?;
        drop(slot);
        Ok(Attempt::Ready(read))
    }

    /// Make the next commit report `fault` instead of its own outcome
    /// (`test_hooks::CommitFault`).
    #[cfg(test)]
    pub(crate) fn inject_commit_fault(&self, fault: crate::test_hooks::CommitFault) {
        *self
            .gate
            .commit_fault
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(fault);
    }

    /// Run `pause` once, on the committing thread, when the next commit of
    /// unknown outcome has marked the registry recovery-required and still
    /// holds the writer slot.
    #[cfg(test)]
    pub(crate) fn pause_when_fenced(&self, pause: impl FnOnce() + Send + 'static) {
        *self
            .gate
            .fenced_pause
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(Box::new(pause));
    }
}

impl RegistryWrite {
    /// Commit, then release the slot. The outcome is classified by what is
    /// known of its durability (`error::classify_commit`); an unknown one
    /// makes the registry recovery-required before the slot is released, so
    /// no writer or established read enters while it is unrecorded. The
    /// caller owns what an unknown outcome obliges of its own state.
    pub(crate) fn commit(self) -> Result<(), error::CommitFailure> {
        let Self { txn, slot } = self;
        let committed = error::classify_commit(Self::outcome(txn, &slot.gate));
        if matches!(committed, Err(error::CommitFailure::Unknown(_))) {
            slot.gate.recovery_required.store(true, Ordering::Release);
            #[cfg(test)]
            {
                let pause = slot
                    .gate
                    .fenced_pause
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .take();
                if let Some(pause) = pause {
                    pause();
                }
            }
        }
        drop(slot);
        committed
    }

    /// redb's outcome of committing `txn`.
    #[cfg(not(test))]
    fn outcome(txn: redb::WriteTransaction, _gate: &RegistryGate) -> Result<(), redb::CommitError> {
        txn.commit()
    }

    /// redb's outcome of committing `txn`, or the outcome an injected fault
    /// reports: the transaction committed or rolled back for real, and the
    /// caller told only that the outcome is unknown.
    #[cfg(test)]
    fn outcome(txn: redb::WriteTransaction, gate: &RegistryGate) -> Result<(), redb::CommitError> {
        use crate::test_hooks::CommitFault;
        let fault = gate
            .commit_fault
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        let unknown = || {
            redb::CommitError::Storage(redb::StorageError::Io(std::io::Error::other(
                "injected commit fault",
            )))
        };
        match fault {
            None => txn.commit(),
            Some(CommitFault::PersistedUnknown) => txn.commit().and_then(|()| Err(unknown())),
            Some(CommitFault::AbortedUnknown) => match txn.abort() {
                Ok(()) => Err(unknown()),
                Err(error) => Err(redb::CommitError::Storage(error)),
            },
        }
    }

    /// Roll back, then release the slot.
    pub(crate) fn abort(self) -> Result<(), StoreError> {
        let Self { txn, slot } = self;
        let aborted = txn.abort();
        drop(slot);
        aborted.map_err(error::redb)
    }
}

impl std::ops::Deref for RegistryWrite {
    type Target = redb::WriteTransaction;

    fn deref(&self) -> &Self::Target {
        &self.txn
    }
}

impl std::ops::DerefMut for RegistryWrite {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.txn
    }
}
