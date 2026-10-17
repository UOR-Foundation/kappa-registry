//! Bounded, batched durability for completed external allocations.
//!
//! Every admitted allocation moves through one state machine:
//!
//! ```text
//! Reserved  capacity charged; the writer is still producing the file
//! Ready     the writer declared its writes complete; eligible to freeze
//! Frozen    selected into the batch being synchronized
//! Covered   its batch synchronized; outcome retained until observed
//! Failed    its batch failed; outcome retained until observed
//! ```
//!
//! Only `Ready` allocations are frozen, so a synchronization never covers
//! bytes a writer has not finished. Capacity is charged from reservation
//! until the outcome is observed, including `Covered` and `Failed`, so slow
//! observers cannot grow the coordinator past its budget. Batches are
//! frozen in admission order, bounded by entries and bytes; an allocation
//! larger than the batch byte bound is synchronized as a batch of one,
//! which is why the queue byte bound must admit it in the first place.
//! A lone ready allocation is synchronized without delay. A request whose
//! deadline has already passed never starts a new batch; a request already
//! frozen is carried through by the worker that froze it.
//!
//! Outcomes are exact. A failed synchronization fences the coordinator
//! and records `Failed` for every member of that batch; allocations still
//! `Reserved` or `Ready` are refused when they ask. An allocation covered
//! by an earlier successful batch that observes its outcome after the
//! fence receives [`DurabilityOutcome::EstablishedThenFenced`]: its own
//! durability holds. `NotEstablished` means durability was not
//! established, never that the bytes are absent.
//!
//! A store configured without fsync never produces the durable
//! capability: `establish` returns [`Capability::Volatile`], and every
//! consumer that promises persistence refuses it.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Instant;

use kappa_types::StoreError;

use crate::representation::AllocationId;

#[cfg(test)]
#[path = "durability_tests.rs"]
mod tests;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurabilityLimits {
    /// Allocations charged against the coordinator at once, in any state.
    pub(crate) queue_entries: usize,
    /// Bytes (payload plus sidecar) charged at once.
    pub(crate) queue_bytes: u64,
    /// Largest frozen batch by entries.
    pub(crate) batch_entries: usize,
    /// Largest frozen batch by bytes; a single larger allocation forms a
    /// batch of one.
    pub(crate) batch_bytes: u64,
}

impl DurabilityLimits {
    pub(crate) fn validate(self) -> Result<Self, StoreError> {
        if self.queue_entries == 0
            || self.batch_entries == 0
            || self.queue_bytes == 0
            || self.batch_bytes == 0
            || self.batch_entries > self.queue_entries
            || self.batch_bytes > self.queue_bytes
        {
            return Err(StoreError::Rejected(
                "durability limits must be positive with batch bounds within queue bounds".into(),
            ));
        }
        Ok(self)
    }
}

/// What establishing durability concluded for one allocation.
#[derive(Debug)]
pub enum DurabilityOutcome {
    /// The batch covering this allocation synchronized successfully.
    Established,
    /// Covered by a successful batch; the coordinator has since fenced.
    EstablishedThenFenced,
    /// Durability was not established: the covering batch failed, the
    /// coordinator fenced first, or the allocation was never admitted.
    NotEstablished(StoreError),
    /// The deadline passed before the allocation was frozen.
    DeadlineExceeded,
}

/// The durability a prepared allocation actually has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    Durable,
    Volatile,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    Reserved,
    Ready,
    Frozen,
    Covered,
    Failed,
}

struct Entry {
    bytes: u64,
    phase: Phase,
    /// Admission order, for age-ordered freezing.
    sequence: u64,
    /// Fence reason recorded for a `Failed` entry.
    failure: Option<String>,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<AllocationId, Entry>,
    charged_bytes: u64,
    next_sequence: u64,
    syncing: bool,
    fenced: Option<String>,
}

pub struct Durability {
    blob_root: PathBuf,
    fsync: bool,
    limits: DurabilityLimits,
    state: Mutex<State>,
    changed: Condvar,
}

impl Durability {
    pub(crate) fn new(
        blob_root: PathBuf,
        fsync: bool,
        limits: DurabilityLimits,
    ) -> Result<Self, StoreError> {
        Ok(Self {
            blob_root,
            fsync,
            limits: limits.validate()?,
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
        })
    }

    fn lock(&self) -> Result<MutexGuard<'_, State>, StoreError> {
        self.state
            .lock()
            .map_err(|_| StoreError::Internal("durability coordinator poisoned".into()))
    }

    /// Reserve capacity for an allocation of `bytes` before its file is
    /// written. Refused, with nothing changed, when the budget is
    /// exhausted or the allocation is already admitted in any phase.
    pub(crate) fn reserve(&self, allocation: AllocationId, bytes: u64) -> Result<(), StoreError> {
        let mut state = self.lock()?;
        if let Some(reason) = &state.fenced {
            return Err(StoreError::Internal(format!(
                "content durability fenced: {reason}"
            )));
        }
        if state.entries.contains_key(&allocation) {
            return Err(StoreError::Internal(
                "allocation reserved durability twice".into(),
            ));
        }
        if bytes > self.limits.queue_bytes {
            return Err(StoreError::CapacityExceeded(format!(
                "allocation of {bytes} bytes exceeds the durability queue budget"
            )));
        }
        if state.entries.len() >= self.limits.queue_entries
            || state.charged_bytes.saturating_add(bytes) > self.limits.queue_bytes
        {
            return Err(StoreError::CapacityExceeded(
                "content durability queue is full".into(),
            ));
        }
        let sequence = state.next_sequence;
        state.next_sequence += 1;
        state.entries.insert(
            allocation,
            Entry {
                bytes,
                phase: Phase::Reserved,
                sequence,
                failure: None,
            },
        );
        state.charged_bytes = state.charged_bytes.saturating_add(bytes);
        drop(state);
        Ok(())
    }

    /// Release an allocation that will never be synchronized: the write
    /// failed or the preparation was abandoned before it was ready. A
    /// frozen allocation cannot be abandoned; its worker settles it.
    pub(crate) fn abandon(&self, allocation: &AllocationId) -> Result<(), StoreError> {
        let mut state = self.lock()?;
        let frozen = state
            .entries
            .get(allocation)
            .is_some_and(|entry| entry.phase == Phase::Frozen);
        if frozen {
            return Err(StoreError::Conflict(
                "allocation is frozen in a synchronizing batch".into(),
            ));
        }
        Self::release(&mut state, allocation);
        drop(state);
        Ok(())
    }

    /// Declare the allocation's writes complete and establish its
    /// durability before `deadline`. The outcome is consumed by this call;
    /// capacity is released when it returns.
    pub(crate) fn establish(
        &self,
        allocation: AllocationId,
        deadline: Instant,
    ) -> (Capability, DurabilityOutcome) {
        let outcome = match self.establish_inner(allocation, deadline) {
            Ok(outcome) => outcome,
            Err(error) => DurabilityOutcome::NotEstablished(error),
        };
        let capability = match (&outcome, self.fsync) {
            (DurabilityOutcome::Established | DurabilityOutcome::EstablishedThenFenced, true) => {
                Capability::Durable
            }
            _ => Capability::Volatile,
        };
        (capability, outcome)
    }

    fn release(state: &mut State, allocation: &AllocationId) {
        if let Some(entry) = state.entries.remove(allocation) {
            state.charged_bytes = state.charged_bytes.saturating_sub(entry.bytes);
        }
    }

    fn establish_inner(
        &self,
        allocation: AllocationId,
        deadline: Instant,
    ) -> Result<DurabilityOutcome, StoreError> {
        let mut state = self.lock()?;
        match state.entries.get_mut(&allocation) {
            None => {
                return Err(StoreError::Internal(
                    "allocation was not reserved for durability".into(),
                ));
            }
            Some(entry) if entry.phase == Phase::Reserved => entry.phase = Phase::Ready,
            Some(_) => {
                return Err(StoreError::Internal(
                    "allocation declared ready twice".into(),
                ));
            }
        }
        if !self.fsync {
            Self::release(&mut state, &allocation);
            return Ok(DurabilityOutcome::Established);
        }
        loop {
            let phase = state
                .entries
                .get(&allocation)
                .map(|entry| entry.phase)
                .ok_or_else(|| StoreError::Internal("admitted allocation vanished".into()))?;
            match phase {
                Phase::Covered => {
                    let fenced = state.fenced.is_some();
                    Self::release(&mut state, &allocation);
                    return Ok(if fenced {
                        DurabilityOutcome::EstablishedThenFenced
                    } else {
                        DurabilityOutcome::Established
                    });
                }
                Phase::Failed => {
                    let reason = state
                        .entries
                        .get(&allocation)
                        .and_then(|entry| entry.failure.clone())
                        .unwrap_or_default();
                    Self::release(&mut state, &allocation);
                    return Err(StoreError::Internal(format!(
                        "content synchronization failed: {reason}"
                    )));
                }
                Phase::Frozen => {
                    // Another worker froze this allocation; it settles it.
                    state = self
                        .changed
                        .wait(state)
                        .map_err(|_| StoreError::Internal("durability wait poisoned".into()))?;
                    continue;
                }
                Phase::Reserved => {
                    return Err(StoreError::Internal("ready allocation regressed".into()));
                }
                Phase::Ready => {}
            }
            if let Some(reason) = &state.fenced {
                let reason = reason.clone();
                Self::release(&mut state, &allocation);
                return Err(StoreError::Internal(format!(
                    "content durability fenced: {reason}"
                )));
            }
            if state.syncing {
                let now = Instant::now();
                if now >= deadline {
                    Self::release(&mut state, &allocation);
                    return Ok(DurabilityOutcome::DeadlineExceeded);
                }
                state = self
                    .changed
                    .wait_timeout(state, deadline.saturating_duration_since(now))
                    .map_err(|_| StoreError::Internal("durability wait poisoned".into()))?
                    .0;
                continue;
            }
            if Instant::now() >= deadline {
                Self::release(&mut state, &allocation);
                return Ok(DurabilityOutcome::DeadlineExceeded);
            }
            state = self.run_batch(state)?;
        }
    }

    /// Freeze a batch under `state`, synchronize it with the lock released,
    /// and record its outcome for every member: `Covered` on success, or
    /// `Failed` with the coordinator fenced. Waiters are woken either way.
    /// Returns the reacquired guard.
    fn run_batch<'a>(
        &'a self,
        mut state: MutexGuard<'a, State>,
    ) -> Result<MutexGuard<'a, State>, StoreError> {
        let batch = Self::freeze(&mut state, self.limits);
        state.syncing = true;
        drop(state);
        let result = self.synchronize();
        let mut state = self.lock()?;
        state.syncing = false;
        let (phase, failure) = match result {
            Ok(()) => (Phase::Covered, None),
            Err(error) => {
                let reason = error.to_string();
                state.fenced = Some(reason.clone());
                (Phase::Failed, Some(reason))
            }
        };
        for id in &batch {
            if let Some(entry) = state.entries.get_mut(id) {
                entry.phase = phase;
                entry.failure.clone_from(&failure);
            }
        }
        self.changed.notify_all();
        Ok(state)
    }

    /// Select ready allocations in admission order within the batch
    /// bounds. The oldest ready allocation is always selected, so one
    /// larger than `batch_bytes` forms a batch of one.
    fn freeze(state: &mut State, limits: DurabilityLimits) -> Vec<AllocationId> {
        let mut ready: Vec<(u64, AllocationId, u64)> = state
            .entries
            .iter()
            .filter(|(_, entry)| entry.phase == Phase::Ready)
            .map(|(id, entry)| (entry.sequence, *id, entry.bytes))
            .collect();
        ready.sort_unstable();
        let mut batch = Vec::new();
        let mut batch_bytes = 0u64;
        for (_, id, bytes) in ready {
            if !batch.is_empty()
                && (batch.len() >= limits.batch_entries
                    || batch_bytes.saturating_add(bytes) > limits.batch_bytes)
            {
                break;
            }
            batch.push(id);
            batch_bytes = batch_bytes.saturating_add(bytes);
        }
        for id in &batch {
            if let Some(entry) = state.entries.get_mut(id) {
                entry.phase = Phase::Frozen;
            }
        }
        batch
    }

    /// One filesystem-wide synchronization covers every frozen file and
    /// directory entry on Linux. Elsewhere the frozen batch is not known
    /// to this function; the store refuses to open without `syncfs`.
    fn synchronize(&self) -> Result<(), StoreError> {
        #[cfg(target_os = "linux")]
        {
            rustix::fs::syncfs(File::open(&self.blob_root)?)
                .map_err(|error| StoreError::Io(error.into()))?;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Err(StoreError::NotSupported(
                "batched content durability requires syncfs".into(),
            ))
        }
    }

    #[cfg(test)]
    fn charged(&self) -> (usize, u64) {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        (state.entries.len(), state.charged_bytes)
    }
}
