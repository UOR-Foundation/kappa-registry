//! Bounded, resumable maintenance of a backend: physical inventory of its
//! content storage, repair of its derived indexes, and settlement of its
//! shared projections.
//!
//! Every operation takes a [`WorkLimit`] and an optional [`Continuation`]
//! and returns [`Progress`]: what the step did, the work it consumed on
//! every dimension (`kappa_types::work`), and the continuation of an
//! unfinished pass. A row or epoch count alone is not a bound: every entry
//! examined, byte read, decoded and allocated, hash, handle and candidate
//! is charged before the work is done, and a step stops at the first
//! dimension its limit would pass.
//!
//! The caller owns the continuation between steps. It carries everything
//! the backend needs to resume, and nothing it must keep alive on its own:
//! dropping a continuation cancels the pass, and the next step without one
//! starts a new pass. A continuation is bound to the store instance and
//! the operation that returned it ([`ContinuationScope`]); any other store
//! or operation refuses it before doing any work. Exhausting a step's
//! budget, on any dimension or its deadline, ends the step with its
//! outcome and its continuation; only a storage failure is an error.
//!
//! What a pass covers is each backend's to state for its own traversal: a
//! backend documents the coverage its continuation establishes under
//! concurrent writes, and decides every entry it acts on against
//! authoritative state at the time it acts, so an entry a pass misses is
//! found by a later pass and an entry a pass sees is never acted on from a
//! stale observation.
//!
//! Committed rows own representations; a representation that no committed
//! row owns (a preparation that never installed, a publication that
//! aborted, a deletion interrupted between its steps) is physical residue
//! that only the backend can recognize. Ownership is decided per entry
//! against committed state, never by index absence alone.

use std::any::Any;
use std::sync::Arc;

use kappa_types::error::StoreError;
use kappa_types::work::{Work, WorkLimit};

/// The maintenance operation a continuation resumes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaintenanceOperation {
    Reclaim,
    RepairIndexes,
    Settle,
}

/// The process-local identity of one open store instance.
///
/// The store holds one token and every continuation it returns holds a
/// clone; two tokens are the same instance exactly when they share the
/// allocation, so an identity is never reused while any holder of it is
/// alive. Continuations are process-local resume state, never serialized,
/// so no wire identity is needed.
#[derive(Clone, Default)]
pub struct StoreToken(Arc<()>);

impl StoreToken {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PartialEq for StoreToken {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for StoreToken {}

impl std::fmt::Debug for StoreToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StoreToken")
    }
}

/// Who may resume a continuation: one store instance and one operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContinuationScope {
    pub store: StoreToken,
    pub operation: MaintenanceOperation,
}

/// Where an unfinished pass resumes. Opaque: only the store and operation
/// that returned it read it.
pub struct Continuation {
    scope: ContinuationScope,
    state: Box<dyn Any + Send>,
}

impl Continuation {
    pub fn new<T: Any + Send>(scope: ContinuationScope, state: T) -> Self {
        Self {
            scope,
            state: Box::new(state),
        }
    }

    /// The resume state of a continuation of `scope`. A continuation of
    /// another store instance or operation is refused before its state is
    /// touched, and so is one whose state is not `T`.
    pub fn into_state<T: Any + Send>(self, scope: &ContinuationScope) -> Result<T, StoreError> {
        if self.scope != *scope {
            return Err(StoreError::Rejected(format!(
                "maintenance continuation of {:?} is not one of this store's {:?} passes",
                self.scope.operation, scope.operation
            )));
        }
        self.state.downcast::<T>().map(|state| *state).map_err(|_| {
            StoreError::Rejected("maintenance continuation state is not this pass's".into())
        })
    }
}

impl std::fmt::Debug for Continuation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Continuation")
            .field("operation", &self.scope.operation)
            .finish_non_exhaustive()
    }
}

/// What one bounded step did.
#[derive(Debug)]
#[must_use = "an unfinished pass resumes only from its continuation"]
pub struct Progress<T> {
    pub outcome: T,
    /// The work the step consumed.
    pub consumed: Work,
    /// Where the pass resumes; `None` when the pass is complete.
    pub continuation: Option<Continuation>,
}

impl<T> Progress<T> {
    /// Whether the pass reached its end.
    pub const fn complete(&self) -> bool {
        self.continuation.is_none()
    }
}

/// Outcome of one bounded inventory step.
///
/// Every entry examined is counted under exactly one of `files`, `owned`,
/// `protected`, `unrecognized`, `absent` or `failed`, so the figures
/// distinguish measured reclamation from logical ownership, from
/// protection by readers and preparations, from residue the backend cannot
/// classify, and from removals that failed and remain owed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reclamation {
    /// Representations deleted.
    pub files: u64,
    /// Bytes those representations held.
    pub bytes: u64,
    /// Entries a committed row (or a published generation) owns.
    pub owned: u64,
    /// Entries protected by a reader, an in-flight preparation, or a
    /// concurrent reclamation claim.
    pub protected: u64,
    /// Entries the backend's layout does not explain; left in place and
    /// reported.
    pub unrecognized: u64,
    /// Entries whose storage was already gone when examined (another entry
    /// of a representation whose deletion, decided at its first entry,
    /// removed every entry; a file unlinked meanwhile).
    pub absent: u64,
    /// Removals attempted that failed. The representation stays owed, its
    /// bytes stay charged, and a later step retries it.
    pub failed: u64,
}

impl Reclamation {
    /// Entries examined and left in place, for logs and summaries.
    #[must_use]
    pub const fn retained(&self) -> u64 {
        self.owned
            .saturating_add(self.protected)
            .saturating_add(self.unrecognized)
    }

    /// Add another step's figures to this one.
    pub const fn accumulate(&mut self, step: &Self) {
        self.files = self.files.saturating_add(step.files);
        self.bytes = self.bytes.saturating_add(step.bytes);
        self.owned = self.owned.saturating_add(step.owned);
        self.protected = self.protected.saturating_add(step.protected);
        self.unrecognized = self.unrecognized.saturating_add(step.unrecognized);
        self.absent = self.absent.saturating_add(step.absent);
        self.failed = self.failed.saturating_add(step.failed);
    }
}

/// Outcome of one bounded index-repair step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IndexRepair {
    /// The step found the derived indexes disagreeing with committed state.
    pub diverged: bool,
    /// Index entries the step rebuilt from committed state.
    pub entries: u64,
}

/// Outcome of one bounded settlement step.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Settlement {
    /// Published epochs whose effects the step settled into the shared
    /// projections.
    pub epochs: u64,
}

/// Bounded, resumable maintenance (see the module documentation).
pub trait MaintenanceStore: Send + Sync {
    /// Examine inventory entries from `from` (a new pass without one)
    /// within `limit`, reclaiming every representation no committed row
    /// owns and nothing protects.
    fn reclaim_unowned(
        &self,
        limit: &WorkLimit,
        from: Option<Continuation>,
    ) -> Result<Progress<Reclamation>, StoreError>;

    /// Rebuild the backend's derived reference indexes from committed state
    /// where they diverged from it, within `limit`, from `from`. A backend
    /// that recorded a divergence while writing rebuilds; one whose indexes
    /// cannot diverge from the state they are published with reports a
    /// complete pass with nothing rebuilt. Changes no epoch-committed state
    /// and publishes nothing.
    fn repair_indexes(
        &self,
        limit: &WorkLimit,
        from: Option<Continuation>,
    ) -> Result<Progress<IndexRepair>, StoreError>;

    /// Settle published epochs into the backend's shared projections
    /// (catalog, ownership, directory) within `limit`, from `from`. A
    /// backend whose projections are updated with the publication settles
    /// nothing and reports a complete pass.
    ///
    /// Publication never waits on a settlement held elsewhere. A backend
    /// that bounds the unsettled epochs of a namespace may, when an
    /// admission finds its namespace at that bound, run a bounded
    /// settlement of that namespace itself, through the same settlement
    /// this operation runs, taking each resource it needs without waiting
    /// and refusing the admission when one is held elsewhere or its
    /// allowance is spent. That bound is on work, not on storage latency.
    fn settle(
        &self,
        limit: &WorkLimit,
        from: Option<Continuation>,
    ) -> Result<Progress<Settlement>, StoreError>;
}
