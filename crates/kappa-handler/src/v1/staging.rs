//! Node-local admission over staged resources: how many resources may be
//! open at once across every namespace, and how many bytes they may hold
//! in total.
//!
//! The budget is a projection of committed resource heads. It is updated
//! from published ledgers: every epoch that sets or deletes a `_resource/`
//! head tag is observed where the publication happened, on the blocking
//! worker that published it, which a dropped request future does not
//! cancel. Open, stage, prepare, complete, discard and expiry therefore
//! all reach the projection through the same path, and no handler updates
//! it by hand. A handler only reserves before it executes: the slot or the
//! bytes a transition will need are charged while the execution runs. The
//! reservation is moved into the execution's work, which lives on the
//! blocking worker until the publication has been observed, so a dropped
//! request future cannot return the charge while its execution can still
//! publish; the sum of reservations and committed figures never admits past
//! the limit.
//!
//! Observations are ordered without holding the accounts lock across
//! storage reads. An observation is issued a sequence number under the
//! lock after its publication committed, resolves the heads it names from
//! committed state outside the lock (so what it reads is at least as new
//! as its own publication, and possibly newer), and records them under
//! the lock with that sequence; a figure recorded by a later sequence is
//! never replaced by an earlier one, and a head deletion is remembered
//! against earlier sequences still in flight. Every publication has its
//! own observation, issued after it committed, so for each resource the
//! observation of its latest publication reads the latest head and
//! carries a sequence above every observation issued before that
//! publication: the projection converges on committed state whichever
//! order the workers ran in. A rebuild is an observation of every
//! namespace's open and prepared heads, ordered the same way and recorded
//! one namespace at a time.
//!
//! A publication that could not be observed, an accounting invariant that
//! failed, or a publication whose outcome is unknown leaves the projection
//! unresolved: it admits nothing until a rebuild succeeds. An invalidation
//! is itself sequenced, and a rebuild resolves the projection only when its
//! own sequence is past the latest invalidation, so a rebuild cannot clear
//! an invalidation recorded for a publication it never scanned. Rebuilds
//! are attempted by later publications and, independently of any
//! foreground work, by the server's maintenance tick (`settle`), so
//! admission reopens once committed state is readable again. Critical
//! sections hold only counters and maps; the lock is never held across
//! storage I/O.
//!
//! Reservations and the committed-head scans are in `staging_admission`.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::ControlFlow;
use std::sync::{Arc, Mutex, MutexGuard};

use kappa_store::epoch::{EpochMutation, MutationOp};
use kappa_store::resource;
use kappa_store::traits::KappaStore;
use kappa_store::{
    Execution, NamespaceFilter, NamespaceRef, PageRequest, ResourceHead, ResourcePhase, StoreError,
};

use crate::error::HandlerError;
use crate::execute::Outcome;

#[path = "staging_admission.rs"]
mod admission;
pub use admission::{
    ByteAdmission, OpenAdmission, scan_namespace_resources, scan_resources, staging_budget,
};

#[cfg(test)]
#[path = "staging_tests.rs"]
mod tests;

/// Execution work as `execute` runs it.
pub type Work<T> = dyn FnMut(&mut dyn Execution) -> Result<Outcome<T>, HandlerError> + Send;

/// A resource: the namespace identity and the resource id.
type Key = ([u8; 16], String);

/// The recorded figure of one resource: the observation that recorded it
/// and the bytes its head held.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Figure {
    seq: u64,
    bytes: u64,
}

#[derive(Default)]
struct Accounts {
    /// Open and prepared resources with the bytes their committed head
    /// holds, by the observation that recorded them.
    committed: BTreeMap<Key, Figure>,
    committed_bytes: u64,
    /// Opens reserved by executions that have not published yet.
    pending_open: usize,
    /// Bytes reserved by executions that have not published yet.
    pending_bytes: u64,
    /// Next observation sequence.
    next_seq: u64,
    /// Observations issued and not yet recorded.
    inflight: BTreeSet<u64>,
    /// Resources whose head deletion was recorded, by the observation
    /// that recorded it; kept while an earlier observation is in flight,
    /// so a stale head it resolved cannot resurrect the resource.
    ended: BTreeMap<Key, u64>,
    /// The projection may undercount: a publication was not observed, an
    /// invariant failed, or a publication's outcome is unknown. Holds the
    /// sequence at which the latest invalidation was recorded; nothing is
    /// admitted until a rebuild issued after it succeeds.
    unresolved: Option<u64>,
}

/// Deletion records kept at most while earlier observations are in
/// flight. Past this many, one stalled observation is holding the records
/// of every later deletion: the records are dropped and the projection is
/// unresolved until a rebuild, which reads committed state and needs none
/// of them.
const MAX_ENDED: usize = 65_536;

impl Accounts {
    /// Drop the deletion records no in-flight observation can contradict.
    fn prune(&mut self) {
        let floor = self.inflight.first().copied();
        self.ended
            .retain(|_, recorded| floor.is_some_and(|floor| floor < *recorded));
    }

    /// Bound the deletion records (see [`MAX_ENDED`]).
    fn bound_ended(&mut self) {
        if self.ended.len() > MAX_ENDED {
            self.ended.clear();
            self.invalidate("deletion records exceeded their bound");
        }
    }

    /// The next observation sequence. Exhaustion invalidates: no further
    /// observation can be ordered.
    fn next(&mut self) -> Option<u64> {
        let seq = self.next_seq;
        let next = seq.checked_add(1)?;
        self.next_seq = next;
        Some(seq)
    }

    fn invalidate(&mut self, reason: &str) {
        if self.unresolved.is_none() {
            tracing::error!(
                reason,
                "staging budget unresolved; admission refused until rebuilt"
            );
        }
        // The invalidation takes the sequence a rebuild must pass; when
        // sequences are exhausted it is unreachable and the projection
        // stays closed.
        self.unresolved = Some(self.next().unwrap_or(u64::MAX));
    }
}

/// The node's staging budget.
pub struct StagingBudget {
    max_open: usize,
    max_bytes: u64,
    accounts: Mutex<Accounts>,
}

const fn capacity(message: String) -> HandlerError {
    HandlerError::Store(StoreError::CapacityExceeded(message))
}

/// The resource id a ledger mutation names when it sets or deletes a
/// resource head tag.
fn head_id(mutation: &EpochMutation) -> Option<&str> {
    if !matches!(mutation.op, MutationOp::TagSet | MutationOp::TagDelete) {
        return None;
    }
    let id = mutation.context.as_deref()?.strip_prefix("_resource/")?;
    (!id.contains('/')).then_some(id)
}

/// An issued observation. Dropped unrecorded (a failed resolution, a
/// panic), it leaves the in-flight set so deletion records can be pruned.
struct Observation<'a> {
    budget: &'a StagingBudget,
    seq: u64,
}

impl Drop for Observation<'_> {
    fn drop(&mut self) {
        let mut accounts = self.budget.lock();
        let previous_floor = accounts.inflight.first().copied();
        accounts.inflight.remove(&self.seq);
        // Only advancing the oldest observation can make deletion records
        // obsolete. Later completions must not repeatedly scan every record
        // retained by a stalled observer while holding the accounts lock.
        if accounts.inflight.first().copied() != previous_floor {
            accounts.prune();
        }
    }
}

impl StagingBudget {
    /// A budget of `max_open` resources and `max_bytes` staged bytes. Zero
    /// disables the respective limit.
    pub fn new(max_open: usize, max_bytes: u64) -> Self {
        Self {
            max_open,
            max_bytes,
            accounts: Mutex::new(Accounts::default()),
        }
    }

    /// A panic while the accounts were held may have left them partially
    /// updated: the projection is unresolved until rebuilt.
    fn lock(&self) -> MutexGuard<'_, Accounts> {
        self.accounts.lock().unwrap_or_else(|poisoned| {
            let mut accounts = poisoned.into_inner();
            accounts.invalidate("accounts lock poisoned");
            accounts
        })
    }

    /// Issue an observation. Called after the publication it observes has
    /// committed, so what it resolves is at least as new as that
    /// publication. Sequence exhaustion invalidates the projection and
    /// issues the terminal sequence, which records nothing newer.
    fn issue(&self) -> Observation<'_> {
        let mut accounts = self.lock();
        let seq = accounts.next().unwrap_or_else(|| {
            accounts.invalidate("observation sequence exhausted");
            u64::MAX
        });
        accounts.inflight.insert(seq);
        drop(accounts);
        Observation { budget: self, seq }
    }

    /// Mark the projection unresolved: it admits nothing until a rebuild
    /// issued after this succeeds.
    pub fn invalidate(&self, reason: &str) {
        self.lock().invalidate(reason);
    }

    /// Whether the projection is unresolved.
    pub fn unresolved(&self) -> bool {
        self.lock().unresolved.is_some()
    }

    /// Replace the projection with every open and prepared head committed
    /// in `store`: an observation of the whole store, scanned outside the
    /// lock one namespace at a time and recorded under one short hold per
    /// namespace, that replaces every figure recorded by an earlier
    /// observation and leaves later ones. Returns the number of resources
    /// found. A successful rebuild resolves the projection unless an
    /// invalidation was recorded after the rebuild was issued, for a
    /// publication the scan may not have seen; that invalidation waits for
    /// the next rebuild. A failed rebuild leaves the projection unresolved.
    pub fn rebuild<S: KappaStore + ?Sized>(&self, store: &S) -> Result<usize, StoreError> {
        let observation = self.issue();
        let seq = observation.seq;
        let mut count = 0usize;
        let mut request = PageRequest::first(256);
        let scanned = loop {
            let page = match store.namespace_list(&NamespaceFilter::default(), &request) {
                Ok(page) => page,
                Err(error) => break Err(error),
            };
            let mut failed = None;
            for info in &page.items {
                let mut found: Vec<(Key, u64)> = Vec::new();
                let scanned = scan_namespace_resources(store, &info.ns, |id, head| {
                    if matches!(head.phase, ResourcePhase::Open | ResourcePhase::Prepared) {
                        found.push(((*info.ns.id(), id.to_string()), head.total_bytes));
                    }
                    Ok(ControlFlow::Continue(()))
                });
                if let Err(error) = scanned {
                    failed = Some(error);
                    break;
                }
                count = count.saturating_add(found.len());
                let mut accounts = self.lock();
                for (key, bytes) in found {
                    Self::record_found(&mut accounts, seq, key, bytes);
                }
            }
            if let Some(error) = failed {
                break Err(error);
            }
            match page.next_after {
                Some(next) if request.after.as_ref() != Some(&next) => request.after = Some(next),
                Some(_) => {
                    break Err(StoreError::Internal(
                        "namespace traversal did not advance".into(),
                    ));
                }
                None => break Ok(()),
            }
        };
        let mut accounts = self.lock();
        if let Err(error) = scanned {
            accounts.invalidate("rebuild scan failed");
            return Err(error);
        }
        Self::finish_scan(&mut accounts, seq)?;
        drop(accounts);
        Ok(count)
    }

    /// Record one head a scan issued at `seq` found: a figure recorded by
    /// a later observation stays, a deletion recorded after `seq` stands.
    /// The total moves with the figure, so `committed_bytes` equals the sum
    /// of `committed` at every point of a scan and an observation applied
    /// between two namespaces of the scan subtracts exactly what was added.
    fn record_found(accounts: &mut Accounts, seq: u64, key: Key, bytes: u64) {
        let ended_after = accounts.ended.get(&key).is_some_and(|ended| *ended > seq);
        let newer = accounts
            .committed
            .get(&key)
            .is_some_and(|figure| figure.seq > seq);
        if ended_after || newer {
            return;
        }
        let previous = accounts
            .committed
            .insert(key, Figure { seq, bytes })
            .map_or(0, |figure| figure.bytes);
        match accounts
            .committed_bytes
            .checked_sub(previous)
            .and_then(|total| total.checked_add(bytes))
        {
            Some(total) => accounts.committed_bytes = total,
            None => accounts.invalidate("staged bytes accounting invariant failed during rebuild"),
        }
    }

    /// Finish a scan issued at `seq`: every figure the scan did not
    /// refresh and no later observation recorded is gone, the total is
    /// recomputed, and the projection resolves unless an invalidation was
    /// recorded after `seq`.
    fn finish_scan(accounts: &mut Accounts, seq: u64) -> Result<(), StoreError> {
        accounts.committed.retain(|_, figure| figure.seq >= seq);
        let total = accounts
            .committed
            .values()
            .try_fold(0u64, |total, figure| total.checked_add(figure.bytes));
        let Some(total) = total else {
            accounts.invalidate("staged bytes overflow");
            return Err(StoreError::Internal("staged bytes overflow".into()));
        };
        accounts.committed_bytes = total;
        // Strictly after: the invalidation consumed its own sequence, and
        // the terminal sequence of an exhausted budget is never exceeded.
        if accounts.unresolved.is_some_and(|recorded| recorded < seq) {
            accounts.unresolved = None;
        }
        Ok(())
    }

    /// Install the result of a whole scan issued at `seq` in one hold.
    #[cfg(test)]
    fn record_scan(
        accounts: &mut Accounts,
        seq: u64,
        found: Vec<(Key, u64)>,
    ) -> Result<usize, StoreError> {
        let count = found.len();
        for (key, bytes) in found {
            Self::record_found(accounts, seq, key, bytes);
        }
        Self::finish_scan(accounts, seq)?;
        Ok(count)
    }

    /// Rebuild the projection when it is unresolved. Returns the number of
    /// resources found by a rebuild, or `None` when none was needed. The
    /// server's maintenance tick calls this, so recovery does not depend
    /// on a foreground publication.
    ///
    /// # Errors
    ///
    /// The rebuild failed; the projection stays unresolved.
    pub fn settle<S: KappaStore + ?Sized>(&self, store: &S) -> Result<Option<usize>, StoreError> {
        if !self.unresolved() {
            return Ok(None);
        }
        self.rebuild(store).map(Some)
    }

    /// Refuse admission while the projection is unresolved.
    fn resolved(accounts: &Accounts) -> Result<(), HandlerError> {
        if accounts.unresolved.is_some() {
            return Err(capacity(
                "staging budget unresolved until its projection is rebuilt".into(),
            ));
        }
        Ok(())
    }

    /// Reserve one resource open for an execution about to run. The
    /// reservation is owned so the execution's work can hold it.
    pub fn admit_open(self: &Arc<Self>) -> Result<OpenAdmission, HandlerError> {
        let mut accounts = self.lock();
        Self::resolved(&accounts)?;
        let open = accounts.committed.len() + accounts.pending_open;
        if self.max_open > 0 && open >= self.max_open {
            return Err(capacity(format!(
                "staged resource limit of {} reached",
                self.max_open
            )));
        }
        accounts.pending_open += 1;
        drop(accounts);
        Ok(OpenAdmission {
            budget: Arc::clone(self),
        })
    }

    /// Reserve `len` staged bytes for an execution about to run. The
    /// reservation is owned so the execution's work can hold it.
    pub fn admit_bytes(self: &Arc<Self>, len: u64) -> Result<ByteAdmission, HandlerError> {
        let mut accounts = self.lock();
        Self::resolved(&accounts)?;
        let staged = accounts
            .committed_bytes
            .checked_add(accounts.pending_bytes)
            .and_then(|staged| staged.checked_add(len))
            .ok_or_else(|| capacity("staged bytes overflow".into()))?;
        if self.max_bytes > 0 && staged > self.max_bytes {
            return Err(capacity(format!(
                "staging budget of {} bytes exhausted",
                self.max_bytes
            )));
        }
        accounts.pending_bytes += len;
        drop(accounts);
        Ok(ByteAdmission {
            budget: Arc::clone(self),
            len,
        })
    }

    /// Project a published ledger of `ns`: every resource head it set is
    /// resolved from committed state and recorded (open and prepared heads
    /// stage their total; completed and discarded heads stage nothing);
    /// every head it deleted is released. Runs where the publication ran,
    /// after it committed, as one ordered observation.
    pub fn observe_published<S: KappaStore + ?Sized>(
        &self,
        store: &S,
        ns: &NamespaceRef,
        mutations: &[EpochMutation],
    ) -> Result<(), StoreError> {
        let ids: Vec<(&str, bool)> = mutations
            .iter()
            .filter_map(|mutation| {
                head_id(mutation).map(|id| (id, mutation.op == MutationOp::TagDelete))
            })
            .collect();
        if ids.is_empty() {
            return Ok(());
        }
        let observation = self.issue();
        let mut heads: Vec<(&str, Option<ResourceHead>)> = Vec::with_capacity(ids.len());
        for (id, deleted) in ids {
            let head = if deleted {
                None
            } else {
                resource::resolve(store, ns, id)?.map(|resource| resource.head)
            };
            heads.push((id, head));
        }
        let mut accounts = self.lock();
        for (id, head) in heads {
            Self::apply(&mut accounts, observation.seq, ns, id, head.as_ref());
        }
        drop(accounts);
        drop(observation);
        Ok(())
    }

    /// Follow one publication of `ns` whose ledger is `mutations`; `None`
    /// when the ledger could not be read. The publication has committed,
    /// so a failure cannot be reported to its writer: a ledger that cannot
    /// be read or observed leaves the projection unresolved and a rebuild
    /// is attempted here; while it has not succeeded, nothing is admitted
    /// and every later publication and maintenance tick retries it.
    pub fn follow<S: KappaStore + ?Sized>(
        &self,
        store: &S,
        ns: &NamespaceRef,
        mutations: Option<&[EpochMutation]>,
    ) {
        let observed = mutations.map_or_else(
            || Err(StoreError::Internal("published ledger unreadable".into())),
            |mutations| self.observe_published(store, ns, mutations),
        );
        if let Err(error) = observed {
            tracing::error!(%error, namespace = %ns, "staging budget could not observe a publication");
            self.invalidate("publication unobserved");
        }
        if let Err(error) = self.settle(store) {
            tracing::error!(%error, "staging budget rebuild failed; admission refused until it succeeds");
        }
    }

    /// Record the committed head of resource `id` of `ns` as observation
    /// `seq`; `None` or a head past staging removes it. An observation
    /// earlier than the one that recorded the resource's figure, or than
    /// the one that recorded its deletion, is stale and ignored.
    fn apply(
        accounts: &mut Accounts,
        seq: u64,
        ns: &NamespaceRef,
        id: &str,
        head: Option<&ResourceHead>,
    ) {
        let key = (*ns.id(), id.to_string());
        if accounts.ended.get(&key).is_some_and(|ended| seq < *ended)
            || accounts
                .committed
                .get(&key)
                .is_some_and(|figure| seq < figure.seq)
        {
            return;
        }
        let staged = head.and_then(|head| {
            matches!(head.phase, ResourcePhase::Open | ResourcePhase::Prepared)
                .then_some(head.total_bytes)
        });
        let previous = if let Some(bytes) = staged {
            accounts.committed.insert(key, Figure { seq, bytes })
        } else {
            let previous = accounts.committed.remove(&key);
            let ended = accounts.ended.entry(key).or_insert(seq);
            *ended = (*ended).max(seq);
            accounts.bound_ended();
            previous
        };
        let previous = previous.map_or(0, |figure| figure.bytes);
        let total = accounts
            .committed_bytes
            .checked_sub(previous)
            .and_then(|bytes| bytes.checked_add(staged.unwrap_or(0)));
        match total {
            Some(total) => accounts.committed_bytes = total,
            None => accounts.invalidate("staged bytes accounting invariant failed"),
        }
    }

    /// Open and prepared resources the projection holds.
    pub fn open_count(&self) -> usize {
        self.lock().committed.len()
    }

    /// Bytes the open and prepared resources hold.
    pub fn staged_bytes(&self) -> u64 {
        self.lock().committed_bytes
    }

    fn release_pending_open(&self) {
        let mut accounts = self.lock();
        match accounts.pending_open.checked_sub(1) {
            Some(pending) => accounts.pending_open = pending,
            None => accounts.invalidate("released an open that was never reserved"),
        }
    }

    fn release_pending_bytes(&self, len: u64) {
        let mut accounts = self.lock();
        match accounts.pending_bytes.checked_sub(len) {
            Some(pending) => accounts.pending_bytes = pending,
            None => accounts.invalidate("released bytes that were never reserved"),
        }
    }
}
