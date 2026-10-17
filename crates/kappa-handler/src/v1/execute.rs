//! Operation-owned write execution for HTTP handlers.
//!
//! Every handler mutation runs as one execution: private writes, then one
//! publication that installs the state, its ledger, and the signed epoch
//! together. A namespace first written by the request is created inside the
//! same execution, so a failed write leaves no empty namespace behind.
//!
//! A request carrying `Idempotency-Key` runs as an operation. Its result is
//! persisted in a receipt committed by the epoch ledger; a retry with the
//! same key and the same request replays that authenticated result instead
//! of executing again, and the same key with a different request conflicts.
//!
//! The types an execution is described with are in `execute_types`.

use std::time::{Duration, Instant};

use topcoat::context::{Cx, try_request_context};

use kappa_store::canonical::from_canonical;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::{Execution, OperationAdmission, StoreError};

use crate::clock::Clock;
use crate::error::HandlerError;
use crate::event_feed::PublicationFeed;

#[path = "execute_types.rs"]
mod types;
pub use types::{Committed, OperationResult, Outcome, WriteTarget, write_target};

/// Bound on one write execution, enforced at the last point before
/// publication becomes visible. A request's own deadline, when nearer,
/// bounds it further (`request_deadline`).
pub const WRITE_DEADLINE: Duration = Duration::from_secs(30);

/// The monotonic deadline of the whole request.
///
/// Set by the server's timeout layer. Every phase of the request
/// (preparation, each execution)
/// is bounded by it, so a request that spans several executions is not
/// granted a fresh allowance at each.
#[derive(Clone, Copy, Debug)]
pub struct RequestDeadline(pub Instant);

/// The deadline of one phase of the request: `bound` from now, or the
/// request's remaining time when that is less.
pub fn request_deadline(cx: &Cx, bound: Duration) -> Instant {
    let phase = Instant::now() + bound;
    try_request_context::<RequestDeadline>(cx).map_or(phase, |request| request.0.min(phase))
}

/// The caller waits this much longer than the execution deadline, so a
/// publication that passed its deadline check completes and is reported
/// rather than raced by the caller's own timeout.
const PUBLICATION_GRACE: Duration = Duration::from_secs(5);

/// Request header naming an idempotent operation.
pub const IDEMPOTENCY_KEY: &str = "idempotency-key";

/// Response header marking a result replayed from a committed operation.
pub const IDEMPOTENT_REPLAYED: &str = "idempotent-replayed";

/// Response header carrying the epoch that published the write.
pub const KAPPA_EPOCH: &str = "x-kappa-epoch";

/// Response header carrying that epoch's signed root identity.
pub const KAPPA_EPOCH_ROOT: &str = "x-kappa-epoch-root";

const MAX_IDEMPOTENCY_KEY: usize = 255;

struct Operation {
    identity: [u8; 32],
    request: Kappa,
}

/// An operation together with the codec of the result its receipt holds.
struct Bound<T> {
    operation: Operation,
    encode: fn(&T) -> Vec<u8>,
    decode: fn(&[u8]) -> Result<T, HandlerError>,
}

/// Operation coordinates for an idempotent request. The identity binds the
/// key to the caller, so two callers choosing the same key never collide;
/// the request identity binds method, target, and payload, so reusing a key
/// for a different request conflicts instead of replaying.
fn operation(cx: &Cx, payload: &[u8]) -> Result<Option<Operation>, HandlerError> {
    let Some(parts) = try_request_context::<http::request::Parts>(cx) else {
        return Ok(None);
    };
    let Some(key) = parts.headers.get(IDEMPOTENCY_KEY) else {
        return Ok(None);
    };
    let key = key.as_bytes();
    if key.is_empty()
        || key.len() > MAX_IDEMPOTENCY_KEY
        || !key
            .iter()
            .all(|byte| byte.is_ascii_graphic() || *byte == b' ')
    {
        return Err(HandlerError::bad_request(format!(
            "{IDEMPOTENCY_KEY} must be 1 to {MAX_IDEMPOTENCY_KEY} visible ASCII characters"
        )));
    }
    let caller = crate::store::caller_anchor(cx).map(|anchor| anchor.key_bytes());
    let mut identity_input = b"kappa-operation\0".to_vec();
    identity_input.extend_from_slice(caller.as_deref().unwrap_or_default());
    identity_input.push(0);
    identity_input.extend_from_slice(key);
    let identity = kappa_store::kappa::sha256_raw(&identity_input);

    let target = parts
        .uri
        .path_and_query()
        .map_or_else(|| parts.uri.path(), http::uri::PathAndQuery::as_str);
    let mut request_input = b"kappa-request\0".to_vec();
    request_input.extend_from_slice(parts.method.as_str().as_bytes());
    request_input.push(0);
    request_input.extend_from_slice(target.as_bytes());
    request_input.push(0);
    request_input.extend_from_slice(&kappa_store::kappa::sha256_raw(payload));
    Ok(Some(Operation {
        identity,
        request: Kappa::sha256(&request_input),
    }))
}

enum Attempt<T> {
    Done(Committed<T>),
    /// The namespace pending creation was created concurrently; run again
    /// against it.
    Resolved(NamespaceRef),
}

/// Run `work` in one execution against `target` and publish or discard it
/// as the work decides.
///
/// `work` runs at most once. A namespace pending creation that another
/// request created first is resolved, and the execution reopened against
/// it, before `work` is called; prepared content a handler hands to `work`
/// is therefore consumed by exactly one execution.
///
/// `payload` is the request content the operation identity binds; handlers
/// pass the body they read, or an empty slice.
///
/// # Errors
///
/// Store, clock, and work failures; `Timeout` when the execution does not
/// finish in time. A timed-out idempotent request is safe to retry with the
/// same key.
pub async fn execute<T, F>(
    cx: &Cx,
    target: WriteTarget,
    payload: &[u8],
    work: F,
) -> Result<Committed<T>, HandlerError>
where
    T: OperationResult + Send + 'static,
    F: FnMut(&mut dyn Execution) -> Result<Outcome<T>, HandlerError> + Send + 'static,
{
    let bound = operation(cx, payload)?.map(|operation| Bound {
        operation,
        encode: T::encode,
        decode: T::decode,
    });
    run(cx, target, bound, work).await
}

/// Run `work` as one internal phase of a request that spans several
/// executions (a resource preparation before its completion), publishing
/// or discarding as the work decides.
///
/// The phase carries no operation identity: the request's
/// `Idempotency-Key` binds the execution that publishes the request's
/// result, and a phase committed under the same identity would make that
/// execution conflict with its own request. A retry of the request
/// therefore runs the phase again, so a phase must converge on committed
/// state (`resource::prepare` returns the generation already frozen for
/// the same request, and reports that nothing was written).
///
/// # Errors
///
/// As [`execute`].
pub async fn execute_phase<T, F>(
    cx: &Cx,
    target: WriteTarget,
    work: F,
) -> Result<Committed<T>, HandlerError>
where
    T: Send + 'static,
    F: FnMut(&mut dyn Execution) -> Result<Outcome<T>, HandlerError> + Send + 'static,
{
    run(cx, target, None, work).await
}

async fn run<T, F>(
    cx: &Cx,
    target: WriteTarget,
    bound: Option<Bound<T>>,
    work: F,
) -> Result<Committed<T>, HandlerError>
where
    T: Send + 'static,
    F: FnMut(&mut dyn Execution) -> Result<Outcome<T>, HandlerError> + Send + 'static,
{
    let store = crate::store::store(cx);
    // The store issues the execution's time from this clock after acquiring
    // its writer; a time issued here, before the writer, could publish after
    // a later one.
    let clock = crate::store::service::<std::sync::Arc<dyn Clock>>(cx).clone();
    let budget =
        crate::store::try_service::<std::sync::Arc<crate::staging::StagingBudget>>(cx).cloned();
    let deadline = request_deadline(cx, WRITE_DEADLINE);
    let (committed, mutation_count) = crate::blocking::with_deadline::<_, HandlerError, _>(
        deadline.saturating_duration_since(Instant::now()) + PUBLICATION_GRACE,
        move || {
            let mut work = work;
            let mut target = target;
            let committed = loop {
                let attempted = attempt(
                    &*store,
                    &target,
                    bound.as_ref(),
                    &*clock,
                    deadline,
                    &mut work,
                );
                // A publication whose outcome is unknown may have
                // committed a staging transition nobody will observe: the
                // budget is unresolved until it is rebuilt from committed
                // state, before the work's reservations are returned.
                if let (
                    Err(HandlerError::Store(
                        StoreError::PublicationIndeterminate { .. }
                        | StoreError::PublicationRecoveryRequired { .. },
                    )),
                    Some(budget),
                ) = (&attempted, &budget)
                {
                    budget.invalidate("publication outcome unknown");
                }
                match attempted? {
                    Attempt::Done(committed) => break committed,
                    Attempt::Resolved(namespace) => target = WriteTarget::existing(namespace),
                }
            };
            let mutation_count = match (&committed.root, committed.replayed) {
                (Some(root), false) => {
                    let mutations = committed_ledger(&*store, &committed.namespace, root)
                        .inspect_err(|error| {
                            tracing::error!(
                                %error,
                                namespace = %committed.namespace,
                                %root,
                                "published epoch ledger unreadable"
                            );
                        })
                        .ok();
                    // The publication has committed; the budget projection
                    // follows it here, on the worker a dropped caller does
                    // not cancel, so every head transition reaches it.
                    if let Some(budget) = &budget {
                        budget.follow(&*store, &committed.namespace, mutations.as_deref());
                    }
                    // An unreadable ledger still notifies: subscribers read
                    // history themselves and report what they cannot read.
                    Some(mutations.map_or(0, |mutations| mutations.len() as u64))
                }
                _ => None,
            };
            // The work, and every reservation it holds, is released only
            // after the publication was observed.
            drop(work);
            Ok((committed, mutation_count))
        },
    )
    .await?;
    if let (Some(count), Some(epoch), Some(root), Some(feed)) = (
        mutation_count,
        committed.epoch,
        &committed.root,
        crate::store::try_service::<std::sync::Arc<PublicationFeed>>(cx),
    ) {
        feed.publish(&committed.namespace, epoch, root, count);
    }
    Ok(committed)
}

/// The ledger of the epoch whose signed root is `root`, read back from
/// committed state.
///
/// For a just-published epoch the publication has already committed; a
/// failure here cannot undo it, so callers log it rather than report a
/// failed write. Subscribers read the same ledger from history
/// (`event_stream`), and the staging budget rebuilds from committed heads
/// (`StagingBudget::follow`).
///
/// # Errors
///
/// The epoch or its ledger cannot be read or does not decode.
pub fn committed_ledger<S: kappa_store::KappaStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    root: &Kappa,
) -> Result<Vec<kappa_store::EpochMutation>, StoreError> {
    let root = store.epoch_get(root)?;
    if root.namespace_id() != namespace.id() {
        return Err(StoreError::Conflict(
            "epoch root belongs to another namespace".into(),
        ));
    }
    // The ledger is a record of the namespace, read from it: a
    // just-published epoch is current there before any projection
    // settles.
    let ledger = store.blob_get_verified_in(namespace, root.ledger_root())?;
    from_canonical::<Vec<kappa_store::EpochMutation>>(&ledger).map_err(StoreError::from)
}

fn attempt<T, F>(
    store: &dyn kappa_store::KappaStore,
    target: &WriteTarget,
    bound: Option<&Bound<T>>,
    clock: &dyn Clock,
    deadline: Instant,
    work: &mut F,
) -> Result<Attempt<T>, HandlerError>
where
    F: FnMut(&mut dyn Execution) -> Result<Outcome<T>, HandlerError>,
{
    let namespace = target.namespace();
    let mut execution = match bound {
        Some(bound) => match store.begin_operation(
            namespace,
            bound.operation.identity,
            bound.operation.request.clone(),
            clock,
        )? {
            OperationAdmission::Execute(execution) => execution,
            OperationAdmission::Replay { epoch, receipt } => {
                return Ok(Attempt::Done(Committed {
                    value: (bound.decode)(receipt.result())?,
                    namespace: namespace.clone(),
                    epoch: Some(epoch.epoch_number()),
                    root: Some(epoch.kappa().clone()),
                    replayed: true,
                }));
            }
        },
        None => store.begin_execution(namespace, clock)?,
    };
    execution.set_deadline(deadline);
    if let Some(creation) = &target.creation {
        match execution.namespace_create(creation.owner.as_ref(), creation.protocol.as_ref()) {
            Ok(()) => {}
            Err(StoreError::Conflict(_) | StoreError::AlreadyExists(_)) => {
                // Release the writer before resolving the concurrent creator.
                execution.abort()?;
                let resolved = store
                    .namespace_resolve(namespace.display_name(), creation.protocol.as_ref())?;
                return Ok(Attempt::Resolved(resolved));
            }
            Err(error) => return Err(error.into()),
        }
    }
    match work(&mut *execution)? {
        Outcome::Publish(value) => {
            let published = match bound {
                Some(bound) => execution.publish_result((bound.encode)(&value))?,
                None => execution.publish()?,
            };
            Ok(Attempt::Done(Committed {
                value,
                namespace: namespace.clone(),
                epoch: Some(published.epoch_number),
                root: Some(published.root),
                replayed: false,
            }))
        }
        Outcome::Discard(value) => {
            execution.abort()?;
            Ok(Attempt::Done(Committed {
                value,
                namespace: namespace.clone(),
                epoch: None,
                root: None,
                replayed: false,
            }))
        }
    }
}
