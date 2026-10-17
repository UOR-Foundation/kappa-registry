//! Namespace lifecycle policy: object expiry and abandonment of incomplete
//! multipart uploads, as a bucket's `lifecycle` configuration directs.
//!
//! Every effect is an epoch-committed transition through an execution of
//! the namespace. Incomplete uploads are staged resources
//! (`kappa_store::resource`): those created before the configured age are
//! discarded through the same guarded transition expiry uses, and the
//! staging budget follows the publication's ledger as it follows every
//! other, so each discarded head releases its charge.

use std::ops::ControlFlow;
use std::sync::Arc;
use std::time::Duration;

use kappa_handler::StagingBudget;
use kappa_store::clock::ClockMs;
use kappa_store::namespace::NamespaceRef;
use kappa_store::resource;
use kappa_store::time::Clock;
use kappa_store::traits::KappaStore;
use kappa_store::{
    NamespaceFilter, PageRequest, ResourcePhase, StoreError, absent, publish_if_changed,
};

const DAY_MS: u64 = 86_400_000;

/// Uploads abandoned per namespace per pass.
const ABANDON_BATCH: usize = 256;

#[derive(Debug, Clone, serde::Deserialize)]
struct LifecycleConfig {
    #[serde(default)]
    expiration_days: Option<u64>,
    #[serde(default)]
    abort_incomplete_days: Option<u64>,
}

pub async fn run_lifecycle_loop<S>(
    store: Arc<S>,
    clock: Arc<dyn Clock>,
    budget: Arc<StagingBudget>,
    interval_secs: u64,
) where
    S: KappaStore + 'static + ?Sized,
{
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    loop {
        interval.tick().await;
        let s = store.clone();
        let clock = clock.clone();
        let b = budget.clone();
        match tokio::task::spawn_blocking(move || evaluate_lifecycles(&*s, &*clock, &b)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(%error, "lifecycle evaluation failed"),
            Err(error) => tracing::error!(%error, "lifecycle evaluation task failed"),
        }
    }
}

/// One lifecycle pass over every namespace.
///
/// Each namespace is evaluated independently: all of its expirations
/// publish in one execution, its abandoned uploads in another, and a
/// namespace whose evaluation fails is logged without affecting the
/// others. A pass that changes nothing publishes no epoch. Only a failure
/// to enumerate namespaces fails the pass.
///
/// Expiry is decided against one time issued at the start of the pass; each
/// publishing execution issues its own time under the store's writer.
pub fn evaluate_lifecycles<S: KappaStore + ?Sized>(
    store: &S,
    clock: &dyn Clock,
    budget: &StagingBudget,
) -> Result<(), StoreError> {
    let now = clock.now()?;
    let mut request = PageRequest::first(1024);
    loop {
        let namespaces = store.namespace_list(&NamespaceFilter::default(), &request)?;
        for ns_info in &namespaces.items {
            if let Err(error) = evaluate_namespace(store, &ns_info.ns, now, clock, budget) {
                tracing::warn!(
                    ns = ns_info.ns.display_name(),
                    %error,
                    "lifecycle: namespace evaluation failed"
                );
            }
        }
        let Some(after) = namespaces.next_after else {
            break;
        };
        if request
            .after
            .as_ref()
            .is_some_and(|previous| after <= *previous)
        {
            return Err(StoreError::Internal(
                "namespace cursor did not advance".into(),
            ));
        }
        request.after = Some(after);
    }
    Ok(())
}

fn evaluate_namespace<S: KappaStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    now: ClockMs,
    clock: &dyn Clock,
    budget: &StagingBudget,
) -> Result<(), StoreError> {
    let Some(config_bytes) = absent(store.namespace_get_meta(ns, "lifecycle"))? else {
        return Ok(());
    };
    let config: LifecycleConfig = match serde_json::from_slice(&config_bytes) {
        Ok(config) => config,
        Err(error) => {
            tracing::warn!(
                ns = ns.display_name(),
                %error,
                "lifecycle config is not valid JSON, skipping"
            );
            return Ok(());
        }
    };
    if let Some(days) = config.expiration_days {
        let threshold_ms = days.checked_mul(DAY_MS).ok_or_else(|| {
            StoreError::Rejected("lifecycle expiration duration exceeds range".into())
        })?;
        expire_objects(store, ns, now, clock, threshold_ms)?;
    }
    if let Some(abort_days) = config.abort_incomplete_days {
        let age_ms = abort_days
            .checked_mul(DAY_MS)
            .and_then(|age| i64::try_from(age).ok())
            .ok_or_else(|| {
                StoreError::Rejected("lifecycle upload duration exceeds range".into())
            })?;
        let cutoff = now
            .as_i64()
            .checked_sub(age_ms)
            .ok_or_else(|| StoreError::Rejected("lifecycle cutoff exceeds range".into()))?;
        let abandoned = abandon_uploads(store, ns, clock, budget, cutoff)?;
        if abandoned > 0 {
            tracing::info!(
                ns = ns.display_name(),
                count = abandoned,
                "lifecycle: abandoned incomplete uploads"
            );
        }
    }
    Ok(())
}

/// Delete every expired object tag of `ns` in one execution. Returns the
/// published epoch number, or `None` when nothing expired.
fn expire_objects<S: KappaStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    now: ClockMs,
    clock: &dyn Clock,
    threshold_ms: u64,
) -> Result<Option<u64>, StoreError> {
    let expired = expired_tags(store, ns, now.physical_ms(), threshold_ms)?;
    if expired.is_empty() {
        return Ok(None);
    }
    let published = publish_if_changed(store, ns, clock, |execution| {
        let mut changed = false;
        for name in &expired {
            // Deleted since enumeration: absence is skipped, never latched.
            if execution.tag_get_raw(name)?.is_some() {
                execution.tag_delete(name)?;
                changed = true;
            }
        }
        Ok(changed)
    })?
    .map(|published| published.epoch_number);
    if let Some(epoch) = published {
        tracing::info!(
            ns = ns.display_name(),
            count = expired.len(),
            epoch,
            "lifecycle: expired objects published"
        );
    }
    Ok(published)
}

/// Staged resources of `ns` still open or prepared that were created
/// before `cutoff_ms`, with the revision each was observed at, at most
/// [`ABANDON_BATCH`] per pass.
fn abandoned_uploads<S: KappaStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    cutoff_ms: i64,
) -> Result<Vec<(String, u64)>, StoreError> {
    let mut candidates = Vec::new();
    kappa_handler::scan_namespace_resources(store, ns, |id, head| {
        if matches!(head.phase, ResourcePhase::Open | ResourcePhase::Prepared)
            && head.created_at_ms < cutoff_ms
        {
            candidates.push((id.to_string(), head.revision));
        }
        Ok(if candidates.len() < ABANDON_BATCH {
            ControlFlow::Continue(())
        } else {
            ControlFlow::Break(())
        })
    })?;
    Ok(candidates)
}

/// Discard every incomplete upload of `ns` created before `cutoff_ms` in
/// one execution, each guarded by the revision it was observed at so an
/// upload that progressed since is left alone. The budget follows the
/// publication. Returns the number discarded.
fn abandon_uploads<S: KappaStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    clock: &dyn Clock,
    budget: &StagingBudget,
    cutoff_ms: i64,
) -> Result<usize, StoreError> {
    let candidates = abandoned_uploads(store, ns, cutoff_ms)?;
    if candidates.is_empty() {
        return Ok(0);
    }
    let asserter = kappa_handler::anonymous_principal();
    let mut discarded = 0usize;
    let published = publish_if_changed(store, ns, clock, |execution| {
        for (id, revision) in &candidates {
            let Some(current) = resource::resolve_in(execution, id)? else {
                continue;
            };
            if current.head.revision != *revision {
                continue;
            }
            if resource::discard(execution, &asserter, id)? {
                discarded += 1;
            }
        }
        Ok(discarded > 0)
    })?;
    if let Some(published) = published {
        let mutations = kappa_handler::committed_ledger(store, ns, &published.root)
            .inspect_err(|error| {
                tracing::error!(%error, namespace = %ns, root = %published.root, "lifecycle ledger unreadable");
            })
            .ok();
        budget.follow(store, ns, mutations.as_deref());
    }
    Ok(discarded)
}

/// Names of published object tags whose `_s3_created_ms` creation time is
/// at least `threshold_ms` before `now_ms`. Internal tags are never expired.
fn expired_tags<S: KappaStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    now_ms: u64,
    threshold_ms: u64,
) -> Result<Vec<String>, StoreError> {
    let mut expired = Vec::new();
    let mut request = PageRequest::first(1024);
    loop {
        let tags = store.tag_list(ns, None, &request)?;
        for tag in &tags.items {
            if tag.name.starts_with('_') {
                continue;
            }
            let Some(created_bytes) =
                absent(store.blob_meta_get_in(ns, &tag.kappa, "_s3_created_ms"))?
            else {
                continue;
            };
            let Some(created_ms) = std::str::from_utf8(&created_bytes)
                .ok()
                .and_then(|text| text.parse::<u64>().ok())
                .filter(|created| *created > 0)
            else {
                tracing::warn!(
                    ns = ns.display_name(),
                    key = %tag.name,
                    "lifecycle: object creation time is not a positive integer, skipping"
                );
                continue;
            };
            let age_ms = now_ms.saturating_sub(created_ms);
            if age_ms >= threshold_ms {
                tracing::info!(
                    ns = ns.display_name(),
                    key = %tag.name,
                    age_days = age_ms / DAY_MS,
                    "lifecycle: expiring object"
                );
                expired.push(tag.name.clone());
            }
        }
        let Some(after) = tags.next_after else { break };
        if request
            .after
            .as_ref()
            .is_some_and(|previous| after <= *previous)
        {
            return Err(StoreError::Internal(
                "lifecycle tag cursor did not advance".into(),
            ));
        }
        request.after = Some(after);
    }
    Ok(expired)
}
