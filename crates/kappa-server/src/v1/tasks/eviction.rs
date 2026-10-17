//! Expiry of staged resources.
//!
//! Every namespace's resources are read from committed state; those past
//! their expiry (open, prepared, or completed with a replayable outcome
//! whose window has closed) are discarded through an execution whose guard
//! rechecks the head's revision and expiry under the writer, so a resource
//! transitioned since it was observed is left alone. Expiry is therefore an
//! epoch-committed transition, never a destructor. The staging budget
//! follows each expiry publication's ledger, the same path every handler
//! publication takes, so a discarded head is released by its tag deletion.
//! Each tick also settles the budget: a projection left unresolved by an
//! unobserved publication is rebuilt here, independently of any further
//! foreground publication, so admission reopens once storage is readable
//! again.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use kappa_handler::StagingBudget;
use kappa_store::resource;
use kappa_store::traits::KappaStore;
use kappa_store::{NamespaceRef, ResourcePhase, StoreError};

/// Resources expired per namespace per tick.
const EXPIRE_BATCH: usize = 64;

pub async fn run_eviction_loop<S>(
    store: Arc<S>,
    clock: Arc<dyn kappa_handler::clock::Clock>,
    budget: Arc<StagingBudget>,
) where
    S: KappaStore + 'static + ?Sized,
{
    let mut interval = tokio::time::interval(Duration::from_secs(60));
    loop {
        interval.tick().await;
        let s = store.clone();
        let c = clock.clone();
        let b = budget.clone();
        match tokio::task::spawn_blocking(move || {
            let settled = b.settle(&*s);
            (settled, expire_resources(&*s, &*c, &b))
        })
        .await
        {
            Ok((settled, expired)) => {
                match settled {
                    Ok(Some(count)) => {
                        tracing::warn!(
                            resources = count,
                            "staging budget rebuilt; admission reopened"
                        );
                    }
                    Ok(None) => {}
                    Err(error) => {
                        tracing::error!(%error, "staging budget rebuild failed; admission stays closed")
                    }
                }
                match expired {
                    Ok(n) if n > 0 => tracing::info!(count = n, "expired staged resources"),
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "resource expiry failed"),
                }
            }
            Err(error) => tracing::warn!(%error, "resource expiry task failed"),
        }
    }
}

/// Expiry candidates per namespace: the resource id and the revision it
/// was observed at.
type Candidates = BTreeMap<[u8; 16], (NamespaceRef, Vec<(String, u64)>)>;

/// Discard every expired resource, at most [`EXPIRE_BATCH`] per namespace.
/// Returns the number discarded.
fn expire_resources<S: KappaStore + ?Sized>(
    store: &S,
    clock: &dyn kappa_handler::clock::Clock,
    budget: &StagingBudget,
) -> Result<usize, StoreError> {
    let now = clock.now()?;
    let asserter = kappa_handler::anonymous_principal();
    let mut candidates: Candidates = BTreeMap::new();
    kappa_handler::scan_resources(store, |ns, id, head| {
        if head.phase == ResourcePhase::Discarded || now.as_i64() <= head.expires_at_ms {
            return Ok(());
        }
        let (_, ids) = candidates
            .entry(*ns.id())
            .or_insert_with(|| (ns.clone(), Vec::new()));
        if ids.len() < EXPIRE_BATCH {
            ids.push((id.to_string(), head.revision));
        }
        Ok(())
    })?;
    let mut expired = 0;
    for (ns, ids) in candidates.into_values() {
        let mut execution = store.begin_execution(&ns, clock)?;
        let mut discarded = Vec::with_capacity(ids.len());
        for (id, revision) in &ids {
            if resource::expire(&mut *execution, &asserter, id, *revision)? {
                discarded.push(id.clone());
            }
        }
        if discarded.is_empty() {
            execution.abort()?;
            continue;
        }
        let published = execution.publish()?;
        // The budget follows this publication's ledger exactly as it follows
        // a handler's: every discarded head's tag deletion releases it.
        let mutations = kappa_handler::committed_ledger(store, &ns, &published.root)
            .inspect_err(|error| {
                tracing::error!(%error, namespace = %ns, root = %published.root, "expiry ledger unreadable");
            })
            .ok();
        budget.follow(store, &ns, mutations.as_deref());
        expired += discarded.len();
    }
    Ok(expired)
}
