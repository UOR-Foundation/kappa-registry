use std::sync::Arc;
use std::time::Duration;

use kappa_handler::ResolverRegistry;
use kappa_store::identity::HandleRecord;
use kappa_store::namespace::NamespaceRef;
use kappa_store::time::Clock;
use kappa_store::{KappaStore, PageRequest, StoreError, publish_if_changed};

/// Record a successful third-party verification of `record` in one
/// execution against the handles namespace `ns`.
///
/// The attestation applies only while the stored record still equals the
/// probed one. A record that changed during the probe is stale: the
/// execution is aborted and nothing is published. Returns the published
/// epoch number, or `None` for a stale probe.
pub fn attest_handle<S: KappaStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    record: &HandleRecord,
    clock: &dyn Clock,
) -> Result<Option<u64>, StoreError> {
    let published = publish_if_changed(store, ns, clock, |execution| {
        execution.handle_attest(record)
    })?;
    Ok(published.map(|published| published.epoch_number))
}

pub async fn run_handle_verify_loop<S: KappaStore + 'static + ?Sized>(
    store: Arc<S>,
    registry: Arc<ResolverRegistry>,
    clock: Arc<dyn Clock>,
    interval_secs: u64,
    ttl_ms: u64,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs));
    loop {
        ticker.tick().await;
        if let Err(error) = verify_stale_handles(&store, &registry, &clock, ttl_ms).await {
            tracing::warn!(%error, "handle verification cycle failed");
        }
    }
}

async fn verify_stale_handles<S: KappaStore + 'static + ?Sized>(
    store: &Arc<S>,
    registry: &Arc<ResolverRegistry>,
    clock: &Arc<dyn Clock>,
    ttl_ms: u64,
) -> Result<(), String> {
    let ns = {
        let store = store.clone();
        kappa_handler::blocking(move || store.namespace_resolve("_handles", None))
            .await
            .map_err(|error| error.to_string())?
    };
    let mut request = PageRequest::first(1024);
    loop {
        let page = {
            let store = store.clone();
            let request = request.clone();
            kappa_handler::blocking(move || store.handle_list(&request))
                .await
                .map_err(|error| error.to_string())?
        };
        for record in page.items {
            let now = clock.now().map_err(|error| error.to_string())?;
            if record.attested_at_ms.is_some_and(|attested| {
                now.as_i64()
                    .checked_sub(attested)
                    .and_then(|age| u64::try_from(age).ok())
                    .is_some_and(|age| age < ttl_ms)
            }) {
                continue;
            }
            let resolved = registry
                .resolve(&record.handle)
                .await
                .map_err(|error| error.to_string())?;
            if resolved.is_some_and(|identity| identity.anchor == record.anchor) {
                let store = store.clone();
                let clock = clock.clone();
                let ns = ns.clone();
                let published =
                    kappa_handler::blocking(move || attest_handle(&*store, &ns, &record, &*clock))
                        .await
                        .map_err(|error| error.to_string())?;
                match published {
                    Some(epoch) => tracing::debug!(epoch, "handle attestation published"),
                    None => {
                        tracing::debug!(
                            "handle changed during verification; discarded stale probe"
                        );
                    }
                }
            }
        }
        let Some(after) = page.next_after else {
            return Ok(());
        };
        if request
            .after
            .as_ref()
            .is_some_and(|previous| after <= *previous)
        {
            return Err(StoreError::Internal("handle cursor did not advance".into()).to_string());
        }
        request.after = Some(after);
    }
}
