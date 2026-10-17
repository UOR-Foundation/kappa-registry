//! Settlement of published epochs, physical inventory of content storage
//! and repair of its indexes.
//!
//! A publication is acknowledged when its namespace committed; its
//! effects on the registry's shared projections (catalog, ownership,
//! directory) are settled here, at most `batch` epochs per tick, from
//! where the previous tick stopped. Representations no settled row owns
//! (preparations that never installed, publications that aborted,
//! retirements whose physical reclamation was deferred by a reader's pin)
//! are settled by the store's bounded inventory: every tick examines at
//! most `batch` entries from where the previous tick stopped, so a large
//! store is settled across ticks without holding anything for the whole
//! of it; the store deletes nothing while settlement is incomplete. Each
//! tick also asks the store to repair its derived reference indexes; a
//! backend that recorded a divergence while writing rebuilds them from
//! committed state here rather than at every open.

use std::sync::Arc;
use std::time::Duration;

use kappa_handler::clock::Clock;
use kappa_store::traits::KappaStore;

pub async fn run_inventory_loop<S>(
    store: Arc<S>,
    clock: Arc<dyn Clock>,
    interval_secs: u64,
    batch: usize,
) where
    S: KappaStore + 'static + ?Sized,
{
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs.max(1)));
    let settle_limit = u64::try_from(batch).unwrap_or(u64::MAX);
    loop {
        interval.tick().await;
        let s = store.clone();
        let c = clock.clone();
        // Settlement, repair, reclamation and session eviction are
        // independent: a failed step is retried next tick and never
        // withholds the others; the reclaimer itself refuses to delete
        // while settlement is behind. Eviction removes session rows whose
        // recorded deadline has passed; it is bounded per call by the
        // store and changes no authorization.
        match tokio::task::spawn_blocking(move || {
            let evicted = c
                .now()
                .map_err(|error| kappa_store::StoreError::Internal(error.to_string()))
                .and_then(|now| s.session_evict(now));
            (
                s.settle(settle_limit),
                s.repair_indexes(),
                s.reclaim_unowned(batch),
                evicted,
            )
        })
        .await
        {
            Ok((settlement, repair, reclamation, evicted)) => {
                match evicted {
                    Ok(count) if count > 0 => {
                        tracing::info!(sessions = count, "expired sessions evicted")
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "session eviction failed"),
                }
                match settlement {
                    Ok(settled) if settled > 0 => {
                        tracing::info!(epochs = settled, "settlement step");
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "settlement step failed"),
                }
                match repair {
                    Ok(repair) if repair.diverged => tracing::warn!(
                        entries = repair.entries,
                        "reference indexes rebuilt from committed state"
                    ),
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "reference index repair failed"),
                }
                match reclamation {
                    Ok(reclamation) if reclamation.files > 0 || reclamation.unrecognized > 0 => {
                        tracing::info!(
                            files = reclamation.files,
                            bytes = reclamation.bytes,
                            owned = reclamation.owned,
                            protected = reclamation.protected,
                            unrecognized = reclamation.unrecognized,
                            absent = reclamation.absent,
                            complete = reclamation.complete,
                            "content inventory step"
                        );
                    }
                    Ok(_) => {}
                    Err(error) => tracing::warn!(%error, "content inventory failed"),
                }
            }
            Err(error) => tracing::warn!(%error, "content inventory task failed"),
        }
    }
}
