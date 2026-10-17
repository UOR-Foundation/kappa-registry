use std::sync::Arc;

use kappa_handler::clock::{ClockError, SystemSource, WallClock};
use kappa_store::clock::DurationMs;
use kappa_store_redb::PersistentStore;

/// Durable issuance headroom: the bound on causal lead over physical time.
/// Restart resumes above the persisted ceiling without waiting, so this is
/// also the furthest a restarted authority can run ahead of a lagging
/// physical source. Renewal at a fifth of the headroom keeps four renewals
/// of slack before issuance fails closed.
const RESERVATION_MS: u64 = 5_000;

/// Renewal cadence for the durable reservation.
const RENEWAL_MS: u64 = RESERVATION_MS / 5;

/// All durable I/O occurs on a blocking worker before authority registration.
pub async fn initialize(store: Arc<PersistentStore>) -> Result<Arc<WallClock>, ClockError> {
    tokio::task::spawn_blocking(move || {
        Ok(Arc::new(WallClock::durable(
            Arc::new(SystemSource),
            store,
            DurationMs::from_millis(RESERVATION_MS),
        )?))
    })
    .await
    .map_err(|error| {
        ClockError::Persistence(kappa_store::StoreError::Internal(format!(
            "time initialization worker: {error}"
        )))
    })?
}

/// Renewal failure preserves the previous ceiling. Issuance fails closed once
/// it exhausts that ceiling; subsequent successful renewal restores issuance.
pub async fn renew(clock: Arc<WallClock>) {
    let mut interval = tokio::time::interval(std::time::Duration::from_millis(RENEWAL_MS));
    loop {
        interval.tick().await;
        let clock = clock.clone();
        let result = tokio::task::spawn_blocking(move || {
            clock.renew_reservation(DurationMs::from_millis(RESERVATION_MS))
        })
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::error!(%error, "time reservation renewal failed"),
            Err(error) => tracing::error!(%error, "time reservation worker failed"),
        }
    }
}
