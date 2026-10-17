//! PERF-CON-002: an execution published after its deadline fails with
//! `DeadlineExceeded`, publishes nothing, leaves namespace state and the
//! epoch unchanged, and releases the writer for the next execution.

use std::time::{Duration, Instant};

use kappa_handler::clock_at;
use kappa_store::{ClockMs, Kappa, StoreError, TagUpdate};

use crate::common::{TestResult, create_ns, on_both_backends};

#[test]
fn deadline_exceeded_aborts_cleanly() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "deadline")?;
        let seed = Kappa::sha256(b"seed");
        let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2000))?)?;
        execution.tag_put(
            "stable",
            &TagUpdate::Set {
                kappa: seed.clone(),
            },
        )?;
        execution.publish()?;
        let before = (store.epoch_current(&ns)?, store.epoch_state(&ns)?);

        let mut late = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(3000))?)?;
        // A deadline that has already passed when publication begins.
        late.set_deadline(Instant::now());
        late.tag_put(
            "stable",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"overwrite"),
            },
        )?;
        late.tag_put(
            "late",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"late"),
            },
        )?;
        std::thread::sleep(Duration::from_millis(1));
        let result = late.publish();
        assert!(
            matches!(result, Err(StoreError::DeadlineExceeded { .. })),
            "got {result:?}"
        );

        assert_eq!(store.tag_get(&ns, "stable")?.kappa, seed);
        assert!(matches!(
            store.tag_get(&ns, "late"),
            Err(StoreError::NotFound(_))
        ));
        assert_eq!((store.epoch_current(&ns)?, store.epoch_state(&ns)?), before);

        // The failed publication released the writer.
        let mut next = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(4000))?)?;
        next.tag_put(
            "after",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"after"),
            },
        )?;
        assert_eq!(next.publish()?.epoch_number, before.0.0 + 1);
        Ok(())
    })
}

#[test]
fn deadline_with_remaining_time_publishes() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "deadline-ok")?;
        let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2000))?)?;
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(60))
            .ok_or("deadline overflows Instant")?;
        execution.set_deadline(deadline);
        execution.tag_put(
            "within",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"ok"),
            },
        )?;
        assert_eq!(execution.publish()?.epoch_number, 2);
        assert_eq!(store.tag_get(&ns, "within")?.kappa, Kappa::sha256(b"ok"));
        Ok(())
    })
}
