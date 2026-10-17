//! PERF-CON-001: concurrent writers on one namespace share the one causal
//! time authority.
//!
//! An execution issues its time only after it holds the store writer, so
//! publication order is issuance order: every concurrent publish succeeds,
//! epoch numbers are dense, and epoch timestamps strictly increase along
//! the chain. The negative case pins the detector the positive case relies
//! on: a time issued before a later-published predecessor is refused at
//! publication and publishes nothing.

use std::sync::Barrier;

use kappa_handler::clock::WallClock;
use kappa_handler::clock_at;
use kappa_store::{ClockMs, Kappa, KappaStore, NamespaceRef, StoreError, TagUpdate, replay_to};

use crate::common::{TestResult, create_ns, on_both_backends};

const WRITERS: usize = 8;
const PER_WRITER: usize = 32;

fn tag(writer: usize, round: usize) -> String {
    format!("writer-{writer}/round-{round}")
}

fn content(writer: usize, round: usize) -> Kappa {
    Kappa::sha256(tag(writer, round).as_bytes())
}

/// Publish `PER_WRITER` single-tag executions; the epoch number of each.
fn write_all(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    clock: &WallClock,
    writer: usize,
    start: &Barrier,
) -> Result<Vec<u64>, StoreError> {
    start.wait();
    (0..PER_WRITER)
        .map(|round| {
            let mut execution = store.begin_execution(ns, clock)?;
            execution.tag_put(
                &tag(writer, round),
                &TagUpdate::Set {
                    kappa: content(writer, round),
                },
            )?;
            Ok(execution.publish()?.epoch_number)
        })
        .collect()
}

#[test]
fn concurrent_writers_publish_in_issuance_order() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "concurrent-writers")?;
        let clock = WallClock::new();
        let start = Barrier::new(WRITERS);
        let outcomes: Vec<Result<Vec<u64>, String>> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..WRITERS)
                .map(|writer| {
                    let (ns, clock, start) = (&ns, &clock, &start);
                    scope.spawn(move || {
                        write_all(store, ns, clock, writer, start)
                            .map_err(|error| format!("writer {writer}: {error}"))
                    })
                })
                .collect();
            workers
                .into_iter()
                .map(|worker| {
                    worker
                        .join()
                        .map_err(|_| String::from("writer thread panicked"))
                        .and_then(|outcome| outcome)
                })
                .collect()
        });
        let mut published = Vec::with_capacity(WRITERS * PER_WRITER);
        for outcome in outcomes {
            published.extend(outcome?);
        }
        published.sort_unstable();
        let total = u64::try_from(WRITERS * PER_WRITER)?;
        assert_eq!(
            published,
            (2..=1 + total).collect::<Vec<_>>(),
            "every publish succeeds with a distinct, dense epoch number"
        );

        let (head, _) = store.epoch_current(&ns)?;
        assert_eq!(head, 1 + total);
        let mut previous: Option<i64> = None;
        for number in 1..=head {
            let timestamp = store
                .epoch_get(&store.epoch_get_by_number(&ns, number)?)?
                .timestamp_ms();
            if let Some(previous) = previous {
                assert!(
                    timestamp > previous,
                    "epoch {number} timestamp {timestamp} does not follow {previous}"
                );
            }
            previous = Some(timestamp);
        }

        let replayed = replay_to(store, &ns, head)?;
        assert_eq!(replayed.tags.len(), WRITERS * PER_WRITER);
        for writer in 0..WRITERS {
            for round in 0..PER_WRITER {
                assert_eq!(
                    store.tag_get(&ns, &tag(writer, round))?.kappa,
                    content(writer, round)
                );
            }
        }
        Ok(())
    })
}

#[test]
fn time_issued_before_a_published_predecessor_is_refused() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "issued-out-of-order")?;
        let mut later = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(3000))?)?;
        later.tag_put(
            "later",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"later"),
            },
        )?;
        let published = later.publish()?;
        let before = store.epoch_state(&ns)?;

        let mut earlier = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2000))?)?;
        earlier.tag_put(
            "earlier",
            &TagUpdate::Set {
                kappa: Kappa::sha256(b"earlier"),
            },
        )?;
        match earlier.publish() {
            Err(StoreError::Rejected(message)) => {
                assert_eq!(message, "epoch timestamp regressed");
            }
            other => return Err(format!("regressed time published: {other:?}").into()),
        }
        assert_eq!(
            store.epoch_current(&ns)?,
            (published.epoch_number, published.root)
        );
        assert_eq!(store.epoch_state(&ns)?, before);
        assert!(matches!(
            store.tag_get(&ns, "earlier"),
            Err(StoreError::NotFound(_))
        ));
        Ok(())
    })
}
