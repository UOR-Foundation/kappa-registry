//! Cross-namespace isolation and progress through the real store boundary.
//! These contracts apply to both backends, including during a held writer.

use std::sync::{Barrier, mpsc};
use std::time::Duration;

use kappa_handler::clock::WallClock;
use kappa_store::{Kappa, KappaStore, NamespaceRef, StoreError, TagUpdate, replay_to};

use crate::common::{TestResult, create_ns, on_both_backends};

const WORKERS: usize = 4;
const ROUNDS: usize = 16;

/// What one contender of a compare-and-swap observed: its namespace index,
/// its candidate, and the current record a losing contender was handed.
type CasOutcome = (usize, Kappa, Option<Box<kappa_store::TagEntry>>);

/// One mixed worker: every round it checks each namespace's anchor while
/// peers publish, then, unless `width` is zero, publishes `width` tags in
/// one batch to its own namespace.
fn mixed_worker(
    store: &dyn KappaStore,
    namespaces: &[NamespaceRef],
    anchors: &[Kappa],
    clock: &WallClock,
    worker: usize,
    width: usize,
) -> Result<(), String> {
    for round in 0..ROUNDS {
        // Identical tag names have different values across namespaces.
        for (ns, expected) in namespaces.iter().zip(anchors) {
            let actual = store.tag_get(ns, "anchor").map_err(|e| e.to_string())?;
            if actual.kappa != *expected {
                return Err(format!("worker {worker}: namespace anchor crossed"));
            }
        }
        if width == 0 {
            continue;
        }
        let ns = &namespaces[worker % namespaces.len()];
        let updates: Vec<_> = (0..width)
            .map(|item| {
                let name = format!("worker-{worker}/{round}/{item}");
                let kappa = Kappa::sha256(name.as_bytes());
                (name, TagUpdate::Set { kappa })
            })
            .collect();
        let mut execution = store
            .begin_execution(ns, clock)
            .map_err(|e| e.to_string())?;
        execution
            .tag_batch_update(&updates)
            .map_err(|e| e.to_string())?;
        execution.publish().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Namespace `index` of `count` holds exactly the epochs and tags its own
/// workers published, and none of any other namespace's.
fn assert_mixed_namespace(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    widths: &[usize],
    count: usize,
    index: usize,
) -> TestResult {
    let writers = widths
        .iter()
        .enumerate()
        .filter(|(worker, width)| **width > 0 && worker % count == index)
        .count();
    let (head, _) = store.epoch_current(ns)?;
    assert_eq!(head, 2 + u64::try_from(writers * ROUNDS)?);
    let replayed = replay_to(store, ns, head)?;
    let entries = widths
        .iter()
        .enumerate()
        .filter(|(worker, _)| worker % count == index)
        .map(|(_, width)| width * ROUNDS)
        .sum::<usize>();
    assert_eq!(replayed.tags.len(), 1 + entries);
    for (worker, width) in widths.iter().enumerate() {
        for round in 0..ROUNDS {
            for item in 0..*width {
                let name = format!("worker-{worker}/{round}/{item}");
                if worker % count == index {
                    assert_eq!(
                        store.tag_get(ns, &name)?.kappa,
                        Kappa::sha256(name.as_bytes())
                    );
                } else {
                    assert!(matches!(
                        store.tag_get(ns, &name),
                        Err(StoreError::NotFound(_))
                    ));
                }
            }
        }
    }
    Ok(())
}

#[test]
fn mixed_reads_and_single_or_batch_writes_preserve_each_namespace() -> TestResult {
    for count in [1, 2, WORKERS] {
        for widths in [
            [0, 0, 0, 0],
            [1, 1, 1, 1],
            [8, 8, 8, 8],
            [0, 1, 8, 0],
            [8, 0, 0, 1],
        ] {
            on_both_backends(|store| {
                let namespaces = (0..count)
                    .map(|index| create_ns(store, &format!("mixed-{index}")))
                    .collect::<Result<Vec<_>, _>>()?;
                let clock = WallClock::new();
                let anchors: Vec<_> = (0..count)
                    .map(|index| Kappa::sha256(format!("namespace-{index}").as_bytes()))
                    .collect();
                for (ns, anchor) in namespaces.iter().zip(&anchors) {
                    let mut execution = store.begin_execution(ns, &clock)?;
                    execution.tag_put(
                        "anchor",
                        &TagUpdate::Set {
                            kappa: anchor.clone(),
                        },
                    )?;
                    execution.publish()?;
                }
                let start = Barrier::new(WORKERS);
                let outcomes = std::thread::scope(|scope| {
                    let handles: Vec<_> = widths
                        .iter()
                        .enumerate()
                        .map(|(worker, &width)| {
                            let (namespaces, anchors, clock, start) =
                                (&namespaces, &anchors, &clock, &start);
                            scope.spawn(move || {
                                start.wait();
                                mixed_worker(store, namespaces, anchors, clock, worker, width)
                            })
                        })
                        .collect();
                    handles
                        .into_iter()
                        .map(|handle| {
                            handle
                                .join()
                                .map_err(|_| "mixed worker panicked".to_owned())?
                        })
                        .collect::<Vec<Result<(), String>>>()
                });
                for outcome in outcomes {
                    outcome?;
                }
                for (index, ns) in namespaces.iter().enumerate() {
                    assert_mixed_namespace(store, ns, &widths, count, index)?;
                }
                Ok(())
            })?;
        }
    }
    Ok(())
}

/// One contender of the compare-and-swap in namespace `worker % count`,
/// expecting the version every contender read.
fn cas_contender(
    store: &dyn KappaStore,
    namespaces: &[NamespaceRef],
    versions: &[u64],
    clock: &WallClock,
    worker: usize,
    count: usize,
) -> Result<CasOutcome, String> {
    let index = worker % count;
    let candidate = Kappa::sha256(format!("candidate-{worker}").as_bytes());
    let mut execution = store
        .begin_execution(&namespaces[index], clock)
        .map_err(|e| e.to_string())?;
    match execution.tag_put(
        "contended",
        &TagUpdate::CompareAndSwap {
            kappa: candidate.clone(),
            expected_version: versions[index],
        },
    ) {
        Ok(()) => {
            execution.publish().map_err(|e| e.to_string())?;
            Ok((index, candidate, None))
        }
        Err(StoreError::VersionMismatch {
            expected,
            found,
            current,
        }) => {
            assert_eq!(expected, versions[index]);
            assert_eq!(found, versions[index] + 1);
            let current = current.ok_or("CAS retry error omitted the current record")?;
            assert_eq!(current.version, found);
            assert_eq!(current.name, "contended");
            execution.abort().map_err(|e| e.to_string())?;
            Ok((index, candidate, Some(current)))
        }
        Err(error) => Err(error.to_string()),
    }
}

#[test]
fn concurrent_cas_has_one_winner_per_namespace_and_losers_publish_nothing() -> TestResult {
    for count in [1, 2, WORKERS] {
        on_both_backends(|store| {
            let clock = WallClock::new();
            let namespaces = (0..count)
                .map(|index| create_ns(store, &format!("cas-isolation-{index}")))
                .collect::<Result<Vec<_>, _>>()?;
            let mut versions = Vec::new();
            let mut heads = Vec::new();
            for ns in &namespaces {
                let mut execution = store.begin_execution(ns, &clock)?;
                execution.tag_put(
                    "contended",
                    &TagUpdate::Set {
                        kappa: Kappa::sha256(b"initial"),
                    },
                )?;
                execution.publish()?;
                versions.push(store.tag_get(ns, "contended")?.version);
                heads.push(store.epoch_current(ns)?.0);
            }
            // Every contender uses the same previously committed version in
            // its namespace. No thread holds a writer while waiting here.
            let start = Barrier::new(WORKERS);
            let outcomes = std::thread::scope(|scope| {
                let workers: Vec<_> = (0..WORKERS)
                    .map(|worker| {
                        let (namespaces, versions, clock, start) =
                            (&namespaces, &versions, &clock, &start);
                        scope.spawn(move || {
                            start.wait();
                            cas_contender(store, namespaces, versions, clock, worker, count)
                        })
                    })
                    .collect();
                workers
                    .into_iter()
                    .map(|worker| {
                        worker
                            .join()
                            .map_err(|_| "CAS worker panicked".to_owned())?
                    })
                    .collect::<Result<Vec<_>, String>>()
            })?;
            for (index, ns) in namespaces.iter().enumerate() {
                let winners: Vec<_> = outcomes
                    .iter()
                    .filter(|(owner, _, retry)| *owner == index && retry.is_none())
                    .collect();
                assert_eq!(
                    winners.len(),
                    1,
                    "namespace {index} must have exactly one CAS winner"
                );
                let actual = store.tag_get(ns, "contended")?;
                assert_eq!(actual.kappa, winners[0].1);
                assert_eq!(actual.version, versions[index] + 1);
                let (head, _) = store.epoch_current(ns)?;
                assert_eq!(
                    head,
                    heads[index] + 1,
                    "rejected CAS must not advance history"
                );
                assert_eq!(replay_to(store, ns, head)?.tags.len(), 1);
                let losers: Vec<_> = outcomes
                    .iter()
                    .filter(|(owner, _, retry)| *owner == index && retry.is_some())
                    .collect();
                assert_eq!(losers.len(), WORKERS / count - 1);
                for (_, _, record) in &losers {
                    let record = record.as_ref().ok_or("missing retry record")?;
                    assert_eq!(
                        kappa_store::canonical::canonical_bytes(record.as_ref()),
                        kappa_store::canonical::canonical_bytes(&actual)
                    );
                }
                // Exercise one returned retry reference after checking that
                // every original loser left the epoch unchanged.
                if let Some((_, candidate, Some(record))) = losers.first().copied() {
                    let mut retry = store.begin_execution(ns, &clock)?;
                    retry.tag_put(
                        "contended",
                        &TagUpdate::CompareAndSwap {
                            kappa: candidate.clone(),
                            expected_version: record.version,
                        },
                    )?;
                    retry.publish()?;
                    let updated = store.tag_get(ns, "contended")?;
                    assert_eq!(&updated.kappa, candidate);
                    assert_eq!(updated.version, record.version + 1);
                    assert_eq!(store.epoch_current(ns)?.0, head + 1);
                }
            }
            Ok(())
        })?;
    }
    Ok(())
}

#[test]
fn a_held_namespace_writer_does_not_block_another_namespace_publication() -> TestResult {
    on_both_backends(|store| {
        let a = create_ns(store, "held-writer")?;
        let b = create_ns(store, "independent-writer")?;
        let clock = WallClock::new();
        let held = store.begin_execution(&a, &clock)?;
        let (send, receive) = mpsc::channel();
        let (before_release, worker) = std::thread::scope(|scope| {
            let worker = scope.spawn(|| -> Result<(), String> {
                let result = (|| {
                    let mut execution = store.begin_execution(&b, &clock)?;
                    execution.tag_put(
                        "independent",
                        &TagUpdate::Set {
                            kappa: Kappa::sha256(b"b"),
                        },
                    )?;
                    execution.publish()?;
                    Ok::<_, StoreError>(())
                })()
                .map_err(|error| error.to_string());
                send.send(result.clone())
                    .map_err(|error| error.to_string())?;
                result
            });
            // A watchdog, not a throughput threshold. Release A before joining
            // even on failure, so the current global-writer regression terminates.
            let before_release = receive.recv_timeout(Duration::from_secs(10));
            drop(held);
            (before_release, worker.join())
        });
        worker.map_err(|_| "independent writer panicked")??;
        before_release.map_err(|_| "namespace B could not publish while A held its writer")??;
        assert_eq!(store.epoch_current(&a)?.0, 1);
        assert_eq!(store.epoch_current(&b)?.0, 2);
        Ok(())
    })
}
