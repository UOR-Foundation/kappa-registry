//! Store contention curves (PERF-STO-027, PERF-CON-013): publishers on
//! disjoint namespaces and on one tag, compare-and-swap on one key,
//! readers quiescent and under a background publisher, and the single
//! writer under background readers.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use criterion::{Criterion, SamplingMode};
use kappa_handler::clock::WallClock;
use kappa_perf::bench::fixture::{create_ns, populate_tags, tag_name, tag_target};
use kappa_perf::bench::{BenchResult, Failure, SplitMix, bench, osc};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use kappa_store::{Kappa, KappaStore, NamespaceRef, StoreError, TagUpdate};

use crate::load::{Background, Load, Shared, Worker, publish_one, under};

/// Tags in the namespace readers query.
const READ_TAGS: usize = 1_000;
/// Names cycled by readers, generated before timing.
const LOOKUPS: usize = 4096;

pub fn register<S: KappaStore + 'static>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    threads: &[usize],
    shared: &Shared<S>,
) -> BenchResult {
    publishers(c, s, threads, shared)?;
    compare_and_swap(c, s, threads, shared)?;
    readers(c, s, threads, shared)?;
    writer_under_readers(c, s, threads, shared)
}

fn publishers<S: KappaStore + 'static>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    threads: &[usize],
    shared: &Shared<S>,
) -> BenchResult {
    let widest = threads.iter().copied().max().ok_or("no thread counts")?;
    let disjoint: Vec<NamespaceRef> = (0..widest)
        .map(|i| {
            create_ns(
                shared.store.as_ref(),
                &shared.clock,
                &format!("publisher-{i}"),
            )
        })
        .collect::<Result<_, _>>()?;
    let one = vec![create_ns(
        shared.store.as_ref(),
        &shared.clock,
        "publisher-shared",
    )?];
    let failure = Arc::new(Failure::default());
    CalibratedGroup::scope(
        c,
        &format!("publishers_{}", shared.backend),
        |group| -> BenchResult {
            group.configure(|g| {
                g.sampling_mode(SamplingMode::Flat);
            });
            for (variant, namespaces) in [
                ("disjoint", Arc::new(disjoint)),
                ("same_key", Arc::new(one)),
            ] {
                for &count in threads {
                    let (store, clock, worker_failure, namespaces) = (
                        Arc::clone(&shared.store),
                        Arc::clone(&shared.clock),
                        Arc::clone(&failure),
                        Arc::clone(&namespaces),
                    );
                    let serial = Arc::new(AtomicU64::new(0));
                    let worker: Worker = Arc::new(move |index, n| {
                        let ns = &namespaces[index % namespaces.len()];
                        for _ in 0..n {
                            let round = serial.fetch_add(1, Ordering::Relaxed);
                            if worker_failure
                                .ok(publish_one(
                                    store.as_ref(),
                                    &clock,
                                    ns,
                                    "contended",
                                    tag_target(index, round),
                                ))
                                .is_none()
                            {
                                return;
                            }
                        }
                    });
                    let id = osc(&format!(
                        "osc:ops/store.publish?mutations=1&threads={count}t&variant={variant}&{}",
                        shared.write_conds()
                    ))?;
                    group.bench_contended(
                        s,
                        &bench(id, variant, count.to_string(), None, "PERF-STO-027"),
                        count,
                        &worker,
                    )?;
                    failure.check("store.publish contended")?;
                }
            }
            Ok(())
        },
    )
}

/// One compare-and-swap of the `cas` tag at the version read just before.
/// `Ok(false)` is a lost race, which is the contention being measured.
fn cas_attempt<S: KappaStore>(
    store: &S,
    clock: &WallClock,
    ns: &NamespaceRef,
    kappa: Kappa,
) -> Result<bool, Box<dyn std::error::Error>> {
    let expected_version = store.tag_get(ns, "cas")?.version;
    let mut execution = store.begin_execution(ns, clock)?;
    match execution.tag_put(
        "cas",
        &TagUpdate::CompareAndSwap {
            kappa,
            expected_version,
        },
    ) {
        Ok(()) => {
            execution.publish()?;
            Ok(true)
        }
        Err(StoreError::VersionMismatch { .. }) => {
            execution.abort()?;
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

fn compare_and_swap<S: KappaStore + 'static>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    threads: &[usize],
    shared: &Shared<S>,
) -> BenchResult {
    let ns = Arc::new(create_ns(shared.store.as_ref(), &shared.clock, "cas")?);
    publish_one(
        shared.store.as_ref(),
        &shared.clock,
        &ns,
        "cas",
        tag_target(0, 0),
    )?;
    let failure = Arc::new(Failure::default());
    CalibratedGroup::scope(
        c,
        &format!("tag_cas_{}", shared.backend),
        |group| -> BenchResult {
            group.configure(|g| {
                g.sampling_mode(SamplingMode::Flat);
            });
            for &count in threads {
                let attempts = Arc::new(AtomicU64::new(0));
                let successes = Arc::new(AtomicU64::new(0));
                let (store, clock, worker_failure, worker_ns) = (
                    Arc::clone(&shared.store),
                    Arc::clone(&shared.clock),
                    Arc::clone(&failure),
                    Arc::clone(&ns),
                );
                let (tried, won) = (Arc::clone(&attempts), Arc::clone(&successes));
                let worker: Worker = Arc::new(move |index, n| {
                    for k in 0..n {
                        match worker_failure.ok(cas_attempt(
                            store.as_ref(),
                            &clock,
                            &worker_ns,
                            tag_target(index, k),
                        )) {
                            Some(true) => {
                                won.fetch_add(1, Ordering::Relaxed);
                            }
                            Some(false) => {}
                            None => return,
                        }
                        tried.fetch_add(1, Ordering::Relaxed);
                    }
                });
                let conds = format!("backend={}&threads={count}t&variant=cas", shared.backend);
                let ran = group.bench_contended(
                    s,
                    &bench(
                        osc(&format!("osc:ops/store.tag_put?{conds}"))?,
                        "cas",
                        count.to_string(),
                        None,
                        "PERF-STO-027",
                    ),
                    count,
                    &worker,
                )?;
                failure.check("store.tag_put cas")?;
                if ran {
                    let total = attempts.load(Ordering::Acquire);
                    if total == 0 {
                        return Err("compare-and-swap made no attempts".into());
                    }
                    #[allow(clippy::cast_precision_loss, reason = "attempt counts far below 2^53")]
                    let ratio = successes.load(Ordering::Acquire) as f64 / total as f64;
                    s.record_direct(
                        &osc(&format!("osc:ratio/store.tag_put?{conds}"))?,
                        ratio,
                        Some("PERF-STO-027"),
                    )?;
                }
            }
            Ok(())
        },
    )
}

/// A background publisher rewriting one tag of `ns` until stopped.
fn publisher_load<S: KappaStore + 'static>(
    shared: &Shared<S>,
    ns: &Arc<NamespaceRef>,
    failure: &Arc<Failure>,
) -> Load {
    let (store, clock, ns, failure) = (
        Arc::clone(&shared.store),
        Arc::clone(&shared.clock),
        Arc::clone(ns),
        Arc::clone(failure),
    );
    Arc::new(move |_, stop: &AtomicBool| {
        let mut round = 0u64;
        while !stop.load(Ordering::Acquire) {
            round += 1;
            if failure
                .ok(publish_one(
                    store.as_ref(),
                    &clock,
                    &ns,
                    "background",
                    tag_target(usize::MAX, round),
                ))
                .is_none()
            {
                break;
            }
        }
        round
    })
}

fn lookups(seed: u64) -> Arc<Vec<(String, Kappa)>> {
    let mut rng = SplitMix(seed);
    Arc::new(
        (0..LOOKUPS)
            .map(|_| {
                let index = rng.below(READ_TAGS);
                (tag_name(index), tag_target(index, 0))
            })
            .collect(),
    )
}

fn readers<S: KappaStore + 'static>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    threads: &[usize],
    shared: &Shared<S>,
) -> BenchResult {
    let ns = Arc::new(create_ns(shared.store.as_ref(), &shared.clock, "readers")?);
    populate_tags(shared.store.as_ref(), &shared.clock, &ns, READ_TAGS)?;
    let names = lookups(80);
    let failure = Arc::new(Failure::default());
    CalibratedGroup::scope(
        c,
        &format!("readers_{}", shared.backend),
        |group| -> BenchResult {
            for contention in ["none", "1w"] {
                let background = (contention == "1w").then(|| {
                    (
                        Background::start(1, &publisher_load(shared, &ns, &failure)),
                        "background publisher",
                    )
                });
                under(background, || {
                    for &count in threads {
                        let (store, worker_ns, worker_failure, names) = (
                            Arc::clone(&shared.store),
                            Arc::clone(&ns),
                            Arc::clone(&failure),
                            Arc::clone(&names),
                        );
                        let worker: Worker = Arc::new(move |index, n| {
                            for (name, expected) in names
                                .iter()
                                .cycle()
                                .skip(index * (LOOKUPS / 8))
                                .take(usize::try_from(n).unwrap_or(usize::MAX))
                            {
                                match worker_failure.ok(store.tag_get(&worker_ns, name)) {
                                    Some(entry) if entry.kappa == *expected => {}
                                    Some(_) => {
                                        worker_failure.fail(format!(
                                            "tag {name} resolved to the wrong content"
                                        ));
                                        return;
                                    }
                                    None => return,
                                }
                            }
                        });
                        let id = osc(&format!(
                            "osc:ops/store.tag_get?backend={}&contention={contention}&hit=hit&state=warm&tags={READ_TAGS}&threads={count}t",
                            shared.backend
                        ))?;
                        group.bench_contended(
                            s,
                            &bench(id, contention, count.to_string(), None, "PERF-CON-013"),
                            count,
                            &worker,
                        )?;
                        failure.check("store.tag_get contended")?;
                    }
                    Ok(())
                })?;
                failure.check("background publisher")?;
            }
            Ok(())
        },
    )
}

/// Background threads cycling `tag_get` over `names` until stopped.
fn reader_load<S: KappaStore + 'static>(
    shared: &Shared<S>,
    ns: &Arc<NamespaceRef>,
    names: &Arc<Vec<(String, Kappa)>>,
    failure: &Arc<Failure>,
) -> Load {
    let (store, ns, failure, names) = (
        Arc::clone(&shared.store),
        Arc::clone(ns),
        Arc::clone(failure),
        Arc::clone(names),
    );
    Arc::new(move |index, stop: &AtomicBool| {
        let mut reads = 0u64;
        for (name, _) in names.iter().cycle().skip(index) {
            if stop.load(Ordering::Acquire) || failure.ok(store.tag_get(&ns, name)).is_none() {
                break;
            }
            reads += 1;
        }
        reads
    })
}

fn writer_under_readers<S: KappaStore + 'static>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    threads: &[usize],
    shared: &Shared<S>,
) -> BenchResult {
    let read_ns = Arc::new(create_ns(
        shared.store.as_ref(),
        &shared.clock,
        "read-load",
    )?);
    populate_tags(shared.store.as_ref(), &shared.clock, &read_ns, READ_TAGS)?;
    let write_ns = Arc::new(create_ns(
        shared.store.as_ref(),
        &shared.clock,
        "write-under-readers",
    )?);
    let names = lookups(81);
    let failure = Arc::new(Failure::default());
    CalibratedGroup::scope(
        c,
        &format!("writer_under_readers_{}", shared.backend),
        |group| -> BenchResult {
            group.configure(|g| {
                g.sampling_mode(SamplingMode::Flat);
            });
            for &readers in threads {
                let background =
                    Background::start(readers, &reader_load(shared, &read_ns, &names, &failure));
                under(Some((background, "background readers")), || {
                    let (store, clock, worker_failure, ns) = (
                        Arc::clone(&shared.store),
                        Arc::clone(&shared.clock),
                        Arc::clone(&failure),
                        Arc::clone(&write_ns),
                    );
                    let serial = Arc::new(AtomicU64::new(0));
                    let worker: Worker = Arc::new(move |_, n| {
                        for _ in 0..n {
                            let round = serial.fetch_add(1, Ordering::Relaxed);
                            if worker_failure
                                .ok(publish_one(
                                    store.as_ref(),
                                    &clock,
                                    &ns,
                                    "written",
                                    tag_target(0, round),
                                ))
                                .is_none()
                            {
                                return;
                            }
                        }
                    });
                    let id = osc(&format!(
                        "osc:ops/store.publish?contention={readers}t&mutations=1&threads=1t&variant=disjoint&{}",
                        shared.write_conds()
                    ))?;
                    group.bench_contended(
                        s,
                        &bench(
                            id,
                            "under_readers",
                            readers.to_string(),
                            None,
                            "PERF-STO-027",
                        ),
                        1,
                        &worker,
                    )?;
                    Ok(())
                })?;
                failure.check("store.publish under readers")?;
            }
            Ok(())
        },
    )
}
