//! Execution and namespace workloads (PERF-STO-020, PERF-STO-021,
//! PERF-EPO-020, PERF-STO-003, PERF-STO-030).
//!
//! For each tag population: a private `tag_put` inside an open execution
//! (per mutation), `tag_get` of present and absent names on published
//! state, and the full publication of executions carrying 1 to 4096
//! mutations. Publication cost must stay flat as the population grows from
//! 10^3 to 10^7 tags (B-6). Then epoch retrieval and operation replay.
//! Every timestamp is issued by the production HLC authority inside the
//! timed region, as a handler issues it.

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{Criterion, SamplingMode};
use kappa_handler::clock::WallClock;
use kappa_perf::bench::fixture::{Target, create_ns, populate_tags, tag_name, tag_target};
use kappa_perf::bench::{BenchResult, Failure, SplitMix, Tier, bench, elements, osc};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use kappa_store::{Kappa, KappaStore, NamespaceRef, OperationAdmission, StoreError, TagUpdate};

/// Private tag writes per timed execution.
const PUT_BATCH: usize = 256;
/// Distinct names cycled by lookups, generated outside the timed region.
const LOOKUPS: usize = 4096;

const fn populations(tier: Tier) -> &'static [usize] {
    tier.pick(
        &[1_000],
        &[1_000, 100_000],
        &[1_000, 100_000, 1_000_000, 10_000_000],
    )
}

const fn mutation_counts(tier: Tier) -> &'static [usize] {
    tier.pick(&[1, 64], &[1, 64, 4096], &[1, 64, 4096])
}

pub fn register<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    target: &Target<'_, S>,
) -> BenchResult {
    for &tags in populations(tier) {
        let ns = create_ns(target.store, clock, &format!("tags-{tags}"))?;
        populate_tags(target.store, clock, &ns, tags)?;
        tag_puts(c, s, clock, target, &ns, tags)?;
        tag_gets(c, s, target, &ns, tags)?;
        publishes(c, s, tier, clock, target, &ns, tags)?;
    }
    epochs_and_operations(c, s, clock, target)
}

fn tag_puts<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    clock: &WallClock,
    target: &Target<'_, S>,
    ns: &NamespaceRef,
    tags: usize,
) -> BenchResult {
    let store = target.store;
    let names: Vec<String> = (0..tags.min(LOOKUPS)).map(tag_name).collect();
    let update = TagUpdate::Set {
        kappa: tag_target(0, u64::MAX),
    };
    let failure = Failure::default();
    let id = osc(&format!(
        "osc:lat/store.tag_put?backend={}&tags={tags}",
        target.backend
    ))?;
    CalibratedGroup::scope(
        c,
        &format!("tag_put_{}", target.label),
        |group| -> BenchResult {
            group.bench(
                s,
                &bench(
                    id,
                    "in_execution",
                    tags.to_string(),
                    elements(PUT_BATCH),
                    "PERF-STO-020",
                ),
                |iters| {
                    let mut total = Duration::ZERO;
                    let mut next = 0usize;
                    for _ in 0..iters {
                        let Some(mut execution) = failure.ok(store.begin_execution(ns, clock))
                        else {
                            break;
                        };
                        let start = Instant::now();
                        for _ in 0..PUT_BATCH {
                            if failure
                                .ok(execution.tag_put(&names[next % names.len()], &update))
                                .is_none()
                            {
                                break;
                            }
                            next += 1;
                        }
                        total += start.elapsed();
                        if failure.ok(execution.abort()).is_none() || failure.failed() {
                            break;
                        }
                    }
                    total
                },
            )?;
            failure.check("store.tag_put")
        },
    )
}

fn tag_gets<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    target: &Target<'_, S>,
    ns: &NamespaceRef,
    tags: usize,
) -> BenchResult {
    let store = target.store;
    let mut rng = SplitMix(30);
    let present: Vec<(String, Kappa)> = (0..LOOKUPS)
        .map(|_| {
            let index = rng.below(tags);
            (tag_name(index), tag_target(index, 0))
        })
        .collect();
    let absent: Vec<String> = (0..LOOKUPS).map(|i| format!("absent-{i:08}")).collect();
    let failure = Failure::default();
    let mut next = 0usize;
    CalibratedGroup::scope(
        c,
        &format!("tag_get_{}", target.label),
        |group| -> BenchResult {
            let id = osc(&format!(
                "osc:lat/store.tag_get?hit=hit&state=warm&tags={tags}&{}",
                target.read_conds()
            ))?;
            group.bench(
                s,
                &bench(id, "hit", tags.to_string(), None, "PERF-STO-020"),
                |iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        let (name, expected) = &present[next % LOOKUPS];
                        next += 1;
                        match failure.ok(store.tag_get(ns, black_box(name))) {
                            Some(entry) if entry.kappa == *expected => {}
                            Some(_) => {
                                failure.fail(format!("tag {name} resolved to the wrong content"));
                                break;
                            }
                            None => break,
                        }
                    }
                    start.elapsed()
                },
            )?;
            failure.check("store.tag_get hit")?;
            let id = osc(&format!(
                "osc:lat/store.tag_get?hit=miss&state=warm&tags={tags}&{}",
                target.read_conds()
            ))?;
            group.bench(
                s,
                &bench(id, "miss", tags.to_string(), None, "PERF-STO-020"),
                |iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        let name = &absent[next % LOOKUPS];
                        next += 1;
                        match store.tag_get(ns, black_box(name)) {
                            Err(StoreError::NotFound(_)) => {}
                            Ok(_) => {
                                failure.fail(format!("absent tag {name} resolved"));
                                break;
                            }
                            Err(error) => {
                                failure.fail(error.to_string());
                                break;
                            }
                        }
                    }
                    start.elapsed()
                },
            )?;
            failure.check("store.tag_get miss")
        },
    )
}

/// One execution publishing `updates`, from timestamp issue to commit.
fn publish_updates<S: KappaStore>(
    store: &S,
    clock: &WallClock,
    ns: &NamespaceRef,
    updates: &[(String, TagUpdate)],
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut execution = store.begin_execution(ns, clock)?;
    for (name, update) in updates {
        execution.tag_put(name, update)?;
    }
    Ok(execution.publish()?.epoch_number)
}

fn publishes<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    target: &Target<'_, S>,
    ns: &NamespaceRef,
    tags: usize,
) -> BenchResult {
    let store = target.store;
    let failure = Failure::default();
    let mut round = 0u64;
    let mut window = 0usize;
    CalibratedGroup::scope(
        c,
        &format!("publish_{}_{tags}", target.label),
        |group| -> BenchResult {
            group.configure(|g| {
                g.sampling_mode(SamplingMode::Flat);
            });
            for &mutations in mutation_counts(tier).iter().filter(|m| **m <= tags) {
                let id = osc(&format!(
                    "osc:lat/store.publish?mutations={mutations}&tags={tags}&{}",
                    target.write_conds()
                ))?;
                group.bench(
                    s,
                    &bench(id, "execution", mutations.to_string(), None, "PERF-STO-020"),
                    |iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            round += 1;
                            let updates: Vec<(String, TagUpdate)> = (0..mutations)
                                .map(|k| {
                                    let index = (window + k) % tags;
                                    (
                                        tag_name(index),
                                        TagUpdate::Set {
                                            kappa: tag_target(index, round),
                                        },
                                    )
                                })
                                .collect();
                            window = (window + mutations) % tags;
                            let start = Instant::now();
                            let published = publish_updates(store, clock, ns, &updates);
                            total += start.elapsed();
                            if failure.ok(published).is_none() {
                                break;
                            }
                        }
                        total
                    },
                )?;
                failure.check("store.publish")?;
            }
            Ok(())
        },
    )
}

fn epochs_and_operations<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    clock: &WallClock,
    target: &Target<'_, S>,
) -> BenchResult {
    let store = target.store;
    let ns = create_ns(store, clock, "operations")?;
    populate_tags(store, clock, &ns, 64)?;
    let (number, root) = store.epoch_current(&ns)?;
    let identity = [0x5a; 32];
    let request = Kappa::sha256(b"operation replay workload");
    let OperationAdmission::Execute(mut execution) =
        store.begin_operation(&ns, identity, request.clone(), clock)?
    else {
        return Err("a fresh operation identity must execute".into());
    };
    execution.tag_put(
        "operation",
        &TagUpdate::Set {
            kappa: request.clone(),
        },
    )?;
    let committed = execution.publish_result(b"operation result".to_vec())?;
    let failure = Failure::default();
    CalibratedGroup::scope(
        c,
        &format!("epoch_{}", target.label),
        |group| -> BenchResult {
            let id = osc(&format!(
                "osc:lat/store.epoch_get?state=warm&{}",
                target.read_conds()
            ))?;
            group.bench(
                s,
                &bench(id, "epoch_get", "published", None, "PERF-STO-030"),
                |iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        match failure.ok(store.epoch_get(black_box(&root))) {
                            Some(epoch) if epoch.epoch_number() == number => {}
                            Some(epoch) => {
                                failure.fail(format!(
                                    "epoch {} returned for {number}",
                                    epoch.epoch_number()
                                ));
                                break;
                            }
                            None => break,
                        }
                    }
                    start.elapsed()
                },
            )?;
            failure.check("store.epoch_get")?;
            let id = osc(&format!(
                "osc:lat/store.operation_replay?{}",
                target.read_conds()
            ))?;
            group.bench(
                s,
                &bench(id, "operation_replay", "committed", None, "PERF-STO-003"),
                |iters| {
                    let start = Instant::now();
                    for _ in 0..iters {
                        match failure.ok(store.begin_operation(
                            &ns,
                            identity,
                            request.clone(),
                            clock,
                        )) {
                            Some(OperationAdmission::Replay { epoch, receipt })
                                if epoch.kappa() == &committed.root =>
                            {
                                black_box(receipt);
                            }
                            Some(OperationAdmission::Replay { .. }) => {
                                failure.fail("replay returned a different epoch");
                                break;
                            }
                            Some(OperationAdmission::Execute(execution)) => {
                                failure.fail("a committed operation executed again");
                                failure.ok(execution.abort());
                                break;
                            }
                            None => break,
                        }
                    }
                    start.elapsed()
                },
            )?;
            failure.check("store.operation_replay")
        },
    )
}
