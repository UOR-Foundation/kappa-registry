//! Graph and object-assembly workloads (PERF-DST-002, PERF-EPO-025,
//! PERF-S3-004): edge queries by fan-out and staged-resource completion.
//!
//! Edge queries return one full page of a published fan-out and verify
//! every edge is present. Completion streams the frozen generation of a
//! numbered resource through the store, verifying every member, and
//! installs the composite from that evidence into an execution that is
//! aborted, so the resource stays prepared and every sample completes the
//! same generation.

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{Criterion, SamplingMode};
use kappa_handler::clock::{Clock, WallClock};
use kappa_perf::bench::fixture::{POPULATE_BATCH, Target, create_ns, tag_target};
use kappa_perf::bench::{BenchResult, Failure, Tier, bench, bytes, mag, osc, pattern};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use kappa_store::resource;
use kappa_store::{
    Axis, BuiltinRelation, ContentIdentity, Direction, EdgeInput, EdgeQuery, EdgeRelation, Kappa,
    KappaStore, NamespaceRef, PageRequest, PreparationBounds, ResourceKind,
};

/// S3's minimum size of a nonfinal part.
const MIN_NONFINAL_PART_SIZE: usize = 5 * 1024 * 1024;

const fn fanouts(tier: Tier) -> &'static [usize] {
    tier.pick(&[100], &[1, 100, 10_000], &[1, 100, 10_000, 100_000])
}

const fn part_counts(tier: Tier) -> &'static [usize] {
    tier.pick(&[2], &[2, 4], &[2, 4, 16])
}

fn asserter() -> Kappa {
    Kappa::sha256(b"workloads")
}

pub fn register<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    target: &Target<'_, S>,
) -> BenchResult {
    edges(c, s, tier, clock, target)?;
    completion(c, s, tier, clock, target)
}

/// Publish `fanout` outbound `Owns` edges from `anchor`.
fn publish_edges<S: KappaStore>(
    store: &S,
    clock: &WallClock,
    ns: &NamespaceRef,
    anchor: &Kappa,
    fanout: usize,
) -> BenchResult {
    let created_at_ms = i64::try_from(clock.now()?.physical_ms())?;
    let mut first = 0usize;
    while first < fanout {
        let last = (first + POPULATE_BATCH).min(fanout);
        let inputs: Vec<EdgeInput> = (first..last)
            .map(|i| EdgeInput {
                source: anchor.clone(),
                target: tag_target(i, fanout as u64),
                relation: EdgeRelation::Builtin(BuiltinRelation::Owns),
                asserter: anchor.clone(),
                created_at_ms,
                metadata: None,
            })
            .collect();
        let mut execution = store.begin_execution(ns, clock)?;
        execution.edge_put_batch(&inputs)?;
        execution.publish()?;
        first = last;
    }
    Ok(())
}

fn edges<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    target: &Target<'_, S>,
) -> BenchResult {
    let store = target.store;
    let ns = create_ns(store, clock, "edges")?;
    let failure = Failure::default();
    CalibratedGroup::scope(
        c,
        &format!("edge_query_{}", target.label),
        |group| -> BenchResult {
            for &fanout in fanouts(tier) {
                let anchor = Kappa::sha256(format!("edge anchor {fanout}").as_bytes());
                publish_edges(store, clock, &ns, &anchor, fanout)?;
                let query = EdgeQuery {
                    anchor,
                    direction: Direction::Outbound,
                    relation: Some(EdgeRelation::Builtin(BuiltinRelation::Owns)),
                    asserter: None,
                };
                let page = PageRequest::first(fanout);
                let id = osc(&format!(
                    "osc:lat/store.edge_query?fanout={fanout}&{}",
                    target.read_conds()
                ))?;
                group.bench(
                    s,
                    &bench(id, "outbound", fanout.to_string(), None, "PERF-DST-002"),
                    |iters| {
                        let start = Instant::now();
                        for _ in 0..iters {
                            match failure.ok(store.edge_query(&ns, black_box(&query), &page)) {
                                Some(result)
                                    if result.items.len() == fanout
                                        && result.next_after.is_none() =>
                                {
                                    black_box(result);
                                }
                                Some(result) => {
                                    failure.fail(format!(
                                        "query returned {} of {fanout} edges",
                                        result.items.len()
                                    ));
                                    break;
                                }
                                None => break,
                            }
                        }
                        start.elapsed()
                    },
                )?;
                failure.check("store.edge_query")?;
            }
            Ok(())
        },
    )
}

/// Open a numbered resource holding `parts` members and freeze its
/// selection for one request. Returns the resource id and the generation.
fn staged<S: KappaStore>(
    store: &S,
    clock: &WallClock,
    ns: &NamespaceRef,
    parts: usize,
    full_part: usize,
    final_part: usize,
) -> Result<(String, Kappa, Vec<u64>), Box<dyn std::error::Error>> {
    let now = clock.now()?;
    let mut execution = store.begin_execution(ns, clock)?;
    let head = resource::open(
        &mut *execution,
        &asserter(),
        ResourceKind::Numbered,
        0,
        now.add_physical_ms(24 * 3600 * 1000),
        None,
    )?;
    execution.publish()?;
    let id = head.id();
    let mut selected = Vec::with_capacity(parts);
    for number in 1..=parts {
        let data = pattern(
            if number == parts {
                final_part
            } else {
                full_part
            },
            40 + number as u64,
        );
        let prepared = store.prepare_content(
            ContentIdentity::Computed(Axis::Sha256),
            &mut data.as_slice(),
            PreparationBounds {
                maximum: u64::MAX,
                deadline: Instant::now() + Duration::from_secs(600),
            },
        )?;
        let mut execution = store.begin_execution(ns, clock)?;
        resource::stage(
            &mut *execution,
            &asserter(),
            &id,
            prepared,
            number as u64,
            None,
        )?;
        execution.publish()?;
        selected.push(number as u64);
    }
    let request = Kappa::sha256(format!("complete {parts}").as_bytes());
    let mut execution = store.begin_execution(ns, clock)?;
    let generation =
        resource::prepare(&mut *execution, &asserter(), &id, &request, &selected)?.generation;
    execution.publish()?;
    Ok((id, generation, selected))
}

fn completion<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    target: &Target<'_, S>,
) -> BenchResult {
    let store = target.store;
    let ns = create_ns(store, clock, "multipart")?;
    let full_part = MIN_NONFINAL_PART_SIZE;
    let final_part = 1 << 20;
    let failure = Failure::default();
    CalibratedGroup::scope(
        c,
        &format!("multipart_{}", target.label),
        |group| -> BenchResult {
            group.configure(|g| {
                g.sampling_mode(SamplingMode::Flat);
            });
            for &parts in part_counts(tier) {
                let total = (parts - 1) * full_part + final_part;
                let (id, generation, _) = staged(store, clock, &ns, parts, full_part, final_part)?;
                let bench_id = osc(&format!(
                    "osc:bw/store.multipart_complete?parts={parts}&size={}&{}",
                    mag(total),
                    target.read_conds()
                ))?;
                group.bench(
                    s,
                    &bench(
                        bench_id,
                        "complete",
                        parts.to_string(),
                        bytes(total),
                        "PERF-S3-004",
                    ),
                    |iters| {
                        let mut elapsed = Duration::ZERO;
                        for _ in 0..iters {
                            let start = Instant::now();
                            let evidence = failure.ok(resource::prepare_composition(
                                store,
                                &ns,
                                &id,
                                &generation,
                                Axis::Sha256,
                                Instant::now() + Duration::from_secs(600),
                            ));
                            let Some(evidence) = evidence else { break };
                            let Some(mut execution) = failure.ok(store.begin_execution(&ns, clock))
                            else {
                                break;
                            };
                            let completed = failure.ok(resource::complete(
                                &mut *execution,
                                &asserter(),
                                &id,
                                &evidence,
                                None,
                            ));
                            elapsed += start.elapsed();
                            // The composite is discarded with the execution;
                            // the resource stays prepared for the next sample.
                            if failure.ok(execution.abort()).is_none() {
                                break;
                            }
                            let Some(completed) = completed else { break };
                            if completed.installed.kappa != *evidence.identity() {
                                failure.fail("completion installed another identity");
                                break;
                            }
                        }
                        elapsed
                    },
                )?;
                failure.check("store.multipart_complete")?;
                let mut execution = store.begin_execution(&ns, clock)?;
                resource::discard(&mut *execution, &asserter(), &id)?;
                execution.publish()?;
            }
            Ok(())
        },
    )
}
