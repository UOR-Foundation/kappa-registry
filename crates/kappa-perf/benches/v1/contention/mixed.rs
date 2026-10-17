//! Matched same-namespace and disjoint-namespace read/write workload curves.
//! One iteration is 30 requests, preserving exact mixes in short samples.
//! Each write request publishes 1 or 32 tags. Latency is per 30-request cycle.

use std::sync::Arc;

use criterion::{Criterion, SamplingMode};
use kappa_perf::bench::fixture::{create_ns, tag_target};
use kappa_perf::bench::{BenchResult, Failure, bench, elements, osc};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use kappa_store::{KappaStore, NamespaceRef, TagUpdate};

use crate::load::{Shared, Worker};

/// Tags request `round` of `worker` publishes under `mix`; zero is a read.
fn width(mix: &str, worker: usize, round: usize) -> usize {
    let phase = round % 10;
    match mix {
        "reads" => 0,
        "writes" => 1,
        "batches" => 32,
        "read_heavy" => usize::from(phase == 0),
        "balanced" => usize::from(phase.is_multiple_of(2)),
        "write_heavy" => usize::from(phase != 0),
        _ => match (worker + round) % 3 {
            0 => 0,
            1 => 1,
            _ => 32,
        },
    }
}

/// The worker of one `mix` curve: 30 requests per iteration against the
/// namespace the worker maps to, each read checking that namespace's
/// anchor. The first failure is recorded in `failure` and ends the worker.
fn mix_worker<S: KappaStore + 'static>(
    shared: &Shared<S>,
    namespaces: &Arc<Vec<NamespaceRef>>,
    failure: &Arc<Failure>,
    mix: &'static str,
) -> Worker {
    let (store, clock, namespaces, errors) = (
        Arc::clone(&shared.store),
        Arc::clone(&shared.clock),
        Arc::clone(namespaces),
        Arc::clone(failure),
    );
    Arc::new(move |worker, iterations| {
        let index = worker % namespaces.len();
        let ns = &namespaces[index];
        let expected = tag_target(index, 0);
        // No global serial counter on the measured hot path.
        let updates: Vec<_> = (0..32)
            .map(|item| {
                (
                    format!("worker-{worker}/{item}"),
                    TagUpdate::Set {
                        kappa: tag_target(worker, item),
                    },
                )
            })
            .collect();
        for _ in 0..iterations {
            for round in 0usize..30 {
                let width = width(mix, worker, round);
                if width == 0 {
                    match errors.ok(store.tag_get(ns, "anchor")) {
                        Some(entry) if entry.kappa == expected => {}
                        Some(_) => {
                            errors.fail("namespace anchor mismatch");
                            return;
                        }
                        None => return,
                    }
                } else {
                    let result = (|| {
                        let mut execution = store.begin_execution(ns, &*clock)?;
                        execution.tag_batch_update(&updates[..width])?;
                        execution.publish()?;
                        Ok::<_, kappa_store::StoreError>(())
                    })();
                    if errors.ok(result).is_none() {
                        return;
                    }
                }
            }
        }
    })
}

pub fn register<S: KappaStore + 'static>(
    criterion: &mut Criterion,
    session: &mut CalibratedSession,
    threads: &[usize],
    shared: &Shared<S>,
) -> BenchResult {
    let widest = threads.iter().copied().max().ok_or("no thread counts")?;
    CalibratedGroup::scope(
        criterion,
        &format!("namespace_mix_{}", shared.backend),
        |group| -> BenchResult {
            group.configure(|group| {
                group.sampling_mode(SamplingMode::Flat);
            });
            for layout in ["shared", "disjoint"] {
                for mix in [
                    "reads",
                    "writes",
                    "batches",
                    "read_heavy",
                    "balanced",
                    "write_heavy",
                    "heterogeneous",
                ] {
                    // Separate data per curve family: preceding workloads do not
                    // leave different tag populations in the two layout baselines.
                    let namespaces = (0..if layout == "shared" { 1 } else { widest })
                        .map(|index| {
                            create_ns(
                                shared.store.as_ref(),
                                &shared.clock,
                                &format!("mix-{layout}-{mix}-{index}"),
                            )
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    for (index, ns) in namespaces.iter().enumerate() {
                        let mut execution = shared.store.begin_execution(ns, &*shared.clock)?;
                        execution.tag_put(
                            "anchor",
                            &TagUpdate::Set {
                                kappa: tag_target(index, 0),
                            },
                        )?;
                        execution.publish()?;
                    }
                    let namespaces = Arc::new(namespaces);
                    for &count in threads {
                        let failure = Arc::new(Failure::default());
                        let worker = mix_worker(shared, &namespaces, &failure, mix);
                        let variant = format!("{layout}_{mix}");
                        let operation = match mix {
                            "reads" => "store.tag_get",
                            "writes" | "batches" => "store.publish",
                            _ => "store.publish+store.tag_get",
                        };
                        let id = osc(&format!(
                            "osc:ops/{operation}?threads={count}t&variant={variant}&{}",
                            shared.write_conds()
                        ))?;
                        group.bench_contended(
                            session,
                            &bench(
                                id,
                                &variant,
                                count.to_string(),
                                elements(30),
                                "PERF-CON-013",
                            ),
                            count,
                            &worker,
                        )?;
                        failure.check(&variant)?;
                    }
                }
            }
            Ok(())
        },
    )
}
