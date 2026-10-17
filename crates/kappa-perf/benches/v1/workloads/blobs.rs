//! Content write and read workloads (PERF-STO-023, PERF-STO-024,
//! PERF-STO-026, PERF-HSH-014, PERF-HSH-015, PERF-HSH-016).
//!
//! `store.blob_put` is the record path: digest the owned bytes under one
//! axis and write the verified record into an execution's private view;
//! the execution is aborted outside the timed region, so nothing
//! accumulates in the committed store. `store.ingest` is content
//! preparation: stream the bytes, hash them under the requested axis and
//! every mandatory axis, and place the durable representation; the
//! prepared value is dropped outside the timed region, which releases it.
//! Every write is distinct content (a serial stamped into the buffer), so
//! no write is a deduplicated no-op. Reads run warm against one published
//! blob per size: whole object, whole object verified, and 4 KiB ranges at
//! random aligned offsets of the largest object.

use std::hint::black_box;
use std::time::{Duration, Instant};

use criterion::{Criterion, SamplingMode};
use kappa_handler::clock::WallClock;
use kappa_perf::bench::fixture::{Target, create_ns, stamp};
use kappa_perf::bench::{BenchResult, Failure, SplitMix, Tier, bench, bytes, mag, osc, pattern};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use kappa_store::{
    Axis, ContentIdentity, Kappa, KappaStore, NamespaceRef, PreparationBounds, VerifiedContent,
};

const RANGE: usize = 4 << 10;

/// Records installed per aborted execution while measuring puts.
const PUT_BATCH: u64 = 256;

const AXES: [(Axis, &str); 6] = [
    (Axis::Sha256, "sha256"),
    (Axis::Blake3, "blake3"),
    (Axis::Sha512, "sha512"),
    (Axis::Sha1, "sha1"),
    (Axis::Sha3_256, "sha3_256"),
    (Axis::Keccak256, "keccak256"),
];

/// Axes of single-axis puts: SHA-256 alone at smoke, then the internal
/// BLAKE3 axis, then every axis.
fn put_axes(tier: Tier) -> &'static [(Axis, &'static str)] {
    tier.pick(&AXES[..1], &AXES[..2], &AXES[..])
}

/// Axes of ingest: SHA-256 stores one axis, every other axis also stores
/// the mandatory SHA-256 secondary, so both shapes run at every tier.
fn ingest_axes(tier: Tier) -> &'static [(Axis, &'static str)] {
    tier.pick(&AXES[..2], &AXES[..2], &AXES[..])
}

fn bounds() -> PreparationBounds {
    PreparationBounds {
        maximum: u64::MAX,
        deadline: Instant::now() + Duration::from_secs(600),
    }
}

pub fn register<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    target: &Target<'_, S>,
) -> BenchResult {
    let ns = create_ns(target.store, clock, "blobs")?;
    puts(c, s, tier, clock, &ns, target)?;
    ingests(c, s, tier, target)?;
    reads(c, s, tier, clock, &ns, target)
}

fn puts<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    ns: &NamespaceRef,
    target: &Target<'_, S>,
) -> BenchResult {
    let store = target.store;
    let failure = Failure::default();
    let mut serial = 0u64;
    CalibratedGroup::scope(
        c,
        &format!("blob_put_{}", target.label),
        |group| -> BenchResult {
            group.configure(|g| {
                g.sampling_mode(SamplingMode::Flat);
            });
            for &size in tier.storage_sizes() {
                let m = mag(size);
                let mut data = pattern(size, 20);
                for &(axis, token) in put_axes(tier) {
                    let id = osc(&format!(
                        "osc:bw/store.blob_put?axis={token}&size={m}&{}",
                        target.write_conds()
                    ))?;
                    group.bench(
                        s,
                        &bench(id, token, m.clone(), bytes(size), "PERF-STO-023"),
                        |iters| {
                            let mut total = Duration::ZERO;
                            let mut remaining = iters;
                            'batches: while remaining > 0 {
                                let batch = remaining.min(PUT_BATCH);
                                let Some(mut execution) =
                                    failure.ok(store.begin_execution(ns, clock))
                                else {
                                    break;
                                };
                                for _ in 0..batch {
                                    serial += 1;
                                    stamp(&mut data, serial);
                                    let owned = data.clone();
                                    let start = Instant::now();
                                    let Some(verified) =
                                        failure.ok(VerifiedContent::compute_owned(axis, owned))
                                    else {
                                        break 'batches;
                                    };
                                    let stored = failure.ok(execution.blob_put(&verified));
                                    total += start.elapsed();
                                    match stored {
                                        Some(true) => {}
                                        Some(false) => {
                                            failure.fail(
                                                "distinct content reported as already stored",
                                            );
                                            break 'batches;
                                        }
                                        None => break 'batches,
                                    }
                                }
                                // The private records are discarded with
                                // the execution; nothing publishes.
                                if failure.ok(execution.abort()).is_none() {
                                    break;
                                }
                                remaining -= batch;
                            }
                            total
                        },
                    )?;
                    failure.check("store.blob_put")?;
                }
            }
            Ok(())
        },
    )
}

fn ingests<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    tier: Tier,
    target: &Target<'_, S>,
) -> BenchResult {
    let store = target.store;
    let mandatory = store.mandatory_axes();
    let failure = Failure::default();
    let mut serial = 1u64 << 40;
    CalibratedGroup::scope(
        c,
        &format!("ingest_{}", target.label),
        |group| -> BenchResult {
            group.configure(|g| {
                g.sampling_mode(SamplingMode::Flat);
            });
            for &size in tier.storage_sizes() {
                let m = mag(size);
                let mut data = pattern(size, 21);
                for &(axis, token) in ingest_axes(tier) {
                    let stored_axes = 1 + mandatory
                        .iter()
                        .filter(|secondary| **secondary != axis)
                        .count();
                    let id = osc(&format!(
                        "osc:bw/store.ingest?axes={stored_axes}&axis={token}&size={m}&{}",
                        target.write_conds()
                    ))?;
                    group.bench(
                        s,
                        &bench(id, token, m.clone(), bytes(size), "PERF-HSH-016"),
                        |iters| {
                            let mut total = Duration::ZERO;
                            for _ in 0..iters {
                                serial += 1;
                                stamp(&mut data, serial);
                                let start = Instant::now();
                                let prepared = failure.ok(store.prepare_content(
                                    ContentIdentity::Computed(axis),
                                    &mut black_box(data.as_slice()),
                                    bounds(),
                                ));
                                total += start.elapsed();
                                let Some(prepared) = prepared else { break };
                                if prepared.aliases().len() + 1 != stored_axes
                                    || prepared.total_size() != size as u64
                                {
                                    failure.fail(format!(
                                        "preparation produced {} axes, expected {stored_axes}",
                                        prepared.aliases().len() + 1
                                    ));
                                    break;
                                }
                                // Dropping the prepared value releases its
                                // representation; nothing is installed.
                                drop(prepared);
                            }
                            total
                        },
                    )?;
                    failure.check("store.ingest")?;
                }
            }
            Ok(())
        },
    )
}

/// Read `identity` with `read` until `iters` reads are done or one fails;
/// every read must return `expected` bytes.
fn read_loop(
    failure: &Failure,
    iters: u64,
    expected: usize,
    what: &str,
    mut read: impl FnMut() -> Result<Vec<u8>, kappa_store::StoreError>,
) -> Duration {
    let start = Instant::now();
    for _ in 0..iters {
        match failure.ok(read()) {
            Some(content) if content.len() == expected => {
                black_box(content);
            }
            Some(content) => {
                failure.fail(format!(
                    "{what} returned {} of {expected} bytes",
                    content.len()
                ));
                break;
            }
            None => break,
        }
    }
    start.elapsed()
}

/// Prepare and publish `content` as a warm read target.
fn published<S: KappaStore>(
    store: &S,
    clock: &WallClock,
    ns: &NamespaceRef,
    content: &[u8],
) -> Result<Kappa, Box<dyn std::error::Error>> {
    let prepared = store.prepare_content(
        ContentIdentity::Computed(Axis::Sha256),
        &mut &content[..],
        bounds(),
    )?;
    let mut execution = store.begin_execution(ns, clock)?;
    let installed = execution.content_install(prepared)?;
    execution.publish()?;
    Ok(installed.kappa)
}

fn reads<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    ns: &NamespaceRef,
    target: &Target<'_, S>,
) -> BenchResult {
    let store = target.store;
    let failure = Failure::default();
    CalibratedGroup::scope(
        c,
        &format!("blob_read_{}", target.label),
        |group| -> BenchResult {
            let mut largest: Option<(Kappa, usize)> = None;
            for &size in tier.storage_sizes() {
                let m = mag(size);
                let identity = published(store, clock, ns, &pattern(size, 22))?;
                let conds = format!("axis=sha256&size={m}&state=warm&{}", target.read_conds());
                let id = osc(&format!("osc:bw/store.blob_get?{conds}"))?;
                group.bench(
                    s,
                    &bench(id, "get", m.clone(), bytes(size), "PERF-STO-024"),
                    |iters| {
                        read_loop(&failure, iters, size, "blob_get", || {
                            store.blob_get(black_box(&identity))
                        })
                    },
                )?;
                failure.check("store.blob_get")?;
                let id = osc(&format!("osc:bw/store.blob_get_verified?{conds}"))?;
                group.bench(
                    s,
                    &bench(id, "get_verified", m.clone(), bytes(size), "PERF-HSH-015"),
                    |iters| {
                        read_loop(&failure, iters, size, "blob_get_verified", || {
                            store.blob_get_verified(black_box(&identity))
                        })
                    },
                )?;
                failure.check("store.blob_get_verified")?;
                largest = Some((identity, size));
            }
            let (identity, size) = largest.ok_or("no storage sizes for this tier")?;
            let slots = size / RANGE;
            let mut rng = SplitMix(23);
            let id = osc(&format!(
                "osc:bw/store.blob_get_range?order=random&size={}&state=warm&{}",
                mag(RANGE),
                target.read_conds()
            ))?;
            group.bench(
                s,
                &bench(
                    id,
                    "range",
                    format!("{}_of_{}", mag(RANGE), mag(size)),
                    bytes(RANGE),
                    "PERF-STO-024",
                ),
                |iters| {
                    read_loop(&failure, iters, RANGE, "blob_get_range", || {
                        store.blob_get_range(
                            &identity,
                            (rng.below(slots) * RANGE) as u64,
                            RANGE as u64,
                        )
                    })
                },
            )?;
            failure.check("store.blob_get_range")
        },
    )
}
