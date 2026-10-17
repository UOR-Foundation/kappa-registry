//! Transaction staging workloads (PERF-STO-007).
//!
//! `txn.put` stages prepared content as a member of a transaction resource,
//! one epoch per put; `txn.promote` ends a staged set inside an execution.

use std::time::{Duration, Instant};

use criterion::{Criterion, SamplingMode};
use kappa_handler::clock::{Clock, WallClock};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use kappa_store::resource;
use kappa_store::{
    Axis, ContentIdentity, Kappa, KappaStore, NamespaceRef, PreparationBounds, ResourceKind,
};

use kappa_perf::bench::fixture::{Target, create_ns, stamp};
use kappa_perf::bench::{BenchResult, Failure, Tier, bench, bytes, elements, mag, osc, pattern};

/// Blobs staged per promoted transaction.
const PROMOTE_BLOBS: usize = 16;
/// Per-transaction staging limit of the measured transactions.
const TXN_BYTES: u64 = 1 << 30;

fn asserter() -> Kappa {
    Kappa::sha256(b"history")
}

fn bounds() -> PreparationBounds {
    PreparationBounds {
        maximum: TXN_BYTES,
        deadline: Instant::now() + Duration::from_secs(600),
    }
}

/// Open a transaction resource in `ns` with the measured byte limit.
fn begin<S: KappaStore>(
    store: &S,
    clock: &WallClock,
    ns: &NamespaceRef,
) -> Result<String, Box<dyn std::error::Error>> {
    let expires_at = clock.now()?.add_physical_ms(3600 * 1000);
    let mut execution = store.begin_execution(ns, clock)?;
    let head = resource::open(
        &mut *execution,
        &asserter(),
        ResourceKind::Membership,
        TXN_BYTES,
        expires_at,
        None,
    )?;
    execution.publish()?;
    Ok(head.id())
}

/// Discard the transaction `id` in its own epoch.
fn abort<S: KappaStore>(
    store: &S,
    clock: &WallClock,
    ns: &NamespaceRef,
    id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut execution = store.begin_execution(ns, clock)?;
    resource::discard(&mut *execution, &asserter(), id)?;
    execution.publish()?;
    Ok(())
}

/// Prepare `data` under its verified identity and stage it as a member of
/// `id` in one published epoch, as `PUT /_transaction/{id}/{kappa}` does.
/// Returns whether the content was newly installed.
fn put<S: KappaStore>(
    store: &S,
    clock: &WallClock,
    ns: &NamespaceRef,
    id: &str,
    identity: &Kappa,
    data: &[u8],
) -> Result<bool, Box<dyn std::error::Error>> {
    let prepared = store.prepare_content(
        ContentIdentity::Verified(identity.clone()),
        &mut &data[..],
        bounds(),
    )?;
    let mut execution = store.begin_execution(ns, clock)?;
    let (_, installed) = resource::stage(&mut *execution, &asserter(), id, prepared, 0, None)?;
    execution.publish()?;
    Ok(installed.newly_stored)
}

pub fn staging<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    target: &Target<'_, S>,
) -> BenchResult {
    let store = target.store;
    let ns = create_ns(store, clock, "staging")?;
    let failure = Failure::default();
    let mut txn = begin(store, clock, &ns)?;
    let mut staged = 0u64;
    let mut serial = 1u64 << 48;
    let measured = CalibratedGroup::scope(
        c,
        &format!("txn_put_{}", target.label),
        |group| -> BenchResult {
            group.configure(|g| {
                g.sampling_mode(SamplingMode::Flat);
            });
            for &size in tier.storage_sizes() {
                let m = mag(size);
                let mut data = pattern(size, 51);
                let id = osc(&format!(
                    "osc:bw/txn.put?axis=sha256&size={m}&{}",
                    target.write_conds()
                ))?;
                group.bench(
                    s,
                    &bench(id, "durable", m.clone(), bytes(size), "PERF-STO-007"),
                    |iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            if staged + size as u64 > TXN_BYTES / 2 {
                                if failure.ok(abort(store, clock, &ns, &txn)).is_none() {
                                    break;
                                }
                                let Some(next) = failure.ok(begin(store, clock, &ns)) else {
                                    break;
                                };
                                txn = next;
                                staged = 0;
                            }
                            serial += 1;
                            stamp(&mut data, serial);
                            let Some(identity) = failure.ok(Kappa::compute(Axis::Sha256, &data))
                            else {
                                break;
                            };
                            let start = Instant::now();
                            let newly = failure.ok(put(store, clock, &ns, &txn, &identity, &data));
                            total += start.elapsed();
                            match newly {
                                Some(true) => staged += size as u64,
                                Some(false) => {
                                    failure.fail("distinct content reported as already staged");
                                    break;
                                }
                                None => break,
                            }
                        }
                        total
                    },
                )?;
                failure.check("txn.put")?;
            }
            Ok(())
        },
    );
    // The open transaction is released whatever the measurement's outcome.
    abort(store, clock, &ns, &txn)?;
    measured
}

pub fn promotion<S: KappaStore>(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    tier: Tier,
    clock: &WallClock,
    target: &Target<'_, S>,
) -> BenchResult {
    let store = target.store;
    let ns = create_ns(store, clock, "promote")?;
    let failure = Failure::default();
    let mut serial = 1u64 << 56;
    CalibratedGroup::scope(
        c,
        &format!("txn_promote_{}", target.label),
        |group| -> BenchResult {
            group.configure(|g| {
                g.sampling_mode(SamplingMode::Flat);
            });
            for &size in tier.pick(
                &[64usize << 10][..],
                &[4 << 10, 64 << 10][..],
                &[4 << 10, 64 << 10, 1 << 20][..],
            ) {
                let m = mag(size);
                let mut data = pattern(size, 52);
                let id = osc(&format!(
                    "osc:lat/txn.promote?backend={}&size={m}",
                    target.backend
                ))?;
                group.bench(
                    s,
                    &bench(
                        id,
                        "into_execution",
                        m.clone(),
                        elements(PROMOTE_BLOBS),
                        "PERF-STO-007",
                    ),
                    |iters| {
                        let mut total = Duration::ZERO;
                        for _ in 0..iters {
                            let staged = (|| -> Result<String, Box<dyn std::error::Error>> {
                                let txn = begin(store, clock, &ns)?;
                                for _ in 0..PROMOTE_BLOBS {
                                    serial += 1;
                                    stamp(&mut data, serial);
                                    let identity = Kappa::compute(Axis::Sha256, &data)?;
                                    put(store, clock, &ns, &txn, &identity, &data)?;
                                }
                                Ok(txn)
                            })();
                            let Some(txn) = failure.ok(staged) else {
                                break;
                            };
                            let Some(mut execution) = failure.ok(store.begin_execution(&ns, clock))
                            else {
                                break;
                            };
                            // The commit's work: read the committed membership
                            // through the execution and end the transaction.
                            let start = Instant::now();
                            let promoted =
                                failure.ok((|| -> Result<usize, kappa_store::StoreError> {
                                    let resolved = resource::resolve_in(&*execution, &txn)?
                                        .ok_or_else(|| {
                                            kappa_store::StoreError::NotFound(txn.clone())
                                        })?;
                                    let members =
                                        resource::members_in(&*execution, &resolved.head)?;
                                    resource::discard(&mut *execution, &asserter(), &txn)?;
                                    Ok(members.len())
                                })());
                            total += start.elapsed();
                            if failure.ok(execution.abort()).is_none()
                                || failure.ok(abort(store, clock, &ns, &txn)).is_none()
                            {
                                break;
                            }
                            match promoted {
                                Some(count) if count == PROMOTE_BLOBS => {}
                                Some(count) => {
                                    failure.fail(format!(
                                        "promoted {count} of {PROMOTE_BLOBS} staged blobs"
                                    ));
                                    break;
                                }
                                None => break,
                            }
                        }
                        total
                    },
                )?;
                failure.check("txn.promote")?;
            }
            Ok(())
        },
    )
}
