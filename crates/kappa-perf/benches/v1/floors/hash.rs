//! Digest floors (PERF-CAL-018, PERF-HSH-010, PERF-HSH-011, PERF-HSH-013,
//! PERF-HSH-014).
//!
//! Every content-addressing axis at 64 B through 16 MiB through the
//! production `Kappa::compute`; the same axes through the path the store's
//! ingest runs (`variant=ingest`: `IncrementalHasher` fed in
//! `BLOB_CHUNK_SIZE` chunks, as `stage_stream` feeds it); the single-pass
//! multi-axis stream that ingest uses for mandatory secondary axes, at the
//! same sizes so the validation rules can bound it by each constituent
//! axis; and SHA-256 of [`OBJECTS`] independent objects per iteration, the
//! multi-object regime a multi-buffer reference implementation is judged
//! against.

use std::hint::black_box;
use std::io::Cursor;

use criterion::Criterion;
use kappa_perf::bench::{BenchResult, Failure, Tier, bench, bytes, mag, osc, pattern, timed};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use kappa_store_redb::BLOB_CHUNK_SIZE;
use kappa_types::axis::Axis;
use kappa_types::kappa::Kappa;
use kappa_types::kappa_streaming::{IncrementalHasher, streaming_compute_multi};

const AXES: [(Axis, &str); 6] = [
    (Axis::Sha256, "sha256"),
    (Axis::Sha512, "sha512"),
    (Axis::Blake3, "blake3"),
    (Axis::Sha1, "sha1"),
    (Axis::Sha3_256, "sha3_256"),
    (Axis::Keccak256, "keccak256"),
];

/// Independent objects per iteration in the multi-object measurements: the
/// lane count of an AVX2 multi-buffer SHA-256.
pub const OBJECTS: usize = 8;

/// The objects of a multi-object measurement at `size`.
pub fn objects(size: usize) -> Vec<Vec<u8>> {
    (20u64..)
        .take(OBJECTS)
        .map(|seed| pattern(size, seed))
        .collect()
}

pub const fn sizes(tier: Tier) -> &'static [usize] {
    tier.pick(
        &[64, 64 << 10, 1 << 20],
        &[64, 256, 1 << 10, 4 << 10, 64 << 10, 1 << 20, 16 << 20],
        &[64, 256, 1 << 10, 4 << 10, 64 << 10, 1 << 20, 16 << 20],
    )
}

pub fn register(c: &mut Criterion, s: &mut CalibratedSession, tier: Tier) -> BenchResult {
    let failure = Failure::default();
    for &size in sizes(tier) {
        let data = pattern(size, 11);
        let m = mag(size);
        CalibratedGroup::scope(c, &format!("hash_{m}"), |group| -> BenchResult {
            for (axis, token) in AXES {
                let id = osc(&format!("osc:bw/hash.{token}?size={m}"))?;
                group.bench(
                    s,
                    &bench(id, token, m.clone(), bytes(size), "PERF-HSH-010"),
                    |iters| {
                        timed(iters, || {
                            black_box(failure.ok(Kappa::compute(axis, black_box(&data))));
                        })
                    },
                )?;
                failure.check(token)?;
                let id = osc(&format!("osc:bw/hash.{token}?size={m}&variant=ingest"))?;
                let function = format!("{token}_ingest");
                group.bench(
                    s,
                    &bench(id, &function, m.clone(), bytes(size), "PERF-HSH-014"),
                    |iters| {
                        timed(iters, || {
                            let mut hasher = IncrementalHasher::new(axis);
                            for chunk in black_box(&data).chunks(BLOB_CHUNK_SIZE) {
                                hasher.update(chunk);
                            }
                            black_box(failure.ok(hasher.finalize()));
                        })
                    },
                )?;
                failure.check(&function)?;
            }
            let id = osc(&format!("osc:bw/hash.multi?axes=2&size={m}"))?;
            group.bench(
                s,
                &bench(
                    id,
                    "multi_sha256_blake3",
                    m.clone(),
                    bytes(size),
                    "PERF-HSH-011",
                ),
                |iters| {
                    timed(iters, || {
                        let mut reader = Cursor::new(black_box(&data));
                        black_box(failure.ok(streaming_compute_multi(
                            &[Axis::Sha256, Axis::Blake3],
                            &mut reader,
                        )));
                    })
                },
            )?;
            failure.check("hash.multi")?;
            let batch = objects(size);
            let id = osc(&format!("osc:bw/hash.sha256?objects={OBJECTS}&size={m}"))?;
            group.bench(
                s,
                &bench(
                    id,
                    "sha256_objects",
                    m.clone(),
                    bytes(size * OBJECTS),
                    "PERF-HSH-013",
                ),
                |iters| {
                    timed(iters, || {
                        for object in &batch {
                            black_box(failure.ok(Kappa::compute(Axis::Sha256, black_box(object))));
                        }
                    })
                },
            )?;
            failure.check("hash.sha256 objects")
        })?;
    }
    Ok(())
}
