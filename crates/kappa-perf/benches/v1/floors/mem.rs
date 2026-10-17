//! Memory hierarchy floors (PERF-CAL-010, 011, 012, 014, 023).
//!
//! Sequential read, write, zero and copy bandwidth at one working set per
//! cache level; dependent-load latency by pointer chase over a random
//! single-cycle permutation with one node per cache line; allocation cost
//! fresh and reused.
//!
//! Read is a `memchr` scan for a byte the buffer never contains: memchr
//! 2.8.3 selects AVX2 or SSE2 at run time and, finding nothing, loads every
//! byte once in four full-width aligned vector loads per iteration. Its rate
//! is the core's load bandwidth whatever the build's target CPU, as the libc
//! `memcpy` behind the copy floor is. A reduction compiled from our own
//! loop is not a floor: its rate moved 3.4x between the shipping and native
//! builds of this host while the hardware stayed the same.

use std::hint::black_box;

use criterion::{Criterion, SamplingMode};
use kappa_perf::bench::{
    BenchResult, Failure, SplitMix, bench, bytes, elements, mag, osc, pattern, timed,
};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};

/// The byte the read floor scans for; [`absent_haystack`] never holds it.
const ABSENT: u8 = 0;

/// Working set per cache level of the reference hosts (H0, H1).
const LEVELS: [(usize, &str); 4] = [
    (16 << 10, "l1"),
    (256 << 10, "l2"),
    (4 << 20, "l3"),
    (64 << 20, "dram"),
];

/// Dependent loads per chase iteration.
const CHASE_STEPS: usize = 1024;

pub fn register(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    bandwidth(c, s)?;
    chase(c, s)?;
    alloc(c, s)
}

/// `size` position-dependent bytes, none of them [`ABSENT`].
fn absent_haystack(size: usize, seed: u64) -> Vec<u8> {
    pattern(size, seed)
        .into_iter()
        .map(|byte| byte | 1)
        .collect()
}

fn bandwidth(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let failure = Failure::default();
    CalibratedGroup::scope(c, "mem_bandwidth", |group| -> BenchResult {
        group.configure(|g| {
            g.sampling_mode(SamplingMode::Flat);
        });
        for (size, cache) in LEVELS {
            let haystack = absent_haystack(size, 1);
            let src = pattern(size, 2);
            let mut dst = vec![0u8; size];
            let m = mag(size);

            let id = osc(&format!(
                "osc:bw/mem.read?cache={cache}&order=sequential&size={m}"
            ))?;
            group.bench(
                s,
                &bench(id, "read", cache, bytes(size), "PERF-CAL-012"),
                |iters| {
                    timed(iters, || {
                        if let Some(at) = memchr::memchr(ABSENT, black_box(&haystack)) {
                            failure.fail(format!(
                                "read floor buffer holds byte {ABSENT} at {at}: the scan stopped before reading it all"
                            ));
                        }
                    })
                },
            )?;
            failure.check("mem.read")?;
            let id = osc(&format!("osc:bw/mem.copy?cache={cache}&size={m}"))?;
            group.bench(
                s,
                &bench(id, "copy", cache, bytes(size), "PERF-CAL-014"),
                |iters| {
                    timed(iters, || {
                        dst.copy_from_slice(black_box(&src));
                        black_box(&dst);
                    })
                },
            )?;
            let id = osc(&format!(
                "osc:bw/mem.write?cache={cache}&order=sequential&size={m}"
            ))?;
            group.bench(
                s,
                &bench(id, "write", cache, bytes(size), "PERF-CAL-012"),
                |iters| {
                    timed(iters, || {
                        dst.fill(black_box(0x5a));
                        black_box(&dst);
                    })
                },
            )?;
            let id = osc(&format!("osc:bw/mem.zero?cache={cache}&size={m}"))?;
            group.bench(
                s,
                &bench(id, "zero", cache, bytes(size), "PERF-CAL-010"),
                |iters| {
                    timed(iters, || {
                        dst.fill(black_box(0));
                        black_box(&dst);
                    })
                },
            )?;
        }
        Ok(())
    })
}

/// One 64-byte node per cache line; `next` links form a single cycle
/// (Sattolo), so every load depends on the previous one and no prefetcher
/// can predict the address.
#[derive(Clone, Copy)]
#[repr(align(64))]
struct Node {
    next: usize,
}

fn cycle(nodes: usize, seed: u64) -> Vec<Node> {
    let mut order: Vec<usize> = (0..nodes).collect();
    let mut shuffle = SplitMix(seed);
    for i in (1..nodes).rev() {
        order.swap(i, shuffle.below(i));
    }
    let mut links = vec![Node { next: 0 }; nodes];
    for (position, &node) in order.iter().enumerate() {
        links[node].next = order[(position + 1) % nodes];
    }
    links
}

fn chase(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    CalibratedGroup::scope(c, "mem_chase", |group| -> BenchResult {
        for (size, cache) in LEVELS {
            let links = cycle(size / std::mem::size_of::<Node>(), 3);
            let mut at = 0usize;
            let id = osc(&format!(
                "osc:lat/mem.chase?cache={cache}&order=random&size={}",
                mag(size)
            ))?;
            group.bench(
                s,
                &bench(id, "chase", cache, elements(CHASE_STEPS), "PERF-CAL-011"),
                |iters| {
                    timed(iters, || {
                        for _ in 0..CHASE_STEPS {
                            at = links[at].next;
                        }
                        black_box(at);
                    })
                },
            )?;
        }
        Ok(())
    })
}

fn alloc(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    CalibratedGroup::scope(c, "mem_alloc", |group| -> BenchResult {
        for size in [64usize, 4 << 10, 64 << 10, 1 << 20] {
            let m = mag(size);
            let id = osc(&format!("osc:lat/mem.alloc?alloc=fresh&size={m}"))?;
            group.bench(
                s,
                &bench(id, "fresh", m.clone(), None, "PERF-CAL-023"),
                |iters| {
                    timed(iters, || {
                        let mut buffer: Vec<u8> = Vec::with_capacity(size);
                        buffer.resize(size, 0x5a);
                        black_box(&buffer);
                    })
                },
            )?;
            let mut reused: Vec<u8> = Vec::with_capacity(size);
            let id = osc(&format!("osc:lat/mem.alloc?alloc=reuse&size={m}"))?;
            group.bench(s, &bench(id, "reuse", m, None, "PERF-CAL-023"), |iters| {
                timed(iters, || {
                    reused.clear();
                    reused.resize(size, 0x5a);
                    black_box(&reused);
                })
            })?;
        }
        Ok(())
    })
}
