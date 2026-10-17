//! Device floors: the persistent datapath (PERF-CAL-015, 016, 017).
//!
//! All measurements run against one preallocated file in `device_dir()`,
//! whose filesystem is attached to every record. Writes are measured
//! buffered (`durability=none`, the page-cache path the memory store's
//! blob cache takes) and durable (`durability=immediate`, write plus
//! `fdatasync` per operation, the path a durable commit takes). Cold reads
//! drop the file's pages with `POSIX_FADV_DONTNEED` outside the timed
//! region, so they reach the device; warm reads are served by the page
//! cache. fsync and fdatasync are recorded as full latency distributions.

use std::fs::{File, OpenOptions};
use std::hint::black_box;
use std::num::NonZeroU64;
use std::os::unix::fs::FileExt;
use std::time::{Duration, Instant};

use criterion::{Criterion, SamplingMode};
use kappa_perf::bench::{
    BenchResult, Failure, SplitMix, Tier, bench, bytes, device_dir, mag, osc, pattern,
};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession, LatencyHistogram};
use rustix::fs::{Advice, fadvise};

const BLOCK: usize = 4 << 10;
/// Samples per sync-latency distribution, after `SYNC_WARMUP` discarded.
const SYNC_SAMPLES: usize = 2_000;
const SYNC_WARMUP: usize = 100;

pub struct Device {
    file: File,
    len: usize,
}

impl Device {
    /// Create and fill the measurement file, durably, before any timing.
    pub fn prepare(tier: Tier) -> Result<Self, Box<dyn std::error::Error>> {
        let len = tier.pick(64usize << 20, 256 << 20, 1 << 30);
        let path = device_dir()?.join("floors.dat");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        let chunk = pattern(1 << 20, 4);
        let mut offset = 0;
        while offset < len {
            file.write_all_at(&chunk, u64::try_from(offset)?)?;
            offset += chunk.len();
        }
        file.sync_all()?;
        Ok(Self { file, len })
    }

    fn drop_cache(&self) -> rustix::io::Result<()> {
        fadvise(&self.file, 0, None::<NonZeroU64>, Advice::DontNeed)
    }

    const fn slots(&self, size: usize) -> usize {
        self.len / size
    }
}

pub fn register(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    device: &Device,
    tier: Tier,
) -> BenchResult {
    writes(c, s, device, tier)?;
    reads(c, s, device, tier)?;
    syncs(s, device)
}

fn writes(
    c: &mut Criterion,
    s: &mut CalibratedSession,
    device: &Device,
    tier: Tier,
) -> BenchResult {
    let failure = Failure::default();
    CalibratedGroup::scope(c, "device_write", |group| -> BenchResult {
        group.configure(|g| {
            g.sampling_mode(SamplingMode::Flat);
        });
        for &size in tier.storage_sizes() {
            let data = pattern(size, 5);
            let m = mag(size);
            for durability in ["none", "immediate"] {
                let durable = durability == "immediate";
                let mut slot = 0usize;
                let id = osc(&format!(
                    "osc:bw/device.seq_write?durability={durability}&order=sequential&size={m}"
                ))?;
                group.bench(
                    s,
                    &bench(id, durability, m.clone(), bytes(size), "PERF-CAL-015"),
                    |iters| {
                        let start = Instant::now();
                        for _ in 0..iters {
                            let offset = (slot % device.slots(size)) * size;
                            slot += 1;
                            let written =
                                failure.ok(device.file.write_all_at(&data, offset as u64));
                            if written.is_none()
                                || (durable && failure.ok(device.file.sync_data()).is_none())
                            {
                                break;
                            }
                        }
                        start.elapsed()
                    },
                )?;
                failure.check("device.seq_write")?;
            }
        }
        let data = pattern(BLOCK, 6);
        let mut rng = SplitMix(7);
        let id = osc(&format!(
            "osc:bw/device.rand_write?durability=immediate&order=random&qd=1&size={}",
            mag(BLOCK)
        ))?;
        group.bench(
            s,
            &bench(
                id,
                "rand_immediate",
                mag(BLOCK),
                bytes(BLOCK),
                "PERF-CAL-016",
            ),
            |iters| {
                let start = Instant::now();
                for _ in 0..iters {
                    let offset = rng.below(device.slots(BLOCK)) * BLOCK;
                    if failure
                        .ok(device.file.write_all_at(&data, offset as u64))
                        .is_none()
                        || failure.ok(device.file.sync_data()).is_none()
                    {
                        break;
                    }
                }
                start.elapsed()
            },
        )?;
        failure.check("device.rand_write")
    })
}

/// Time `iters` reads chosen by `next_slot`. Cold runs drop the page cache
/// before the first read and again whenever a quarter of the file has been
/// read, with the clock paused, so repeated offsets are never cache hits.
fn timed_reads(
    device: &Device,
    failure: &Failure,
    size: usize,
    cold: bool,
    iters: u64,
    buffer: &mut [u8],
    mut next_slot: impl FnMut() -> usize,
) -> Duration {
    let refresh = (device.slots(size) / 4).max(1);
    let mut total = Duration::ZERO;
    let mut done = 0u64;
    while done < iters && !failure.failed() {
        if cold && failure.ok(device.drop_cache()).is_none() {
            break;
        }
        let batch = (iters - done).min(refresh as u64);
        let start = Instant::now();
        for _ in 0..batch {
            let offset = next_slot() * size;
            if failure
                .ok(device.file.read_exact_at(buffer, offset as u64))
                .is_none()
            {
                break;
            }
            black_box(&buffer[0]);
        }
        total += start.elapsed();
        done += batch;
    }
    total
}

fn reads(c: &mut Criterion, s: &mut CalibratedSession, device: &Device, tier: Tier) -> BenchResult {
    let failure = Failure::default();
    CalibratedGroup::scope(c, "device_read", |group| -> BenchResult {
        group.configure(|g| {
            g.sampling_mode(SamplingMode::Flat);
        });
        for &size in tier.storage_sizes() {
            let m = mag(size);
            let mut buffer = vec![0u8; size];
            for state in ["cold", "warm"] {
                let cold = state == "cold";
                let mut slot = 0usize;
                let slots = device.slots(size);
                let id = osc(&format!(
                    "osc:bw/device.seq_read?order=sequential&qd=1&size={m}&state={state}"
                ))?;
                group.bench(
                    s,
                    &bench(id, state, m.clone(), bytes(size), "PERF-CAL-015"),
                    |iters| {
                        timed_reads(device, &failure, size, cold, iters, &mut buffer, || {
                            slot = (slot + 1) % slots;
                            slot
                        })
                    },
                )?;
                failure.check("device.seq_read")?;
            }
        }
        let mut buffer = vec![0u8; BLOCK];
        let mut rng = SplitMix(8);
        let slots = device.slots(BLOCK);
        let id = osc(&format!(
            "osc:bw/device.rand_read?order=random&qd=1&size={}&state=cold",
            mag(BLOCK)
        ))?;
        group.bench(
            s,
            &bench(id, "rand_cold", mag(BLOCK), bytes(BLOCK), "PERF-CAL-016"),
            |iters| {
                timed_reads(device, &failure, BLOCK, true, iters, &mut buffer, || {
                    rng.below(slots)
                })
            },
        )?;
        failure.check("device.rand_read")
    })
}

/// fsync and fdatasync of one dirtied 4 KiB block, as distributions.
fn syncs(s: &mut CalibratedSession, device: &Device) -> BenchResult {
    let data = pattern(BLOCK, 9);
    for (operation, full) in [("device.fsync", true), ("device.fdatasync", false)] {
        let id = osc(&format!("osc:lat/{operation}?size={}", mag(BLOCK)))?;
        if let Err(skip) = s.check_deps(&id) {
            s.skip(skip);
            continue;
        }
        let mut histogram = LatencyHistogram::new()?;
        let mut rng = SplitMix(10);
        for sample in 0..SYNC_WARMUP + SYNC_SAMPLES {
            let offset = rng.below(device.slots(BLOCK)) * BLOCK;
            device.file.write_all_at(&data, offset as u64)?;
            let start = Instant::now();
            if full {
                device.file.sync_all()?;
            } else {
                device.file.sync_data()?;
            }
            let elapsed = start.elapsed();
            if sample >= SYNC_WARMUP {
                histogram.record_duration(elapsed)?;
            }
        }
        s.record_histogram(&id, &histogram, None, Some("PERF-CAL-017"))?;
    }
    Ok(())
}
