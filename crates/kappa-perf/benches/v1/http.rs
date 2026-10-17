//! Open-loop HTTP load against the assembled kappa-registry server, recorded
//! to `calibration_http.jsonl` and validated and graded against the same
//! host's floors.
//!
//! The server is exactly what the binary serves (`kappa_server::app`,
//! accepting through `kappa_server::listener`), in this process on its own
//! runtime and a loopback port; the load generator runs on a separate
//! two-thread runtime. Each measurement offers a constant request rate over
//! exactly `connections` TCP connections, one per load task, for a fixed
//! time, after an unrecorded warm-up at the same rate, and records the
//! latency distribution of every request from its scheduled slot (`lat`,
//! no coordinated omission) and the rate actually completed (`ops`). An
//! achieved rate below the offered rate is the server saturating, and its
//! latency distribution shows the queue.
//!
//! Reads (PERF-HTTP-001, PERF-HTTP-002): blob GET at every storage size and
//! the image manifest GET by tag, each response checked for status, digest
//! and length. Writes (PERF-HTTP-003): monolithic blob PUT of distinct
//! content at every storage size, durable (fsync), each newly stored;
//! a rate and size pair offering more than 256 MiB/s is not offered.
//!
//! Scale: `KAPPA_PERF_TIER=smoke|standard|full` (default standard).
//! Device: `KAPPA_PERF_DEVICE_DIR` selects the filesystem the store uses.

#[path = "http/load.rs"]
mod load;
#[path = "http/requests.rs"]
mod requests;
#[path = "http/server.rs"]
mod server;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use kappa_perf::bench::fixture::stamp;
use kappa_perf::bench::{BenchResult, Tier, device_dir, mag, osc, pattern};
use kappa_perf::calibrate::{CalibratedSession, Profile};
use tokio::runtime::Runtime;

use load::Plan;
use requests::{Call, MANIFEST_TYPE, Seeded};

const NAMESPACE: &str = "perf/http";
/// Worker threads of the load generator's runtime; the server's runtime
/// gets the rest of the host.
const CLIENT_THREADS: usize = 2;
/// Upload bandwidth a write measurement may offer.
const MAX_OFFERED_UPLOAD: u64 = 256 << 20;

#[derive(Debug, Clone, Copy)]
struct Load {
    connections: u64,
    duration: Duration,
    warmup: Duration,
    read_rates: &'static [u64],
    write_rates: &'static [u64],
}

const fn load(tier: Tier) -> Load {
    tier.pick(
        Load {
            connections: 4,
            duration: Duration::from_secs(2),
            warmup: Duration::from_secs(1),
            read_rates: &[200],
            write_rates: &[50],
        },
        Load {
            connections: 16,
            duration: Duration::from_secs(10),
            warmup: Duration::from_secs(2),
            read_rates: &[1_000, 4_000],
            write_rates: &[100, 400],
        },
        Load {
            connections: 64,
            duration: Duration::from_secs(30),
            warmup: Duration::from_secs(5),
            read_rates: &[1_000, 4_000, 16_000],
            write_rates: &[100, 400, 1_600],
        },
    )
}

fn main() -> BenchResult {
    let tier = Tier::from_env()?;
    let load = load(tier);
    let mut session = CalibratedSession::new("http", Profile::L6Graded, "tokio")?;
    let device = device_dir()?;
    session.set_storage_path(&device);
    let store = tempfile::Builder::new()
        .prefix("http-store-")
        .tempdir_in(&device)?;
    let logical = std::thread::available_parallelism().map_or(1, usize::from);
    let server =
        server::InProcess::start(store.path(), logical.saturating_sub(CLIENT_THREADS).max(1))?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(CLIENT_THREADS)
        .thread_name("load")
        .enable_all()
        .build()?;
    let seeded = runtime.block_on(requests::seed(server.addr, NAMESPACE, tier.storage_sizes()))?;

    reads(&mut session, &runtime, load, server.addr, &seeded)?;
    writes(&mut session, &runtime, load, server.addr, tier)?;

    drop(runtime);
    server.stop()?;
    let summary = session.finalize()?;
    eprint!("{summary}");
    if summary.untrusted.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} HTTP measurements violated physical bounds; see the summary above",
            summary.untrusted.len()
        )
        .into())
    }
}

/// Offer `rate` requests per second of `operation` and record its latency
/// distribution and achieved rate, unless its floors are not established.
#[allow(
    clippy::too_many_arguments,
    reason = "one measurement: its identity, its load and its request"
)]
fn measure<P>(
    s: &mut CalibratedSession,
    runtime: &Runtime,
    load: Load,
    addr: SocketAddr,
    operation: &str,
    conditions: &str,
    rate: u64,
    test_id: &str,
    prepare: P,
) -> BenchResult
where
    P: Fn(u64) -> Result<Call, String> + Clone + Send + Sync + 'static,
{
    let conditions = format!("{conditions}&connections={}&rate={rate}", load.connections);
    let latency = osc(&format!("osc:lat/{operation}?{conditions}"))?;
    if let Err(skip) = s.check_deps(&latency) {
        eprintln!("{skip}");
        s.skip(skip);
        return Ok(());
    }
    let plan = |duration| Plan {
        rate,
        connections: load.connections,
        duration,
    };
    runtime.block_on(load::run(addr, plan(load.warmup), prepare.clone()))?;
    let outcome = runtime.block_on(load::run(addr, plan(load.duration), prepare))?;
    eprintln!(
        "{latency}: {} requests, offered {rate}/s, achieved {:.0}/s",
        outcome.completed,
        outcome.achieved_rate()
    );
    s.record_histogram(&latency, &outcome.latency, None, Some(test_id))?;
    s.record_direct(
        &osc(&format!("osc:ops/{operation}?{conditions}"))?,
        outcome.achieved_rate(),
        Some(test_id),
    )?;
    Ok(())
}

fn reads(
    s: &mut CalibratedSession,
    runtime: &Runtime,
    load: Load,
    addr: SocketAddr,
    seeded: &Seeded,
) -> BenchResult {
    for (size, blob) in &seeded.blobs {
        let path = requests::blob_path(NAMESPACE, &blob.digest);
        for &rate in load.read_rates {
            let (path, blob) = (path.clone(), blob.clone());
            measure(
                s,
                runtime,
                load,
                addr,
                "http.blob_get",
                &format!("backend=redb&size={}", mag(*size)),
                rate,
                "PERF-HTTP-001",
                move |_| Ok(Call::get(path.clone(), None, &blob)),
            )?;
        }
    }
    let path = format!("/v2/{NAMESPACE}/manifests/latest");
    for &rate in load.read_rates {
        let (path, manifest) = (path.clone(), seeded.manifest.clone());
        measure(
            s,
            runtime,
            load,
            addr,
            "http.manifest_get",
            "backend=redb",
            rate,
            "PERF-HTTP-002",
            move |_| Ok(Call::get(path.clone(), Some(MANIFEST_TYPE), &manifest)),
        )?;
    }
    Ok(())
}

fn writes(
    s: &mut CalibratedSession,
    runtime: &Runtime,
    load: Load,
    addr: SocketAddr,
    tier: Tier,
) -> BenchResult {
    // One serial space for every upload, warm-up included, so each request
    // stores content the server has never seen.
    let serial = Arc::new(AtomicU64::new(1));
    for &size in tier.storage_sizes() {
        let template = Arc::new(pattern(size, 950));
        for &rate in load.write_rates {
            if rate.saturating_mul(size as u64) > MAX_OFFERED_UPLOAD {
                continue;
            }
            let (template, serial) = (template.clone(), serial.clone());
            measure(
                s,
                runtime,
                load,
                addr,
                "http.blob_put",
                &format!("backend=redb&durability=immediate&size={}", mag(size)),
                rate,
                "PERF-HTTP-003",
                move |_| {
                    let mut content = template.as_ref().clone();
                    stamp(&mut content, serial.fetch_add(1, Ordering::Relaxed));
                    Ok(Call::put_blob(NAMESPACE, Bytes::from(content)))
                },
            )?;
        }
    }
    Ok(())
}
