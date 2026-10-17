//! Criterion integration: configuration, dependency-gated benchmarks,
//! barrier-gated contention benchmarks, and finalization.
//!
//! Bench files contain measurement bodies and identifiers; everything else
//! is here. Defaults meet PERF-DOC-010: at least 100 samples, warm-up,
//! 100 000 bootstrap resamples, outlier classification by criterion.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, BenchmarkId, Criterion, Throughput};

use super::grammar::OscId;
use super::quantity::Work;
use super::record::HarnessCoords;
use super::session::{CalibratedSession, SessionError};
use super::summary::Summary;

/// Samples per benchmark (PERF-DOC-010: at least 100).
pub const SAMPLE_SIZE: usize = 100;

/// Criterion configured for calibration. Command-line flags still override
/// (`--measurement-time`, `--sample-size`, `--noplot`, filters). Plots are
/// disabled when `CI` or `KAPPA_PERF_NO_PLOTS` is set.
pub fn calibrated_criterion() -> Criterion {
    let mut criterion = Criterion::default()
        .sample_size(SAMPLE_SIZE)
        .warm_up_time(Duration::from_secs(3))
        .measurement_time(Duration::from_secs(5))
        .nresamples(100_000)
        .noise_threshold(0.01)
        .confidence_level(0.95)
        .significance_level(0.05);
    if std::env::var_os("CI").is_some() || std::env::var_os("KAPPA_PERF_NO_PLOTS").is_some() {
        criterion = criterion.without_plots();
    }
    criterion.configure_from_args()
}

/// One calibrated benchmark.
pub struct Bench<'a> {
    pub id: OscId,
    pub function: &'a str,
    pub param: Option<String>,
    pub work: Option<Work>,
    pub test_id: Option<&'a str>,
}

#[derive(Debug, thiserror::Error)]
pub enum HarnessError {
    #[error(transparent)]
    Session(#[from] SessionError),
    #[error(
        "{id}: group '{group}' already declared throughput; criterion keeps it, so this benchmark must declare its own work"
    )]
    StickyThroughput { group: String, id: String },
    #[error("{id}: identifier must carry threads={threads}t to match the contention it measures")]
    ThreadsMismatch { id: String, threads: usize },
    #[error("contended benchmark needs at least one thread")]
    NoThreads,
}

const fn throughput(work: Work) -> Throughput {
    match work {
        Work::Bytes(bytes) => Throughput::Bytes(bytes),
        Work::Bits(bits) => Throughput::Bits(bits),
        Work::Elements(elements) => Throughput::Elements(elements),
        Work::ElementsAndBytes { elements, bytes } => {
            Throughput::ElementsAndBytes { elements, bytes }
        }
    }
}

/// A criterion group bound to a calibration session.
pub struct CalibratedGroup<'c> {
    group: BenchmarkGroup<'c, WallTime>,
    name: String,
    throughput_declared: bool,
}

impl<'c> CalibratedGroup<'c> {
    /// Run `body` against a new group, then finish the group whatever the
    /// body's outcome. The group exists only for the body, so it cannot be
    /// left open or finished twice.
    pub fn scope<T, E>(
        criterion: &'c mut Criterion,
        name: &str,
        body: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut group = Self {
            group: criterion.benchmark_group(name),
            name: name.to_owned(),
            throughput_declared: false,
        };
        let outcome = body(&mut group);
        group.finish();
        outcome
    }

    fn finish(self) {
        self.group.finish();
    }

    /// Per-group criterion configuration (e.g. fewer samples or longer
    /// measurement for slow durable operations).
    pub fn configure(&mut self, configure: impl FnOnce(&mut BenchmarkGroup<'c, WallTime>)) {
        configure(&mut self.group);
    }

    fn prepare(
        &mut self,
        session: &mut CalibratedSession,
        bench: &Bench<'_>,
    ) -> Result<bool, HarnessError> {
        if let Err(skip) = session.check_deps(&bench.id) {
            eprintln!("{skip}");
            session.skip(skip);
            return Ok(false);
        }
        match bench.work {
            Some(work) => {
                self.group.throughput(throughput(work));
                self.throughput_declared = true;
            }
            None if self.throughput_declared => {
                return Err(HarnessError::StickyThroughput {
                    group: self.name.clone(),
                    id: bench.id.canonical(),
                });
            }
            None => {}
        }
        Ok(true)
    }

    fn criterion_id(bench: &Bench<'_>) -> BenchmarkId {
        bench.param.as_ref().map_or_else(
            || BenchmarkId::new(bench.function, "_"),
            |param| BenchmarkId::new(bench.function, param),
        )
    }

    fn coords(&self, bench: &Bench<'_>) -> HarnessCoords {
        HarnessCoords {
            group: self.name.clone(),
            function: Some(bench.function.to_owned()),
            value: Some(bench.param.clone().unwrap_or_else(|| "_".to_owned())),
        }
    }

    /// Run `body(iters) -> elapsed` under criterion and record it. Returns
    /// `false` when skipped for missing dependencies.
    pub fn bench(
        &mut self,
        session: &mut CalibratedSession,
        bench: &Bench<'_>,
        mut body: impl FnMut(u64) -> Duration,
    ) -> Result<bool, HarnessError> {
        if !self.prepare(session, bench)? {
            return Ok(false);
        }
        self.group
            .bench_function(Self::criterion_id(bench), |b| b.iter_custom(&mut body));
        session.record_criterion(&bench.id, self.coords(bench), bench.test_id)?;
        Ok(true)
    }

    /// Run `worker(iterations)` on `threads` threads that start together.
    ///
    /// Threads are spawned once per criterion call and gated by barriers;
    /// spawn and join are outside the timed region. Each sample divides the
    /// requested iterations evenly across threads and scales the elapsed
    /// time by requested/performed iterations, so the reported time is per
    /// requested iteration of the whole system.
    ///
    /// # Panics
    ///
    /// When any worker panics, the sample in which it panicked re-raises on
    /// the timing thread: every sample of a run with a failed worker is
    /// invalid, and criterion must not publish its estimates.
    #[allow(
        clippy::cast_precision_loss,
        reason = "iteration counts far below 2^53"
    )]
    pub fn bench_contended(
        &mut self,
        session: &mut CalibratedSession,
        bench: &Bench<'_>,
        threads: usize,
        worker: &Arc<dyn Fn(usize, u64) + Send + Sync>,
    ) -> Result<bool, HarnessError> {
        if threads == 0 {
            return Err(HarnessError::NoThreads);
        }
        if bench.id.conditions().get("threads") != Some(format!("{threads}t").as_str()) {
            return Err(HarnessError::ThreadsMismatch {
                id: bench.id.canonical(),
                threads,
            });
        }
        if !self.prepare(session, bench)? {
            return Ok(false);
        }
        let label = bench.id.canonical();
        self.group.bench_function(Self::criterion_id(bench), |b| {
            let go = Arc::new(Barrier::new(threads + 1));
            let done = Arc::new(Barrier::new(threads + 1));
            let per_thread = Arc::new(AtomicU64::new(0));
            let running = Arc::new(AtomicBool::new(true));
            // A worker that panicked must still reach `done`, or the timing
            // thread waits forever; the panic is re-raised on that thread.
            let panicked = Arc::new(AtomicBool::new(false));
            let handles: Vec<_> = (0..threads)
                .map(|index| {
                    let (go, done, per_thread, running, panicked, worker) = (
                        Arc::clone(&go),
                        Arc::clone(&done),
                        Arc::clone(&per_thread),
                        Arc::clone(&running),
                        Arc::clone(&panicked),
                        Arc::clone(worker),
                    );
                    std::thread::spawn(move || {
                        loop {
                            go.wait();
                            if !running.load(Ordering::Acquire) {
                                done.wait();
                                break;
                            }
                            let n = per_thread.load(Ordering::Acquire);
                            let work = std::panic::AssertUnwindSafe(|| worker(index, n));
                            if std::panic::catch_unwind(work).is_err() {
                                panicked.store(true, Ordering::Release);
                            }
                            done.wait();
                        }
                    })
                })
                .collect();
            b.iter_custom(|iters| {
                let each = iters.div_ceil(threads as u64);
                per_thread.store(each, Ordering::Release);
                go.wait();
                let start = Instant::now();
                done.wait();
                let elapsed = start.elapsed();
                assert!(
                    !panicked.load(Ordering::Acquire),
                    "a contended worker panicked in {label}; every sample is invalid"
                );
                elapsed.mul_f64(iters as f64 / (each * threads as u64) as f64)
            });
            running.store(false, Ordering::Release);
            go.wait();
            done.wait();
            for handle in handles {
                if let Err(payload) = handle.join() {
                    std::panic::resume_unwind(payload);
                }
            }
        });
        session.record_criterion(&bench.id, self.coords(bench), bench.test_id)?;
        Ok(true)
    }
}

/// Emit criterion's summary, then finalize the session and print its summary.
pub fn finalize(
    session: &mut CalibratedSession,
    criterion: &Criterion,
) -> Result<Summary, SessionError> {
    criterion.final_summary();
    let summary = session.finalize()?;
    eprint!("{summary}");
    Ok(summary)
}
