//! Kernel and synchronization floors (PERF-CAL-021, PERF-CON-011).
//!
//! Syscall floor (`getpid`, an uncontended `futex` wake); atomic and mutex
//! cost uncontended and contended across 1 to 8 threads; cross-thread
//! wake round trips by futex and by thread park; channel round trips; and
//! the `spawn_blocking` handoff every store call in an async handler pays.
//! Round trips are two handoffs and are reported per handoff.

use std::hint::black_box;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread;

use criterion::{Criterion, SamplingMode};
use kappa_perf::bench::{BenchResult, Failure, bench, elements, osc, timed};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use rustix::thread::futex;

const THREADS: [usize; 4] = [1, 2, 4, 8];

type Worker = Arc<dyn Fn(usize, u64) + Send + Sync>;

pub fn register(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    syscalls(c, s)?;
    uncontended(c, s)?;
    contended(c, s)?;
    wakes(c, s)?;
    channels(c, s)?;
    spawn_blocking(c, s)
}

fn syscalls(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let word = AtomicU32::new(0);
    let failure = Failure::default();
    CalibratedGroup::scope(c, "syscall", |group| -> BenchResult {
        group.bench(
            s,
            &bench(
                osc("osc:lat/sys.getpid")?,
                "getpid",
                "_",
                None,
                "PERF-CAL-021",
            ),
            |iters| {
                timed(iters, || {
                    black_box(rustix::process::getpid());
                })
            },
        )?;
        group.bench(
            s,
            &bench(
                osc("osc:lat/sys.futex")?,
                "futex_wake",
                "no_waiter",
                None,
                "PERF-CAL-021",
            ),
            |iters| {
                timed(iters, || {
                    black_box(failure.ok(futex::wake(&word, futex::Flags::PRIVATE, 1)));
                })
            },
        )?;
        failure.check("sys.futex")
    })
}

fn uncontended(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let counter = AtomicU64::new(0);
    let mutex = Mutex::new(0u64);
    let failure = Failure::default();
    CalibratedGroup::scope(c, "sync_uncontended", |group| -> BenchResult {
        for (variant, ordering) in [("relaxed", Ordering::Relaxed), ("seqcst", Ordering::SeqCst)] {
            let id = osc(&format!("osc:lat/sync.atomic?variant={variant}"))?;
            group.bench(
                s,
                &bench(id, "fetch_add", variant, None, "PERF-CAL-021"),
                |iters| {
                    timed(iters, || {
                        black_box(counter.fetch_add(1, ordering));
                    })
                },
            )?;
        }
        group.bench(
            s,
            &bench(
                osc("osc:lat/sync.mutex?variant=std")?,
                "lock",
                "std",
                None,
                "PERF-CAL-021",
            ),
            |iters| {
                timed(iters, || match mutex.lock() {
                    Ok(mut guard) => *guard += 1,
                    Err(_) => failure.fail("mutex poisoned"),
                })
            },
        )?;
        failure.check("sync.mutex")
    })
}

fn contended(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let failure = Arc::new(Failure::default());
    CalibratedGroup::scope(c, "sync_contended", |group| -> BenchResult {
        group.configure(|g| {
            g.sampling_mode(SamplingMode::Flat);
        });
        for threads in THREADS {
            let shared = Arc::new(AtomicU64::new(0));
            let worker: Worker = Arc::new(move |_, n| {
                for _ in 0..n {
                    shared.fetch_add(1, Ordering::SeqCst);
                }
            });
            let id = osc(&format!(
                "osc:ops/sync.atomic?threads={threads}t&variant=seqcst"
            ))?;
            group.bench_contended(
                s,
                &bench(id, "atomic", threads.to_string(), None, "PERF-CON-013"),
                threads,
                &worker,
            )?;

            let lock = Arc::new(Mutex::new(0u64));
            let poisoned = Arc::clone(&failure);
            let worker: Worker = Arc::new(move |_, n| {
                for _ in 0..n {
                    let Ok(mut guard) = lock.lock() else {
                        poisoned.fail("contended mutex poisoned");
                        return;
                    };
                    *guard += 1;
                }
            });
            let id = osc(&format!(
                "osc:ops/sync.mutex?threads={threads}t&variant=std"
            ))?;
            group.bench_contended(
                s,
                &bench(id, "mutex", threads.to_string(), None, "PERF-CON-013"),
                threads,
                &worker,
            )?;
            failure.check("sync.mutex contended")?;
        }
        Ok(())
    })
}

/// Round-trip partner: waits for `call` to become 1, resets it, sets
/// `answer` and wakes the caller, until `stop`.
fn futex_partner(
    call: Arc<AtomicU32>,
    answer: Arc<AtomicU32>,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<rustix::io::Result<()>> {
    thread::spawn(move || {
        loop {
            while call.load(Ordering::Acquire) == 0 {
                if stop.load(Ordering::Acquire) {
                    return Ok(());
                }
                match futex::wait(&call, futex::Flags::PRIVATE, 0, None) {
                    Ok(()) | Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                    Err(error) => return Err(error),
                }
            }
            call.store(0, Ordering::Release);
            answer.store(1, Ordering::Release);
            futex::wake(&answer, futex::Flags::PRIVATE, 1)?;
        }
    })
}

fn wakes(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let (call, answer, stop) = (
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicU32::new(0)),
        Arc::new(AtomicBool::new(false)),
    );
    let partner = futex_partner(Arc::clone(&call), Arc::clone(&answer), Arc::clone(&stop));
    let failure = Failure::default();
    let measured = CalibratedGroup::scope(c, "sync_wake_futex", |group| -> BenchResult {
        group.configure(|g| {
            g.sampling_mode(SamplingMode::Flat);
        });
        group.bench(
            s,
            &bench(
                osc("osc:lat/sync.wake?variant=futex")?,
                "futex",
                "roundtrip",
                elements(2),
                "PERF-CAL-021",
            ),
            |iters| {
                timed(iters, || {
                    call.store(1, Ordering::Release);
                    if failure
                        .ok(futex::wake(&call, futex::Flags::PRIVATE, 1))
                        .is_none()
                    {
                        return;
                    }
                    while answer.load(Ordering::Acquire) == 0 {
                        match futex::wait(&answer, futex::Flags::PRIVATE, 0, None) {
                            Ok(()) | Err(rustix::io::Errno::AGAIN | rustix::io::Errno::INTR) => {}
                            Err(error) => {
                                failure.fail(error.to_string());
                                return;
                            }
                        }
                    }
                    answer.store(0, Ordering::Release);
                })
            },
        )?;
        Ok(())
    });
    stop.store(true, Ordering::Release);
    call.store(1, Ordering::Release);
    futex::wake(&call, futex::Flags::PRIVATE, 1)?;
    partner.join().map_err(|_| "futex partner panicked")??;
    measured?;
    failure.check("sync.wake futex")?;

    let (to_partner, from_main) = mpsc::sync_channel::<thread::Thread>(1);
    let done = Arc::new(AtomicBool::new(false));
    let (turn, partner_done) = (Arc::new(AtomicBool::new(false)), Arc::clone(&done));
    let partner_turn = Arc::clone(&turn);
    let partner = thread::spawn(move || {
        let Ok(main) = from_main.recv() else { return };
        while !partner_done.load(Ordering::Acquire) {
            if partner_turn.swap(false, Ordering::AcqRel) {
                main.unpark();
            } else {
                thread::park();
            }
        }
    });
    to_partner
        .send(thread::current())
        .map_err(|_| "park partner exited")?;
    let partner_handle = partner.thread().clone();
    let measured = CalibratedGroup::scope(c, "sync_wake_park", |group| -> BenchResult {
        group.configure(|g| {
            g.sampling_mode(SamplingMode::Flat);
        });
        group.bench(
            s,
            &bench(
                osc("osc:lat/sync.wake?variant=park")?,
                "park",
                "roundtrip",
                elements(2),
                "PERF-CAL-021",
            ),
            |iters| {
                timed(iters, || {
                    turn.store(true, Ordering::Release);
                    partner_handle.unpark();
                    while turn.load(Ordering::Acquire) {
                        thread::park();
                    }
                })
            },
        )?;
        Ok(())
    });
    done.store(true, Ordering::Release);
    partner_handle.unpark();
    partner.join().map_err(|_| "park partner panicked")?;
    measured
}

fn channels(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    CalibratedGroup::scope(c, "sync_channel", |group| -> BenchResult {
        group.configure(|g| {
            g.sampling_mode(SamplingMode::Flat);
        });
        for (variant, capacity) in [("std_rendezvous", 0usize), ("std_bounded", 64)] {
            let (request, requests) = mpsc::sync_channel::<u64>(capacity);
            let (reply, replies) = mpsc::sync_channel::<u64>(capacity);
            let echo = thread::spawn(move || {
                while let Ok(value) = requests.recv() {
                    if reply.send(value).is_err() {
                        break;
                    }
                }
            });
            let failure = Failure::default();
            let id = osc(&format!("osc:lat/sync.channel?variant={variant}"))?;
            let measured = group.bench(
                s,
                &bench(id, variant, "roundtrip", elements(2), "PERF-CAL-021"),
                |iters| {
                    timed(iters, || {
                        if failure.ok(request.send(7)).is_some() {
                            black_box(failure.ok(replies.recv()));
                        }
                    })
                },
            );
            drop(request);
            echo.join().map_err(|_| "channel echo panicked")?;
            measured?;
            failure.check("sync.channel")?;
        }
        Ok(())
    })
}

fn spawn_blocking(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .build()?;
    let failure = Failure::default();
    CalibratedGroup::scope(c, "sched", |group| -> BenchResult {
        group.configure(|g| {
            g.sampling_mode(SamplingMode::Flat);
        });
        let id = osc("osc:lat/sched.spawn_blocking?variant=tokio")?;
        group.bench(
            s,
            &bench(id, "spawn_blocking", "roundtrip", None, "PERF-CON-011"),
            |iters| {
                runtime.block_on(async {
                    let start = std::time::Instant::now();
                    for _ in 0..iters {
                        if failure
                            .ok(tokio::task::spawn_blocking(|| black_box(1u64)).await)
                            .is_none()
                        {
                            break;
                        }
                    }
                    start.elapsed()
                })
            },
        )?;
        failure.check("sched.spawn_blocking")
    })
}
