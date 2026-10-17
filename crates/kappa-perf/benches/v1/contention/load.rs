//! Measured workers, background load, and the shared store handle every
//! contention curve uses.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;

use kappa_handler::clock::WallClock;
use kappa_perf::bench::BenchResult;
use kappa_store::{Kappa, KappaStore, NamespaceRef, TagUpdate};

/// A measured worker: thread index and the iterations it performs.
pub type Worker = Arc<dyn Fn(usize, u64) + Send + Sync>;
/// A background load: thread index and the stop flag; returns the
/// operations it completed.
pub type Load = Arc<dyn Fn(usize, &AtomicBool) -> u64 + Send + Sync>;

/// Threads applying load outside the measured workers until finished.
pub struct Background {
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<u64>>,
}

impl Background {
    pub fn start(count: usize, load: &Load) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let handles = (0..count)
            .map(|index| {
                let (stop, load) = (Arc::clone(&stop), Arc::clone(load));
                std::thread::spawn(move || load(index, &stop))
            })
            .collect();
        Self { stop, handles }
    }

    /// Stop, join, and require that the load actually ran concurrently.
    fn finish(self, what: &str) -> Result<u64, Box<dyn std::error::Error>> {
        self.stop.store(true, Ordering::Release);
        let mut total = 0u64;
        for handle in self.handles {
            total += handle
                .join()
                .map_err(|_| format!("{what}: background thread panicked"))?;
        }
        if total == 0 {
            return Err(format!("{what}: background load made no progress").into());
        }
        Ok(total)
    }
}

/// Run `measure` with `background` load applied, then stop the load and
/// require its progress whatever the measurement's outcome.
pub fn under(
    background: Option<(Background, &str)>,
    measure: impl FnOnce() -> BenchResult,
) -> BenchResult {
    let measured = measure();
    if let Some((load, what)) = background {
        load.finish(what)?;
    }
    measured
}

/// One store under measurement, shareable with worker threads.
pub struct Shared<S> {
    pub store: Arc<S>,
    pub clock: Arc<WallClock>,
    pub backend: &'static str,
    pub durability: &'static str,
}

impl<S> Shared<S> {
    pub fn write_conds(&self) -> String {
        format!(
            "backend={}&durability={}&encryption=off",
            self.backend, self.durability
        )
    }
}

/// Publish one tag update to `ns` as its own execution.
pub fn publish_one<S: KappaStore>(
    store: &S,
    clock: &WallClock,
    ns: &NamespaceRef,
    name: &str,
    kappa: Kappa,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut execution = store.begin_execution(ns, clock)?;
    execution.tag_put(name, &TagUpdate::Set { kappa })?;
    execution.publish()?;
    Ok(())
}
