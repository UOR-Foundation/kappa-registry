//! The assembled kappa-registry server, in process.
//!
//! `kappa_server::app::build` assembles exactly what the binary serves:
//! the redb-backed persistent store with fsync, the time authority, node
//! identity, the full layer chain and every default protocol module. It
//! runs on its own multi-threaded runtime, bound to an ephemeral loopback
//! port and accepting through the binary's own `NoDelayListener`, so the
//! load generator's runtime never shares worker threads with it and its
//! connections are served as the binary serves them. Disk-pressure
//! monitoring is off: the store lives in a temporary directory on the
//! device under test, and a pressure flag raised by other tenants of that
//! filesystem would turn measurements into rejections.

use std::collections::HashMap;
use std::ffi::OsString;
use std::net::SocketAddr;
use std::path::Path;

use kappa_server::app;
use kappa_server::config::Config;
use kappa_server::listener::NoDelayListener;
use tokio::runtime::Runtime;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub type BoxError = Box<dyn std::error::Error>;

pub struct InProcess {
    pub addr: SocketAddr,
    runtime: Runtime,
    shutdown: oneshot::Sender<()>,
    served: JoinHandle<std::io::Result<()>>,
}

impl InProcess {
    /// Assemble and serve a server storing under `store_root`, on a
    /// runtime with `worker_threads` workers.
    pub fn start(store_root: &Path, worker_threads: usize) -> Result<Self, BoxError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(worker_threads)
            .thread_name("kappa-server")
            .enable_all()
            .build()?;
        let values: HashMap<String, OsString> = [
            ("KAPPA_STORE_ROOT", OsString::from(store_root)),
            ("KAPPA_FSYNC", OsString::from("true")),
            ("KAPPA_DISK_PRESSURE_THRESHOLD_MB", OsString::from("0")),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect();
        let config = Config::from_lookup(|key| values.get(key).cloned())?;
        let (assembled, listener) = runtime.block_on(async {
            let assembled = app::build(&config, false).await?;
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0)).await?;
            Ok::<_, BoxError>((assembled, listener))
        })?;
        let addr = listener.local_addr()?;
        let (shutdown, stopped) = oneshot::channel();
        let serving = runtime.spawn(assembled.serve(NoDelayListener::new(listener), async {
            // A dropped sender also means stop.
            let _ = stopped.await;
        }));
        Ok(Self {
            addr,
            runtime,
            shutdown,
            served: serving,
        })
    }

    /// Stop serving, wait for the server to drain and wind down, and
    /// report how serving ended.
    pub fn stop(self) -> Result<(), BoxError> {
        // An error means the server has already returned and dropped the
        // receiver; its outcome is the join result below.
        let _ = self.shutdown.send(());
        self.runtime.block_on(self.served)??;
        Ok(())
    }
}
