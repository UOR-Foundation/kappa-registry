//! Store fixtures for workload measurements.
//!
//! Every store lives in one scope created under the device directory, so
//! its blobs and database reach the filesystem the device floors measured.
//! Stores are acquired through the backends' `test_support` and retain
//! that scope themselves. Timestamps come from one production `WallClock`
//! (an HLC authority), as every handler issues them. A [`Target`] carries
//! the conditions that distinguish one store configuration from another in
//! every identifier.

use std::path::Path;

use kappa_fixture::{FixtureRoot, SetupError};
use kappa_handler::clock::{Clock, WallClock};
use kappa_store::{ExecutionStore, Kappa, NamespaceRef, TagUpdate};
use kappa_store_memory::InMemoryStore;
use kappa_store_memory::test_support::StoreSpec;
use kappa_store_redb::PersistentStore;
use kappa_store_redb::test_support::PersistentSpec;

use super::BenchResult;

/// Fixed, published blob-encryption key. It exists to make the redb store
/// pay its cipher cost (PERF-STO-026) and protects nothing.
const MEASUREMENT_KEY: [u8; 32] = [0x6b; 32];

/// Tags or mutations written per published execution while populating.
pub const POPULATE_BATCH: usize = 4096;

/// A store configuration under measurement and its identifying conditions.
pub struct Target<'a, S> {
    pub store: &'a S,
    /// Criterion group suffix.
    pub label: &'static str,
    pub backend: &'static str,
    /// `none`: page-cache writes, no flush (the memory store's blob cache
    /// and in-memory generations). `immediate`: every commit is durable
    /// before it returns (redb's default transaction policy).
    pub durability: &'static str,
    pub encryption: &'static str,
}

impl<S> Target<'_, S> {
    /// Conditions every write measurement of this target carries.
    pub fn write_conds(&self) -> String {
        format!(
            "backend={}&durability={}&encryption={}",
            self.backend, self.durability, self.encryption
        )
    }

    /// Conditions every read measurement of this target carries.
    pub fn read_conds(&self) -> String {
        format!("backend={}&encryption={}", self.backend, self.encryption)
    }
}

/// The scope every store one bench binary opens lives in.
pub struct Fixture {
    root: FixtureRoot,
}

impl Fixture {
    /// A fresh scope inside the calibrated `device_dir`.
    pub fn new(device_dir: &Path) -> Result<Self, SetupError> {
        Ok(Self {
            root: FixtureRoot::within(device_dir, "workloads-")?,
        })
    }

    pub fn path(&self) -> &Path {
        self.root.path()
    }

    /// The memory store named `name`, its blobs at `{name}/blobs`.
    pub fn memory(&self, name: &str) -> Result<InMemoryStore, SetupError> {
        Ok(StoreSpec::new()
            .in_root(&self.root)
            .blob_dir(Path::new(name).join("blobs"))
            .acquire()?
            .into_store())
    }

    /// The redb store named `name`, in directory `name`; `encrypted` pays the
    /// blob and table cipher under [`MEASUREMENT_KEY`].
    pub fn redb(&self, name: &str, encrypted: bool) -> Result<PersistentStore, SetupError> {
        let spec = PersistentSpec::new().in_root(&self.root).dir(name);
        let spec = if encrypted {
            spec.encryption_key(MEASUREMENT_KEY)
        } else {
            spec
        };
        Ok(spec.acquire()?.into_store())
    }
}

pub const fn memory_target(store: &InMemoryStore) -> Target<'_, InMemoryStore> {
    Target {
        store,
        label: "memory",
        backend: "memory",
        durability: "none",
        encryption: "off",
    }
}

pub const fn redb_target(store: &PersistentStore) -> Target<'_, PersistentStore> {
    Target {
        store,
        label: "redb",
        backend: "redb",
        durability: "immediate",
        encryption: "off",
    }
}

pub const fn encrypted_target(store: &PersistentStore) -> Target<'_, PersistentStore> {
    Target {
        store,
        label: "redb_encrypted",
        backend: "redb",
        durability: "immediate",
        encryption: "on",
    }
}

/// Create and publish a namespace at the authority's current time.
pub fn create_ns<S: ExecutionStore + ?Sized>(
    store: &S,
    clock: &WallClock,
    name: &str,
) -> Result<NamespaceRef, Box<dyn std::error::Error>> {
    let ns = NamespaceRef::generate(name, clock.now()?)?;
    let mut execution = store.begin_execution(&ns, clock)?;
    execution.namespace_create(None, None)?;
    execution.publish()?;
    Ok(ns)
}

/// Name of the `index`th populated tag. Fixed width, so names sort in
/// population order.
pub fn tag_name(index: usize) -> String {
    format!("t{index:08}")
}

/// Content of the `index`th populated tag in population round `round`.
pub fn tag_target(index: usize, round: u64) -> Kappa {
    let mut seed = [0u8; 16];
    seed[..8].copy_from_slice(&(index as u64).to_le_bytes());
    seed[8..].copy_from_slice(&round.to_le_bytes());
    Kappa::sha256(&seed)
}

/// Publish `count` tags named by [`tag_name`] in executions of
/// [`POPULATE_BATCH`] tags each.
pub fn populate_tags<S: ExecutionStore + ?Sized>(
    store: &S,
    clock: &WallClock,
    ns: &NamespaceRef,
    count: usize,
) -> BenchResult {
    let mut start = 0;
    while start < count {
        let end = (start + POPULATE_BATCH).min(count);
        let updates: Vec<(String, TagUpdate)> = (start..end)
            .map(|i| {
                (
                    tag_name(i),
                    TagUpdate::Set {
                        kappa: tag_target(i, 0),
                    },
                )
            })
            .collect();
        let mut execution = store.begin_execution(ns, clock)?;
        execution.tag_batch_update(&updates)?;
        execution.publish()?;
        start = end;
    }
    Ok(())
}

/// Overwrite the leading bytes (up to eight) with `serial`, so every write
/// of the buffer is distinct content and never a deduplicated no-op.
pub fn stamp(buffer: &mut [u8], serial: u64) {
    for (byte, value) in buffer.iter_mut().zip(serial.to_le_bytes()) {
        *byte = value;
    }
}
