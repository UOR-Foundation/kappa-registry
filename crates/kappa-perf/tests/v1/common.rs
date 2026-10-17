//! Store fixtures shared by the correctness tests.
//!
//! Every fixture is fallible: a fixture failure fails the test with its
//! cause instead of panicking without one. Contract tests are written once,
//! generic over the store traits they exercise, and run against both
//! backends through [`memory_store`] and [`redb_store`]. Acquisition is the
//! backends' own `test_support`; every store retains its filesystem scope,
//! and [`redb_store_in`] reopens the database of a caller-held scope so a
//! test can drop the store and observe restart behavior.

use kappa_fixture::{FixtureRoot, SetupError};
use kappa_handler::clock_at;
use kappa_store::clock::{CausalTime, TimeError};
use kappa_store::{ClockMs, ExecutionStore, KappaStore, NamespaceRef, StoreError};
use kappa_store_memory::InMemoryStore;
use kappa_store_redb::PersistentStore;
use kappa_store_redb::test_support::PersistentSpec;

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

/// Causal time of namespace creation in every fixture namespace.
pub const CREATED_AT: ClockMs = ClockMs::from_raw(1000);

/// A memory store in its own scope, signing as the fixture authority.
pub fn memory_store() -> Result<InMemoryStore, SetupError> {
    Ok(kappa_store_memory::test_support::test_store()?.into_store())
}

/// Open, or reopen, the redb store in `root`, signing as the fixture
/// authority, the same identity [`memory_store`] signs with.
pub fn redb_store_in(root: &FixtureRoot) -> Result<PersistentStore, SetupError> {
    Ok(PersistentSpec::new().in_root(root).acquire()?.into_store())
}

/// A redb store in its own scope.
pub fn redb_store() -> Result<PersistentStore, SetupError> {
    redb_store_in(&FixtureRoot::temporary()?)
}

/// A contract failure on one backend: names the backend and keeps the
/// original error as its source, so typed causes survive reporting.
#[derive(Debug)]
pub struct BackendFailure {
    pub backend: &'static str,
    pub source: Box<dyn std::error::Error>,
}

impl std::fmt::Display for BackendFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} backend: {}", self.backend, self.source)
    }
}

impl std::error::Error for BackendFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.source.as_ref())
    }
}

/// Run one contract exercise against both backends, each on a fresh store.
/// A failure names the backend it occurred on and carries its cause.
pub fn on_both_backends(exercise: impl Fn(&dyn KappaStore) -> TestResult) -> TestResult {
    exercise(&memory_store()?).map_err(|source| BackendFailure {
        backend: "memory",
        source,
    })?;
    exercise(&redb_store()?).map_err(|source| BackendFailure {
        backend: "redb",
        source,
    })?;
    Ok(())
}

/// A realistic wall-clock instant (2023-11-14T22:13:20Z) for tests whose
/// semantics depend on the HLC encoding of production timestamps.
pub const WALL_T0: u64 = 1_700_000_000_000;

/// The timestamp `Clock::now` issues at physical millisecond `ms` with a
/// zero logical counter: physical milliseconds in the upper 48 bits.
pub fn hlc(ms: u64) -> Result<ClockMs, TimeError> {
    Ok(CausalTime::new(ms, 0)?.encoded())
}

/// Create and publish namespace `name`; epoch 1 of every fixture namespace.
pub fn create_ns<S: ExecutionStore + ?Sized>(
    store: &S,
    name: &str,
) -> Result<NamespaceRef, StoreError> {
    let ns = NamespaceRef::generate(name, CREATED_AT)?;
    let mut execution = store.begin_execution(&ns, &clock_at(CREATED_AT)?)?;
    execution.namespace_create(None, None)?;
    execution.publish()?;
    Ok(ns)
}
