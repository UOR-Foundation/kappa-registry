//! Owned backend fixtures for substrate conformance.

use kappa_handler::clock_at;
use kappa_store::clock::ClockMs;
use kappa_store::namespace::NamespaceRef;
use kappa_store::{Execution, ExecutionStore, StoreError};
use kappa_store_memory::InMemoryStore;
use kappa_store_memory::test_support::test_store;

pub type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A conformance store. The store retains its own filesystem scope, so it
/// is the whole fixture.
pub struct MemoryFixture {
    pub store: InMemoryStore,
}

impl MemoryFixture {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            store: test_store()?.into_store(),
        })
    }
}

pub const fn test_now() -> ClockMs {
    ClockMs::from_raw(1000)
}

/// Publish one execution against `ns`, running `work` inside it.
pub fn publish(
    store: &InMemoryStore,
    ns: &NamespaceRef,
    work: impl FnOnce(&mut dyn Execution) -> Result<(), StoreError>,
) -> Result<kappa_store::Published, StoreError> {
    let mut execution = store.begin_execution(ns, &clock_at(test_now())?)?;
    work(&mut *execution)?;
    execution.publish()
}

/// Create a namespace in its own published execution.
pub fn create_ns(store: &InMemoryStore, name: &str) -> Result<NamespaceRef, StoreError> {
    let ns = NamespaceRef::generate(name, test_now())?;
    let mut execution = store.begin_execution(&ns, &clock_at(test_now())?)?;
    execution.namespace_create(None, None)?;
    execution.publish()?;
    Ok(ns)
}
