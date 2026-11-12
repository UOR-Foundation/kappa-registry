use kappa_types::error::StoreError;
use kappa_types::namespace::NamespaceRef;

/// Decide the next issued value from the counter observed under the writer.
pub fn next_value(name: &str, current: u64) -> Result<u64, StoreError> {
    if name.is_empty() {
        return Err(StoreError::Rejected("sequence name is empty".into()));
    }
    current
        .checked_add(1)
        .ok_or_else(|| StoreError::CapacityExceeded(format!("sequence {name} exhausted")))
}

/// Published monotonically increasing named counters per namespace.
/// Reservation is `ExecutionWrites::sequence_next`, which publishes its
/// evidence with the epoch.
pub trait SequenceStore: Send + Sync {
    /// Read the current value without incrementing.
    fn sequence_current(&self, ns: &NamespaceRef, name: &str) -> Result<u64, StoreError>;
}
