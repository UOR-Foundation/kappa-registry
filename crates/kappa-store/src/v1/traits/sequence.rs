use kappa_types::error::StoreError;
use kappa_types::namespace::NamespaceRef;

/// Published monotonically increasing named counters per namespace.
/// Reservation is `ExecutionWrites::sequence_next`, which publishes its
/// evidence with the epoch.
pub trait SequenceStore: Send + Sync {
    /// Read the current value without incrementing.
    fn sequence_current(&self, ns: &NamespaceRef, name: &str) -> Result<u64, StoreError>;
}
