use kappa_types::epoch_root::EpochRoot;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;

/// Published epochs: signed snapshots of namespace state. Epochs are sealed
/// only by publishing an execution.
pub trait EpochStore: Send + Sync {
    /// Committed tag-state digest and tag count, captured from one backend
    /// snapshot. This is the only observation of namespace state; executions
    /// compute their own state commitment when they seal.
    fn epoch_state(&self, ns: &NamespaceRef) -> Result<([u8; 32], u64), StoreError>;

    /// Current epoch number and root kappa.
    fn epoch_current(&self, ns: &NamespaceRef) -> Result<(u64, Kappa), StoreError>;

    /// Retrieve the epoch root by its kappa.
    fn epoch_get(&self, kappa: &Kappa) -> Result<EpochRoot, StoreError>;

    /// Retrieve an epoch by epoch number.
    fn epoch_get_by_number(
        &self,
        ns: &NamespaceRef,
        epoch_number: u64,
    ) -> Result<Kappa, StoreError>;
}
