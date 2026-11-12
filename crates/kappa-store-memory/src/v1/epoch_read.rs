//! Reads of a namespace view's epochs: a root read and decoded, a root
//! admitted against its persisted ledger, the epoch number index, and
//! global lookup by root through the epoch projection. Every read runs on
//! its operation's meter.

use kappa_store::epoch_publication::admit_persisted_epoch;
use kappa_store::traits::epoch::EpochStore;
use kappa_types::epoch_root::EpochRoot;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::work::Meter;

use super::InMemoryStore;
use super::blob_read;
use super::locate::incomplete;
use super::view::NamespaceView;

/// Bytes an epoch root may hold.
const ROOT_LIMIT: u64 = 1 << 20;

impl InMemoryStore {
    /// The authenticated epoch root `kappa` of `view`, on `work`: the root
    /// read and decoded (`unadmitted_epoch_in`), then admitted against its
    /// persisted ledger, read and verified once, by the shared rule
    /// (`admit_persisted_epoch`).
    pub(crate) fn epoch_in(
        &self,
        view: &NamespaceView,
        kappa: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<EpochRoot, StoreError> {
        let root = unadmitted_epoch_in(view, kappa, work, &self.decoded_storage)?;
        let ledger = blob_read::verified(view, root.ledger_root(), None, work)?;
        admit_persisted_epoch(&root, &self.authority.load(), &ledger, work)?;
        Ok(root)
    }
}

/// The epoch root `kappa` of `view`, read, verified against its identity
/// and decoded on `work`, its decoding charged before it runs, and not yet
/// admitted: the one form a caller that admits the epoch itself reads
/// (`epoch_in`, and operation replay through `admit_operation_outcome`).
pub(crate) fn unadmitted_epoch_in(
    view: &NamespaceView,
    kappa: &Kappa,
    work: &mut dyn Meter,
    storage: &std::sync::Arc<kappa_types::capacity::CapacityPool>,
) -> Result<EpochRoot, StoreError> {
    let bytes =
        blob_read::verified(view, kappa, Some(ROOT_LIMIT), work).map_err(|error| match error {
            StoreError::NotFound(_) => StoreError::NotFound(format!("epoch root {kappa}")),
            other => other,
        })?;
    EpochRoot::from_verified(&bytes, 1, work, storage)
}

impl EpochStore for InMemoryStore {
    fn epoch_state(&self, ns: &NamespaceRef) -> Result<([u8; 32], u64), StoreError> {
        // One view supplies both values.
        let view = self.view(ns.id());
        Ok((*view.digest.value(), view.tags.len() as u64))
    }

    fn epoch_current(&self, ns: &NamespaceRef) -> Result<(u64, Kappa), StoreError> {
        let view = self.view(ns.id());
        let kappa = view
            .epoch
            .clone()
            .ok_or_else(|| StoreError::NotFound(format!("epoch for {ns}")))?;
        let root = self.epoch_in(&view, &kappa, &mut self.read_meter())?;
        if root.namespace_id() != ns.id() {
            return Err(StoreError::Internal(
                "epoch pointer crosses namespace identity".into(),
            ));
        }
        Ok((root.epoch_number(), kappa))
    }

    /// The candidate whose epoch index names `kappa` under the root's own
    /// epoch number decides: one index lookup per candidate, every
    /// candidate's root read on the one operation's meter.
    fn epoch_get(&self, kappa: &Kappa) -> Result<EpochRoot, StoreError> {
        let mut meter = self.read_meter();
        let mut found: Option<Result<EpochRoot, StoreError>> = None;
        let complete = self.located(&self.projections.epochs, kappa, |_, view| {
            if !view.holds(kappa) {
                return false;
            }
            match self.epoch_in(view, kappa, &mut meter) {
                Ok(root) if view.epochs.get(&root.epoch_number()) == Some(kappa) => {
                    found = Some(Ok(root));
                    true
                }
                Ok(_) => false,
                Err(error) => {
                    found = Some(Err(error));
                    true
                }
            }
        });
        match found {
            Some(result) => result,
            None if complete => Err(StoreError::NotFound(format!("epoch root {kappa}"))),
            None => Err(incomplete(&format_args!("epoch root {kappa}"))),
        }
    }

    fn epoch_get_by_number(
        &self,
        ns: &NamespaceRef,
        epoch_number: u64,
    ) -> Result<Kappa, StoreError> {
        let view = self.view(ns.id());
        view.epochs.get(&epoch_number).cloned().ok_or_else(|| {
            let current = view.epochs.keys().next_back().copied().unwrap_or(0);
            StoreError::NotFound(format!("epoch {epoch_number} of {ns} (current {current})"))
        })
    }
}
