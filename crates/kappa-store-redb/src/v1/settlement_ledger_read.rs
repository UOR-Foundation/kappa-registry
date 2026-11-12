//! Native reads over the epoch cursor's retained namespace snapshot: the
//! epoch index lookup and the ledger's bytes from the source opening
//! retained (`settlement_ledger_open::LedgerSource`), so no read resolves
//! the ledger's alias or reopens its allocation again.

use kappa_store::work::{Dimension, Meter, Work};
use kappa_store::{Kappa, NamespaceRef, StoreError};
use redb::ReadTransaction;

use super::open::LedgerSource;
use crate::content_read::ReadView;
use crate::epoch::epoch_idx_key;
use crate::namespace_snapshot::NamespaceSnapshot;
use crate::representation::Representation;
use crate::tables::EPOCH_INDEX;

/// What reading `[offset, offset + length)` of the ledger charges, decided
/// from its source's framing alone: the output buffer and the copy for an
/// inline ledger, every chunk touched for an external one
/// (`ExternalSource::unverified_range_cost`). A composite ledger's cost
/// depends on the components the range touches, which only the read
/// resolves: `None`, and the read charges as it goes.
pub(super) fn ledger_read_cost(
    ledger: &LedgerSource,
    offset: u64,
    length: u64,
) -> Result<Option<Work>, StoreError> {
    match ledger {
        LedgerSource::Inline(_) => Ok(Some(
            Work::default()
                .with(Dimension::BytesAllocated, length)
                .with(Dimension::BytesRead, length),
        )),
        LedgerSource::External(source) => source.unverified_range_cost(offset, length).map(Some),
        LedgerSource::Composite(_) => Ok(None),
    }
}

/// Bytes `[offset, offset + length)` of the ledger, on `work`. The
/// cursor's complete ledger digest checks every byte before staging becomes
/// visible.
pub(super) fn read_ledger(
    ledger: &mut LedgerSource,
    snapshot: &NamespaceSnapshot,
    offset: u64,
    length: u64,
    work: &mut dyn Meter,
) -> Result<Vec<u8>, StoreError> {
    match ledger {
        LedgerSource::Inline(record) => {
            let Representation::Inline { bytes } = record.representation() else {
                return Err(StoreError::Internal(
                    "an inline ledger source holds a non-inline record".into(),
                ));
            };
            let start = usize::try_from(offset)
                .map_err(|_| StoreError::Internal("ledger offset exceeds address space".into()))?;
            let end = offset
                .checked_add(length)
                .and_then(|end| usize::try_from(end).ok())
                .ok_or_else(|| StoreError::Internal("ledger end exceeds address space".into()))?;
            let part = bytes
                .get(start..end)
                .ok_or_else(|| StoreError::Internal("ledger read past its inline row".into()))?;
            work.charge_all(&[
                (Dimension::BytesAllocated, length),
                (Dimension::BytesRead, length),
            ])?;
            let mut out = ReadView::reserve(length)?;
            out.extend_from_slice(part);
            Ok(out)
        }
        LedgerSource::External(source) => source.range(offset, length, work),
        LedgerSource::Composite(identity) => snapshot.view().range(identity, offset, length, work),
    }
}

/// The root identity the epoch index names for `epoch` of `ns` in `txn`, on
/// `work`: the lookup charged before it runs, the stored key before it is
/// interpreted. The index key is inline and allocates nothing.
pub(super) fn indexed_root(
    txn: &ReadTransaction,
    ns: &NamespaceRef,
    epoch: u64,
    work: &mut dyn Meter,
) -> Result<Kappa, StoreError> {
    work.charge(Dimension::Entries, 1)?;
    let epochs = txn.open_table(EPOCH_INDEX).map_err(crate::error::redb)?;
    let index_key = epoch_idx_key(ns, epoch);
    let stored = epochs
        .get(index_key.as_slice())
        .map_err(crate::error::redb)?
        .ok_or_else(|| {
            StoreError::NotFound(format!(
                "epoch {epoch} of namespace {} is not indexed",
                hex::encode(ns.id()),
            ))
        })?;
    work.charge(Dimension::BytesRead, stored.value().len() as u64)?;
    Ok(Kappa::from_key_bytes(stored.value())?)
}
