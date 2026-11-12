//! Handle reads and succession writes shared by the store's own
//! transactions and by executions reading their private writer.

use std::sync::Arc;

use redb::{ReadableMultimapTable, ReadableTable};

use kappa_store::canonical::from_canonical;
use kappa_store::capacity::CapacityPool;
use kappa_store::clock::ClockMs;
use kappa_store::error::StoreError;
use kappa_store::identity::{HandleRecord, Succession};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::{NamespaceRef, ProtocolId};
use kappa_store::page::{Page, PageRequest};
use kappa_store::succession_index::{SuccessionOutcome, plan_succession_link};
use kappa_store::transition::RecordTransition;
use kappa_store::work::{Dimension, Meter, reserve_charged};

use crate::PersistentStore;
use crate::tables;
use crate::transition_apply::{RedbPayload, TxnWriter};

/// The handle record stored as `value`, its read, decoding and the decoded
/// record charged to `work` at the stored length before it is decoded.
pub(crate) fn handle_row(value: &[u8], work: &mut dyn Meter) -> Result<HandleRecord, StoreError> {
    let length = value.len() as u64;
    work.charge_all(&[
        (Dimension::BytesRead, length),
        (Dimension::BytesDecoded, length),
        (Dimension::BytesAllocated, length),
    ])?;
    from_canonical(value).map_err(|e| StoreError::Internal(format!("handle decode: {e}")))
}

/// One handle record from any view of `ID_HANDLES`, on `work`: its key
/// built and looked up, then its row ([`handle_row`]).
pub fn handle_from_table(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    protocol: &ProtocolId,
    handle: &str,
    work: &mut dyn Meter,
) -> Result<HandleRecord, StoreError> {
    let key = crate::identity_write::handle_key(protocol, handle);
    work.charge_all(&[
        (Dimension::BytesAllocated, key.len() as u64),
        (Dimension::Entries, 1),
    ])?;
    let value = table
        .get(key.as_str())
        .map_err(crate::error::redb)?
        .ok_or_else(|| StoreError::NotFound(format!("handle {key}")))?;
    handle_row(value.value(), work)
}

/// Handles owned by `anchor`, ordered by handle key, from any view of the
/// anchor index and the handle table, on `work`: every index member is
/// examined, and every record looked up, read and decoded, charged before
/// it is done, and the result buffer charged as it grows.
pub fn handles_by_anchor_from(
    index: &impl ReadableMultimapTable<&'static [u8], &'static str>,
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    anchor: &Kappa,
    page: &PageRequest,
    work: &mut dyn Meter,
) -> Result<Page<HandleRecord>, StoreError> {
    if page.limit == 0 {
        return Ok(Page::empty());
    }
    work.charge_all(&[
        (Dimension::BytesAllocated, anchor.key_len() as u64),
        (Dimension::Entries, 1),
    ])?;
    let anchor_key = anchor.key_bytes();
    let mut results = Vec::new();
    let mut members = index
        .get(anchor_key.as_slice())
        .map_err(crate::error::redb)?;
    loop {
        work.charge(Dimension::Entries, 1)?;
        let Some(item) = members.next() else {
            break;
        };
        let item = item.map_err(crate::error::redb)?;
        let handle_key = item.value();
        if page
            .after
            .as_deref()
            .is_some_and(|after| handle_key <= after)
        {
            continue;
        }
        work.charge(Dimension::Entries, 1)?;
        if let Some(value) = table.get(handle_key).map_err(crate::error::redb)? {
            let record = handle_row(value.value(), work)?;
            if record.anchor != *anchor {
                return Err(StoreError::Internal(format!(
                    "handle anchor index mismatch: {handle_key}"
                )));
            }
            reserve_charged(work, &mut results)?;
            results.push(record);
            if results.len() > page.limit {
                break;
            }
        }
    }
    Ok(Page::from_oversized(results, page.limit, |record| {
        crate::identity_write::handle_key(&record.protocol, &record.handle)
    }))
}

/// One row of the successor index read on `meter`: an entry examined before
/// the lookup, and the bytes it holds read and decoded once found.
fn successor_row(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    anchor: &[u8],
    meter: &mut dyn Meter,
) -> Result<Option<Kappa>, StoreError> {
    meter.charge(Dimension::Entries, 1)?;
    let Some(value) = table.get(anchor).map_err(crate::error::redb)? else {
        return Ok(None);
    };
    let length = value.value().len() as u64;
    meter.charge_all(&[
        (Dimension::BytesRead, length),
        (Dimension::BytesDecoded, length),
    ])?;
    Ok(Some(
        from_canonical::<Succession>(value.value())?.new_anchor,
    ))
}

impl PersistentStore {
    /// Index a successor for its old anchor, on `meter`, the allowance of the
    /// operation writing it, its encoding held live in `storage` until its
    /// row is written. The identical record is idempotent; a different
    /// record for the same anchor conflicts. A record that would close a
    /// cycle, or make any chain through it longer than
    /// `SUCCESSION_CHAIN_MAX` links, is rejected before it is indexed, so no
    /// published record makes a chain unresolvable. The depth index is
    /// written in the same transaction as the record, which is written as
    /// the plan's own canonical encoding of it.
    pub(crate) fn succession_index_in_txn(
        txn: &redb::WriteTransaction,
        record: &Succession,
        meter: &mut dyn Meter,
        storage: &Arc<CapacityPool>,
    ) -> Result<(), StoreError> {
        let old_key = record.old_anchor.key_bytes();
        let mut table = txn
            .open_table(tables::ID_SUCCESSIONS)
            .map_err(crate::error::redb)?;
        meter.charge(Dimension::Entries, 1)?;
        let existing = table.get(old_key.as_slice()).map_err(crate::error::redb)?;
        if let Some(held) = &existing {
            meter.charge(Dimension::BytesRead, held.value().len() as u64)?;
        }
        let mut depth = txn
            .open_table(tables::ID_SUCCESSION_DEPTH)
            .map_err(crate::error::redb)?;
        let admitted = plan_succession_link(
            record,
            meter,
            storage,
            existing.as_ref().map(|value| value.value()),
            |anchor, meter| {
                meter.charge(Dimension::Entries, 1)?;
                Ok(depth
                    .get(anchor)
                    .map_err(crate::error::redb)?
                    .map_or(0, |value| value.value()))
            },
            |anchor, meter| successor_row(&table, anchor, meter),
        )?;
        drop(existing);
        let SuccessionOutcome::New(updates) = admitted.outcome else {
            return Ok(());
        };
        table
            .insert(old_key.as_slice(), admitted.canonical.as_ref())
            .map_err(crate::error::redb)?;
        // The row holds the bytes now; their live reservation ends with them.
        drop(admitted.canonical);
        for (anchor, links) in updates {
            depth
                .insert(anchor.as_slice(), links)
                .map_err(crate::error::redb)?;
        }
        Ok(())
    }

    /// Apply the signed succession record through the transition boundary,
    /// which indexes it ([`TxnWriter::apply_succession`]) and commits its
    /// evidence identity to the namespace ledger.
    ///
    /// The record's signatures were admitted by the caller's
    /// `Verified<Succession>`; this layer enforces only index invariants.
    pub(crate) fn succession_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        record: &Succession,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<Kappa, StoreError> {
        TxnWriter::new(self, txn, ns, now, meter)?.apply(
            RecordTransition::Succession(record.clone()),
            RedbPayload::NoResources,
        )
    }
}

impl TxnWriter<'_> {
    /// Index the succession record under the shared admission rule, on the
    /// allowance of the operation this writer writes for.
    pub(crate) fn apply_succession(&self, record: &Succession) -> Result<(), StoreError> {
        self.metered(|meter| {
            PersistentStore::succession_index_in_txn(
                self.txn,
                record,
                meter,
                &self.store.encoding_storage,
            )
        })?;
        self.store.discoverable(
            self.ns,
            crate::unsettled_index::DiscoveryKey::SuccessorOf(record.old_anchor.clone()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_store::work::{WorkLimit, WorkMeter};

    /// Encoding storage no test exhausts.
    fn storage() -> Arc<CapacityPool> {
        Arc::new(CapacityPool::new("test encodings", u64::MAX))
    }

    /// Index `record` on an allowance of its own, as an operation indexes on
    /// its.
    fn index(txn: &redb::WriteTransaction, record: &Succession) -> Result<(), StoreError> {
        PersistentStore::succession_index_in_txn(
            txn,
            record,
            &mut WorkMeter::unbounded(),
            &storage(),
        )
    }

    fn record(old: u8, new: u8) -> Succession {
        Succession {
            old_anchor: Kappa::sha256(&[old]),
            new_anchor: Kappa::sha256(&[new]),
            reason: kappa_store::identity::SuccessionReason::Rotation,
            effective_at_ms: 0,
            chain_anchor: None,
            prev_identifier: None,
            old_cose_signature: kappa_store::SignedPayload::empty(),
            new_cose_signature: kappa_store::SignedPayload::empty(),
        }
    }

    fn depth_of(store: &PersistentStore, anchor: u8) -> Result<Option<u64>, StoreError> {
        let read = store.registry.begin_read()?;
        let table = read
            .open_table(tables::ID_SUCCESSION_DEPTH)
            .map_err(crate::error::redb)?;
        Ok(table
            .get(Kappa::sha256(&[anchor]).key_bytes().as_slice())
            .map_err(crate::error::redb)?
            .map(|value| value.value()))
    }

    #[test]
    fn depth_index_is_durable_and_bounds_links_after_reopen()
    -> Result<(), Box<dyn std::error::Error>> {
        let spec = crate::test_support::PersistentSpec::new()
            .in_root(&kappa_fixture::FixtureRoot::temporary()?)
            .db_file("db.redb");
        // The index invariants are the same in a namespace database and in
        // the registry projection; the registry is exercised here, as
        // settlement writes it.
        {
            let store = spec.clone().acquire()?.into_store();
            let txn = store.registry.begin_write()?;
            for position in 0..63u8 {
                index(&txn, &record(position, position + 1))?;
            }
            txn.commit()?;
            // An aborted admission leaves neither record nor depth.
            let aborted = store.registry.begin_write()?;
            index(&aborted, &record(150, 151))?;
            aborted.abort()?;
        }
        let store = spec.acquire()?.into_store();
        assert_eq!(depth_of(&store, 0)?, None, "origins have no depth row");
        assert_eq!(depth_of(&store, 1)?, Some(1));
        assert_eq!(depth_of(&store, 63)?, Some(63));
        assert_eq!(depth_of(&store, 151)?, None);

        // The persisted index bounds new links: one more fits, two do not.
        let txn = store.registry.begin_write()?;
        index(&txn, &record(63, 64))?;
        assert!(matches!(
            index(&txn, &record(64, 65)),
            Err(StoreError::CapacityExceeded(_))
        ));
        assert!(matches!(
            index(&txn, &record(200, 0)),
            Err(StoreError::CapacityExceeded(_))
        ));
        txn.commit()?;
        assert_eq!(depth_of(&store, 64)?, Some(64));
        Ok(())
    }

    /// Admission runs on the allowance of the operation writing the link and
    /// the store's encoding storage: an allowance or a storage that cannot
    /// hold the record's encoding writes neither record nor depth; every
    /// lookup and the encoding are charged to the allowance, and the
    /// encoding's reservation ends once its row is written.
    #[test]
    fn indexing_charges_the_writers_allowance() -> Result<(), Box<dyn std::error::Error>> {
        let store = crate::test_support::persistent_store()?.into_store();
        let txn = store.registry.begin_write()?;
        let pool = storage();
        let mut short = WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, 0));
        assert!(matches!(
            PersistentStore::succession_index_in_txn(&txn, &record(1, 2), &mut short, &pool),
            Err(StoreError::WorkRefused(_))
        ));
        let none = Arc::new(CapacityPool::new("no encodings", 0));
        assert!(matches!(
            PersistentStore::succession_index_in_txn(
                &txn,
                &record(1, 2),
                &mut WorkMeter::unbounded(),
                &none
            ),
            Err(StoreError::CapacityExceeded(_))
        ));
        let mut meter = WorkMeter::unbounded();
        PersistentStore::succession_index_in_txn(&txn, &record(1, 2), &mut meter, &pool)?;
        assert!(
            meter.used().get(Dimension::Entries) >= 3,
            "held row, depth and walk"
        );
        assert!(meter.used().get(Dimension::BytesAllocated) > 0);
        assert_eq!(
            pool.used(),
            0,
            "the row holds the bytes; the reservation ended"
        );
        txn.commit()?;
        assert_eq!(depth_of(&store, 2)?, Some(1));
        Ok(())
    }
}
