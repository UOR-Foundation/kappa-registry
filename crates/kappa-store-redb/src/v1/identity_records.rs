//! Handle reads and succession writes shared by the store's own
//! transactions and by executions reading their private writer.

use redb::{ReadableMultimapTable, ReadableTable};

use kappa_store::VerifiedContent;
use kappa_store::axis::Axis;
use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::clock::ClockMs;
use kappa_store::epoch::MutationOp;
use kappa_store::error::StoreError;
use kappa_store::identity::{HandleRecord, Succession};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::{NamespaceRef, ProtocolId};
use kappa_store::page::{Page, PageRequest};

use crate::PersistentStore;
use crate::tables;

/// One handle record from any view of `ID_HANDLES`.
pub fn handle_from_table(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    protocol: &ProtocolId,
    handle: &str,
) -> Result<HandleRecord, StoreError> {
    let key = format!("{protocol}:{handle}");
    let value = table
        .get(key.as_str())
        .map_err(crate::error::redb)?
        .ok_or_else(|| StoreError::NotFound(format!("handle {protocol}:{handle}")))?;
    from_canonical(value.value()).map_err(|e| StoreError::Internal(format!("handle decode: {e}")))
}

/// Handles owned by `anchor`, ordered by handle key, from any view of the
/// anchor index and the handle table.
pub fn handles_by_anchor_from(
    index: &impl ReadableMultimapTable<&'static [u8], &'static str>,
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    anchor: &Kappa,
    page: &PageRequest,
) -> Result<Page<HandleRecord>, StoreError> {
    if page.limit == 0 {
        return Ok(Page::empty());
    }
    let anchor_key = anchor.key_bytes();
    let mut results = Vec::with_capacity(page.limit.min(1000));
    for item in index
        .get(anchor_key.as_slice())
        .map_err(crate::error::redb)?
    {
        let item = item.map_err(crate::error::redb)?;
        let handle_key = item.value();
        if page
            .after
            .as_deref()
            .is_some_and(|after| handle_key <= after)
        {
            continue;
        }
        if let Some(value) = table.get(handle_key).map_err(crate::error::redb)? {
            let record: HandleRecord = from_canonical(value.value())
                .map_err(|e| StoreError::Internal(format!("handle decode: {e}")))?;
            if record.anchor != *anchor {
                return Err(StoreError::Internal(format!(
                    "handle anchor index mismatch: {handle_key}"
                )));
            }
            results.push(record);
            if results.len() > page.limit {
                break;
            }
        }
    }
    Ok(Page::from_oversized(results, page.limit, |record| {
        format!("{}:{}", record.protocol, record.handle)
    }))
}

impl PersistentStore {
    /// Index a successor for its old anchor. The identical record is
    /// idempotent; a different record for the same anchor conflicts. A record
    /// that would close a cycle, or make any chain through it longer than
    /// `SUCCESSION_CHAIN_MAX` links, is rejected before it is indexed, so no
    /// published record makes a chain unresolvable. The depth index is
    /// written in the same transaction as the record.
    pub(crate) fn succession_index_in_txn(
        txn: &redb::WriteTransaction,
        record: &Succession,
    ) -> Result<(), StoreError> {
        if record.old_anchor == record.new_anchor {
            return Err(StoreError::Rejected(
                "succession cannot target itself".into(),
            ));
        }
        let old_key = record.old_anchor.key_bytes();
        let bytes = canonical_bytes(record);
        let mut table = txn
            .open_table(tables::ID_SUCCESSIONS)
            .map_err(crate::error::redb)?;
        if let Some(existing) = table.get(old_key.as_slice()).map_err(crate::error::redb)? {
            if existing.value() != bytes.as_slice() {
                return Err(StoreError::Conflict(
                    "anchor already has another succession record".into(),
                ));
            }
            return Ok(());
        }
        let mut depth = txn
            .open_table(tables::ID_SUCCESSION_DEPTH)
            .map_err(crate::error::redb)?;
        let updates = kappa_store::succession_index::plan_succession_link(
            record,
            |anchor| {
                Ok(depth
                    .get(anchor)
                    .map_err(crate::error::redb)?
                    .map_or(0, |value| value.value()))
            },
            |anchor| {
                table
                    .get(anchor)
                    .map_err(crate::error::redb)?
                    .map(|value| {
                        from_canonical::<Succession>(value.value()).map(|next| next.new_anchor)
                    })
                    .transpose()
                    .map_err(StoreError::from)
            },
        )?;
        table
            .insert(old_key.as_slice(), bytes.as_slice())
            .map_err(crate::error::redb)?;
        for (anchor, links) in updates {
            depth
                .insert(anchor.as_slice(), links)
                .map_err(crate::error::redb)?;
        }
        Ok(())
    }

    /// Publish the signed succession record, index it, and commit its
    /// content identity to the namespace ledger.
    ///
    /// The record's signatures were admitted by the caller's
    /// `Verified<Succession>`; this layer enforces only index invariants.
    pub(crate) fn succession_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        record: &Succession,
        now: ClockMs,
    ) -> Result<Kappa, StoreError> {
        Self::succession_index_in_txn(txn, record)?;
        let content = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(record))?;
        crate::epoch_blob::blob_put_in_txn(self, txn, ns, &content)?;
        self.record_mutation_in_txn(
            txn,
            ns,
            MutationOp::AnchorOrigin,
            content.kappa().clone(),
            now,
            Some(kappa_store::identity_scope::AnchorScope::Succession.to_context()),
        )?;
        Ok(content.kappa().clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use redb::ReadableDatabase;

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
        let read = store.registry.begin_read().map_err(crate::error::redb)?;
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
            let txn = store.registry.begin_write().map_err(crate::error::redb)?;
            for index in 0..63u8 {
                PersistentStore::succession_index_in_txn(&txn, &record(index, index + 1))?;
            }
            txn.commit().map_err(crate::error::redb)?;
            // An aborted admission leaves neither record nor depth.
            let aborted = store.registry.begin_write().map_err(crate::error::redb)?;
            PersistentStore::succession_index_in_txn(&aborted, &record(150, 151))?;
            aborted.abort().map_err(crate::error::redb)?;
        }
        let store = spec.acquire()?.into_store();
        assert_eq!(depth_of(&store, 0)?, None, "origins have no depth row");
        assert_eq!(depth_of(&store, 1)?, Some(1));
        assert_eq!(depth_of(&store, 63)?, Some(63));
        assert_eq!(depth_of(&store, 151)?, None);

        // The persisted index bounds new links: one more fits, two do not.
        let txn = store.registry.begin_write().map_err(crate::error::redb)?;
        PersistentStore::succession_index_in_txn(&txn, &record(63, 64))?;
        assert!(matches!(
            PersistentStore::succession_index_in_txn(&txn, &record(64, 65)),
            Err(StoreError::CapacityExceeded(_))
        ));
        assert!(matches!(
            PersistentStore::succession_index_in_txn(&txn, &record(200, 0)),
            Err(StoreError::CapacityExceeded(_))
        ));
        txn.commit().map_err(crate::error::redb)?;
        assert_eq!(depth_of(&store, 64)?, Some(64));
        Ok(())
    }
}
