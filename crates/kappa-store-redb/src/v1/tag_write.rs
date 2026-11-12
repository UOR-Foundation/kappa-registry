//! Tag writes in an execution-owned transaction: the domain methods decide
//! the entry under shared policy (`tag_update`) and apply it through the
//! transition boundary (`transition_apply`), which calls the row helpers
//! here.

use crate::transition_apply::{RedbPayload, TxnWriter};
use crate::{PersistentStore, tables::TAGS};
use kappa_store::transition::RecordTransition;
use kappa_store::work::Meter;
use kappa_store::{
    ClockMs, NamespaceRef, StoreError, TagEntry, TagUpdate, canonical::canonical_bytes,
};

impl PersistentStore {
    /// The tag `name` of `ns` as `txn` holds it, read on `work`
    /// (`tag::tag_row`).
    fn tag_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        name: &str,
        work: &mut dyn Meter,
    ) -> Result<Option<TagEntry>, StoreError> {
        let table = txn.open_table(TAGS).map_err(crate::error::redb)?;
        super::tag::tag_row(self, &table, ns, name, work)
    }

    pub(crate) fn tag_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        name: &str,
        update: &TagUpdate,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<TagEntry, StoreError> {
        let existing = self.tag_in_txn(txn, ns, name, meter)?;
        let entry =
            kappa_store::tag_update::prepare_tag_update(ns, name, existing.as_ref(), update, now)?;
        TxnWriter::new(self, txn, ns, now, meter)?.apply(
            RecordTransition::TagSet(entry.clone()),
            RedbPayload::NoResources,
        )?;
        Ok(entry)
    }

    pub(crate) fn tag_delete_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        name: &str,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<TagEntry, StoreError> {
        let existing = self
            .tag_in_txn(txn, ns, name, meter)?
            .ok_or_else(|| StoreError::NotFound(format!("{ns}/{name}")))?;
        TxnWriter::new(self, txn, ns, now, meter)?.apply(
            RecordTransition::TagDelete(existing.clone()),
            RedbPayload::NoResources,
        )?;
        Ok(existing)
    }
}

impl TxnWriter<'_> {
    /// Hold `entry` as its tag, move the tag's content reference from the
    /// previous direct target to the new one, and update the tag-state
    /// digest. Only a direct tag refers to content; a symbolic tag names
    /// another tag and its placeholder digest is not a reference.
    pub(crate) fn apply_tag_set(&self, entry: &TagEntry) -> Result<(), StoreError> {
        let (store, txn, ns) = (self.store, self.txn, self.ns);
        let existing = self.metered(|work| store.tag_in_txn(txn, ns, &entry.name, work))?;
        let key = super::tag::tag_key(ns, &entry.name);
        let stored =
            store.encrypt_bytes(&super::tag::tag_context(&key), &canonical_bytes(entry))?;
        txn.open_table(TAGS)
            .map_err(crate::error::redb)?
            .insert(key.as_slice(), stored.as_slice())
            .map_err(crate::error::redb)?;
        let referrer = crate::referrers::Referrer::tag(ns, &entry.name)?;
        let old_target = existing
            .as_ref()
            .filter(|tag| tag.symref.is_none())
            .map(|tag| &tag.kappa);
        let new_target = entry.symref.is_none().then_some(&entry.kappa);
        if old_target != new_target {
            if let Some(previous) = old_target {
                crate::referrers::release(store, txn, ns, previous, &referrer)?;
            }
            if let Some(next) = new_target {
                crate::referrers::establish(store, txn, ns, next, &referrer)?;
            }
        }
        store.update_tag_state_in_txn(
            txn,
            ns,
            &entry.name,
            existing.as_ref().map(|tag| &tag.kappa),
            Some(&entry.kappa),
        )
    }

    /// Remove exactly the tag `entry` names, releasing its content
    /// reference and updating the tag-state digest. A row that differs from
    /// the entry the transition removes is refused.
    pub(crate) fn apply_tag_delete(&self, entry: &TagEntry) -> Result<(), StoreError> {
        let (store, txn, ns) = (self.store, self.txn, self.ns);
        let held = self.metered(|work| store.tag_in_txn(txn, ns, &entry.name, work))?;
        if held.as_ref() != Some(entry) {
            return Err(StoreError::Internal(format!(
                "tag {} removal names an entry the namespace does not hold",
                entry.name
            )));
        }
        let key = super::tag::tag_key(ns, &entry.name);
        txn.open_table(TAGS)
            .map_err(crate::error::redb)?
            .remove(key.as_slice())
            .map_err(crate::error::redb)?;
        if entry.symref.is_none() {
            crate::referrers::release(
                store,
                txn,
                ns,
                &entry.kappa,
                &crate::referrers::Referrer::tag(ns, &entry.name)?,
            )?;
        }
        store.update_tag_state_in_txn(txn, ns, &entry.name, Some(&entry.kappa), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_store::{BlobStore, EpochStore, Kappa, TagStore};
    use redb::{ReadableDatabase, ReadableTableMetadata};

    #[test]
    fn owned_transaction_retains_private_tags_state_and_ledger_until_commit()
    -> Result<(), Box<dyn std::error::Error>> {
        let store = crate::test_support::persistent_store()?.into_store();
        let ns = NamespaceRef::deterministic("owned-execution");
        let now = ClockMs::from_raw(1000);
        let writer = store.test_writer(&ns)?;
        let before = store.epoch_state(&ns)?;
        let write = &writer.txn;
        let meter = &mut kappa_store::work::WorkMeter::unbounded();
        let update = TagUpdate::Set {
            kappa: Kappa::sha256(b"staged"),
        };
        let entry = store.tag_put_in_txn(write, &ns, "first", &update, now, meter)?;
        store.tag_put_in_txn(write, &ns, "second", &update, now, meter)?;
        let edge = kappa_store::EdgeInput {
            source: Kappa::sha256(b"source"),
            target: entry.kappa.clone(),
            relation: kappa_store::EdgeRelation::Builtin(kappa_store::BuiltinRelation::Owns),
            asserter: Kappa::sha256(b"asserter"),
            created_at_ms: now.as_i64(),
            metadata: None,
        };
        let edge_identity = store.edge_mutation_put_in_txn(write, &ns, &edge, now, meter)?;
        assert!(!store.blob_exists_in(&ns, &edge_identity)?);
        assert!(matches!(
            store.tag_get_raw(&ns, "first"),
            Err(StoreError::NotFound(_))
        ));
        assert_eq!(store.epoch_state(&ns)?, before);
        assert_eq!(store.tag_state_in_txn(write, &ns)?.1, 2);
        assert_eq!(
            store
                .tag_delete_in_txn(write, &ns, "first", now, meter)?
                .kappa,
            entry.kappa
        );
        let prepared = store.prepare_test_writer(writer, &ns, now)?;
        let ledger = prepared.ledger().clone();
        assert!(matches!(
            store.epoch_current(&ns),
            Err(StoreError::NotFound(_))
        ));
        assert!(!store.blob_exists_in(&ns, &ledger)?);
        drop(prepared);
        assert!(!store.blob_exists_in(&ns, &ledger)?);
        assert!(matches!(
            store.epoch_current(&ns),
            Err(StoreError::NotFound(_))
        ));
        assert_eq!(store.epoch_state(&ns)?, before);
        assert!(matches!(
            store.tag_get_raw(&ns, "second"),
            Err(StoreError::NotFound(_))
        ));
        let (db, _active) = store.namespace_db(&ns)?;
        let read = db.begin_read()?;
        let ledger = read.open_table(crate::tables::MUTATION_BUFFER)?;
        assert_eq!(ledger.len()?, 0);
        assert!(!store.blob_exists_in(&ns, &edge_identity)?);
        let edges = read.open_table(crate::tables::EDGES)?;
        assert_eq!(edges.len()?, 0);
        Ok(())
    }

    #[test]
    fn staged_tags_and_signed_epoch_publish_together_and_survive_reopen()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = kappa_fixture::FixtureRoot::temporary()?;
        let spec = crate::test_support::PersistentSpec::new().in_root(&root);
        let store = spec.clone().acquire()?.into_store();
        let ns = NamespaceRef::deterministic("atomic-epoch");
        let now = ClockMs::from_raw(1000);
        let writer = store.test_writer(&ns)?;
        let update = TagUpdate::Set {
            kappa: Kappa::sha256(b"staged"),
        };
        let meter = &mut kappa_store::work::WorkMeter::unbounded();
        store.tag_put_in_txn(&writer.txn, &ns, "first", &update, now, meter)?;
        store.tag_put_in_txn(&writer.txn, &ns, "second", &update, now, meter)?;
        let prepared = store.prepare_test_writer(writer, &ns, now)?;
        assert!(matches!(
            store.tag_get_raw(&ns, "first"),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.epoch_current(&ns),
            Err(StoreError::NotFound(_))
        ));
        let (_, identity) = prepared.publish()?;
        let root = store.epoch_get(&identity)?;
        assert_eq!(store.epoch_current(&ns)?, (1, identity.clone()));
        assert_eq!(
            store.tag_get_raw(&ns, "first")?.kappa,
            Kappa::sha256(b"staged")
        );
        let ledger = store.blob_get_in(&ns, root.ledger_root())?;
        kappa_store::epoch_publication::verify_persisted_epoch(
            &root,
            &store.authority.load(),
            &ledger,
            meter,
        )?;
        drop(store);
        let reopened = spec.acquire()?.into_store();
        assert_eq!(reopened.epoch_current(&ns)?, (1, identity));
        assert_eq!(reopened.epoch_state(&ns)?.1, 2);
        assert_eq!(
            reopened.tag_get_raw(&ns, "second")?.kappa,
            Kappa::sha256(b"staged")
        );
        Ok(())
    }
}
