//! Tag records, digest state, and ledger writes in an execution-owned transaction.

use crate::{PersistentStore, tables::TAGS};
use kappa_store::{
    ClockMs, MutationOp, NamespaceRef, StoreError, TagEntry, TagUpdate,
    canonical::{canonical_bytes, from_canonical},
};
use redb::ReadableTable;

impl PersistentStore {
    pub(crate) fn tag_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        name: &str,
        update: &TagUpdate,
        now: ClockMs,
    ) -> Result<TagEntry, StoreError> {
        let key = super::tag::tag_key(ns, name);
        let (entry, existing) = {
            let mut table = txn.open_table(TAGS).map_err(crate::error::redb)?;
            let existing: Option<TagEntry> = table
                .get(key.as_slice())
                .map_err(crate::error::redb)?
                .map(|guard| {
                    self.decrypt_bytes(&super::tag::tag_context(&key), guard.value())
                        .and_then(|bytes| Ok(from_canonical(&bytes)?))
                })
                .transpose()?;
            let entry = kappa_store::tag_update::prepare_tag_update(
                ns,
                name,
                existing.as_ref(),
                update,
                now,
            )?;
            let stored =
                self.encrypt_bytes(&super::tag::tag_context(&key), &canonical_bytes(&entry))?;
            table
                .insert(key.as_slice(), stored.as_slice())
                .map_err(crate::error::redb)?;
            (entry, existing)
        };
        // The reverse-reference index follows the tag in the same
        // transaction. Only a direct tag refers to content; a symbolic tag
        // names another tag and its placeholder digest is not a reference.
        let referrer = crate::referrers::Referrer::tag(ns, name)?;
        let old_target = existing
            .as_ref()
            .filter(|tag| tag.symref.is_none())
            .map(|tag| &tag.kappa);
        let new_target = entry.symref.is_none().then_some(&entry.kappa);
        if old_target != new_target {
            if let Some(previous) = old_target {
                crate::referrers::release(self, txn, previous, &referrer)?;
            }
            if let Some(next) = new_target {
                crate::referrers::establish(self, txn, next, &referrer)?;
            }
        }
        self.record_mutation_in_txn(
            txn,
            ns,
            MutationOp::TagSet,
            entry.kappa.clone(),
            now,
            Some(name.to_string()),
        )?;
        self.update_tag_state_in_txn(
            txn,
            ns,
            name,
            existing.as_ref().map(|tag| &tag.kappa),
            Some(&entry.kappa),
        )?;
        Ok(entry)
    }

    pub(crate) fn tag_delete_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        name: &str,
        now: ClockMs,
    ) -> Result<TagEntry, StoreError> {
        let key = super::tag::tag_key(ns, name);
        let existing: TagEntry = {
            let mut table = txn.open_table(TAGS).map_err(crate::error::redb)?;
            let guard = table
                .get(key.as_slice())
                .map_err(crate::error::redb)?
                .ok_or_else(|| StoreError::NotFound(format!("{ns}/{name}")))?;
            let existing = from_canonical(
                &self.decrypt_bytes(&super::tag::tag_context(&key), guard.value())?,
            )?;
            drop(guard);
            table.remove(key.as_slice()).map_err(crate::error::redb)?;
            existing
        };
        if existing.symref.is_none() {
            crate::referrers::release(
                self,
                txn,
                &existing.kappa,
                &crate::referrers::Referrer::tag(ns, name)?,
            )?;
        }
        self.record_mutation_in_txn(
            txn,
            ns,
            MutationOp::TagDelete,
            existing.kappa.clone(),
            now,
            Some(name.to_string()),
        )?;
        self.update_tag_state_in_txn(txn, ns, name, Some(&existing.kappa), None)?;
        Ok(existing)
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
        let update = TagUpdate::Set {
            kappa: Kappa::sha256(b"staged"),
        };
        let entry = store.tag_put_in_txn(write, &ns, "first", &update, now)?;
        store.tag_put_in_txn(write, &ns, "second", &update, now)?;
        let edge = kappa_store::EdgeInput {
            source: Kappa::sha256(b"source"),
            target: entry.kappa.clone(),
            relation: kappa_store::EdgeRelation::Builtin(kappa_store::BuiltinRelation::Owns),
            asserter: Kappa::sha256(b"asserter"),
            created_at_ms: now.as_i64(),
            metadata: None,
        };
        let edge_identity = store.edge_mutation_put_in_txn(write, &ns, &edge, now)?;
        assert!(!store.blob_exists_in(&ns, &edge_identity)?);
        assert!(matches!(
            store.tag_get_raw(&ns, "first"),
            Err(StoreError::NotFound(_))
        ));
        assert_eq!(store.epoch_state(&ns)?, before);
        assert_eq!(store.tag_state_in_txn(write, &ns)?.1, 2);
        assert_eq!(
            store.tag_delete_in_txn(write, &ns, "first", now)?.kappa,
            entry.kappa
        );
        let prepared = store.prepare_test_writer(writer, &ns, now)?;
        let root = prepared.root().clone();
        assert!(matches!(
            store.epoch_current(&ns),
            Err(StoreError::NotFound(_))
        ));
        assert!(!store.blob_exists_in(&ns, root.kappa())?);
        drop(prepared);
        assert!(!store.blob_exists_in(&ns, root.kappa())?);
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
        store.tag_put_in_txn(&writer.txn, &ns, "first", &update, now)?;
        store.tag_put_in_txn(&writer.txn, &ns, "second", &update, now)?;
        let prepared = store.prepare_test_writer(writer, &ns, now)?;
        let root = prepared.root().clone();
        let identity = root.kappa().clone();
        assert!(matches!(
            store.tag_get_raw(&ns, "first"),
            Err(StoreError::NotFound(_))
        ));
        assert!(matches!(
            store.epoch_current(&ns),
            Err(StoreError::NotFound(_))
        ));
        prepared.publish()?;
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
