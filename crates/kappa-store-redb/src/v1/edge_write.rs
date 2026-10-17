//! Edge records, content, and indexes in an execution-owned transaction.

use crate::{
    PersistentStore,
    epoch_blob::blob_put_in_txn,
    tables::{EDGE_ASR, EDGE_FWD, EDGE_REL, EDGE_REV, EDGES},
};
use kappa_store::{
    Axis, ClockMs, EdgeInput, Kappa, MutationOp, NamespaceRef, StoreError, VerifiedContent,
    canonical::{canonical_bytes, from_canonical},
};
use redb::ReadableTable;

fn ns_key(ns: &NamespaceRef, payload: &[u8]) -> Vec<u8> {
    let mut key = ns.id().to_vec();
    key.extend_from_slice(payload);
    key
}

impl PersistentStore {
    pub(crate) fn edge_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        input: &EdgeInput,
        content: &VerifiedContent,
    ) -> Result<bool, StoreError> {
        let raw = content.kappa().key_bytes();
        let key = ns_key(ns, &raw);
        let stored =
            self.encrypt_bytes(&crate::encrypted::bound("edge", &key), content.content())?;
        {
            let mut records = txn.open_table(EDGES).map_err(crate::error::redb)?;
            if records
                .get(key.as_slice())
                .map_err(crate::error::redb)?
                .is_some()
            {
                return Ok(false);
            }
            records
                .insert(key.as_slice(), stored.as_slice())
                .map_err(crate::error::redb)?;
        }
        blob_put_in_txn(self, txn, ns, content)?;
        // The edge record owns the edge's own content; a retaining edge
        // additionally refers to its target. Both entries are written with
        // the record so the index is a projection of the committed edge.
        crate::referrers::establish(
            self,
            txn,
            content.kappa(),
            &crate::referrers::Referrer::edge_record(ns, content.kappa()),
        )?;
        if input.relation.gc_reachable() {
            crate::referrers::establish(
                self,
                txn,
                &input.target,
                &crate::referrers::Referrer::edge_target(ns, content.kappa()),
            )?;
        }
        for (definition, payload) in [
            (EDGE_FWD, input.source.key_bytes()),
            (EDGE_REV, input.target.key_bytes()),
            (EDGE_REL, canonical_bytes(&input.relation)),
            (EDGE_ASR, input.asserter.key_bytes()),
        ] {
            let key = ns_key(ns, &payload);
            txn.open_multimap_table(definition)
                .map_err(crate::error::redb)?
                .insert(key.as_slice(), raw.as_slice())
                .map_err(crate::error::redb)?;
        }
        Ok(true)
    }

    pub(crate) fn edge_mutation_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        input: &EdgeInput,
        now: ClockMs,
    ) -> Result<Kappa, StoreError> {
        let content = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(input))?;
        if self.edge_put_in_txn(txn, ns, input, &content)? {
            self.record_mutation_in_txn(
                txn,
                ns,
                MutationOp::EdgePut,
                content.kappa().clone(),
                now,
                Some(input.relation.to_string()),
            )?;
        }
        Ok(content.kappa().clone())
    }

    pub(crate) fn edge_delete_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        identity: &Kappa,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let raw = identity.key_bytes();
        let key = ns_key(ns, &raw);
        let input: EdgeInput = {
            let mut records = txn.open_table(EDGES).map_err(crate::error::redb)?;
            let input = match records.get(key.as_slice()).map_err(crate::error::redb)? {
                Some(value) => from_canonical(
                    &self.decrypt_bytes(&crate::encrypted::bound("edge", &key), value.value())?,
                )?,
                None => return Ok(()),
            };
            records.remove(key.as_slice()).map_err(crate::error::redb)?;
            input
        };
        crate::referrers::release(
            self,
            txn,
            identity,
            &crate::referrers::Referrer::edge_record(ns, identity),
        )?;
        if input.relation.gc_reachable() {
            crate::referrers::release(
                self,
                txn,
                &input.target,
                &crate::referrers::Referrer::edge_target(ns, identity),
            )?;
        }
        for (definition, payload) in [
            (EDGE_FWD, input.source.key_bytes()),
            (EDGE_REV, input.target.key_bytes()),
            (EDGE_REL, canonical_bytes(&input.relation)),
            (EDGE_ASR, input.asserter.key_bytes()),
        ] {
            let key = ns_key(ns, &payload);
            txn.open_multimap_table(definition)
                .map_err(crate::error::redb)?
                .remove(key.as_slice(), raw.as_slice())
                .map_err(crate::error::redb)?;
        }
        self.record_mutation_in_txn(
            txn,
            ns,
            MutationOp::EdgeDelete,
            identity.clone(),
            now,
            Some(input.relation.to_string()),
        )
    }
}
