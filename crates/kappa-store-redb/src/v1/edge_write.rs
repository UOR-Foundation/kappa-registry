//! Edge records, content, and indexes in an execution-owned transaction.

use crate::transition_apply::{RedbPayload, TxnWriter};
use crate::{
    PersistentStore,
    epoch_blob::blob_put_in_txn,
    tables::{EDGE_ASR, EDGE_FWD, EDGE_REL, EDGE_REV, EDGES},
};
use kappa_store::transition::RecordTransition;
use kappa_store::work::Meter;
use kappa_store::{
    Axis, ClockMs, EdgeInput, Kappa, NamespaceRef, StoreError, VerifiedContent,
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
            ns,
            content.kappa(),
            &crate::referrers::Referrer::edge_record(ns, content.kappa()),
        )?;
        if input.relation.gc_reachable() {
            crate::referrers::establish(
                self,
                txn,
                ns,
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

    /// The edge `identity` of `ns` as `txn` holds it.
    fn edge_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        identity: &Kappa,
    ) -> Result<Option<EdgeInput>, StoreError> {
        let key = ns_key(ns, &identity.key_bytes());
        txn.open_table(EDGES)
            .map_err(crate::error::redb)?
            .get(key.as_slice())
            .map_err(crate::error::redb)?
            .map(|value| {
                self.decrypt_bytes(&crate::encrypted::bound("edge", &key), value.value())
                    .and_then(|bytes| Ok(from_canonical(&bytes)?))
            })
            .transpose()
    }

    /// Put `input` as an edge of `ns`. An edge the namespace already holds
    /// is kept and records no mutation.
    pub(crate) fn edge_mutation_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        input: &EdgeInput,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<Kappa, StoreError> {
        let identity = Kappa::sha256(&canonical_bytes(input));
        if self.edge_in_txn(txn, ns, &identity)?.is_some() {
            return Ok(identity);
        }
        TxnWriter::new(self, txn, ns, now, meter)?.apply(
            RecordTransition::EdgePut(input.clone()),
            RedbPayload::NoResources,
        )
    }

    /// An edge `ns` does not hold is a no-op and records no mutation.
    pub(crate) fn edge_delete_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        identity: &Kappa,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let Some(input) = self.edge_in_txn(txn, ns, identity)? else {
            return Ok(());
        };
        TxnWriter::new(self, txn, ns, now, meter)?
            .apply(
                RecordTransition::EdgeDelete(input),
                RedbPayload::NoResources,
            )
            .map(drop)
    }
}

impl TxnWriter<'_> {
    /// Hold the edge whose evidence is `identity`, with its indexes and
    /// references. The evidence itself was installed by the boundary.
    pub(crate) fn apply_edge_put(
        &self,
        identity: &Kappa,
        input: &EdgeInput,
    ) -> Result<(), StoreError> {
        let content = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(input))?;
        if content.kappa() != identity {
            return Err(StoreError::Internal(
                "edge evidence differs from its record".into(),
            ));
        }
        if !self
            .store
            .edge_put_in_txn(self.txn, self.ns, input, &content)?
        {
            return Err(StoreError::Internal(format!(
                "edge {identity} applied twice"
            )));
        }
        Ok(())
    }

    /// Remove the edge `identity`, which must be the edge `input`, with its
    /// indexes and references.
    pub(crate) fn apply_edge_delete(
        &self,
        identity: &Kappa,
        input: &EdgeInput,
    ) -> Result<(), StoreError> {
        let (store, txn, ns) = (self.store, self.txn, self.ns);
        if store.edge_in_txn(txn, ns, identity)?.as_ref() != Some(input) {
            return Err(StoreError::Internal(format!(
                "edge deletion names {identity}, which the namespace does not hold"
            )));
        }
        let raw = identity.key_bytes();
        txn.open_table(EDGES)
            .map_err(crate::error::redb)?
            .remove(ns_key(ns, &raw).as_slice())
            .map_err(crate::error::redb)?;
        crate::referrers::release(
            store,
            txn,
            ns,
            identity,
            &crate::referrers::Referrer::edge_record(ns, identity),
        )?;
        if input.relation.gc_reachable() {
            crate::referrers::release(
                store,
                txn,
                ns,
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
        Ok(())
    }
}
