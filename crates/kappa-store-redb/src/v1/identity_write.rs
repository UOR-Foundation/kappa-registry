//! Namespace-scoped identity claims written inside a caller-owned writer:
//! bindings, assertions, revocations and watermarks. Each write records
//! its ledger mutation in the same transaction, with the scope
//! (`AnchorScope`) that tells settlement which row to project. The
//! anchor-keyed records are in `identity_anchor_write`.

use kappa_store::axis::Axis;
use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::clock::ClockMs;
use kappa_store::epoch::MutationOp;
use kappa_store::error::StoreError;
use kappa_store::identity::{IdentityAssertion, IdentityBinding, Revocation, Watermark};
use kappa_store::identity_scope::AnchorScope;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::{NamespaceRef, ProtocolId};
use redb::ReadableTable;

use crate::PersistentStore;
use crate::tables;
use crate::unsettled_index::DiscoveryKey;

pub fn binding_key(ns: &NamespaceRef, source: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(16 + source.len());
    key.extend_from_slice(ns.id());
    key.extend_from_slice(source.as_bytes());
    key
}

pub fn encode_subject_idx_value(asserter: &Kappa, assertion_kappa: &Kappa) -> Vec<u8> {
    let akb = asserter.key_bytes();
    let kkb = assertion_kappa.key_bytes();
    let mut buf = Vec::with_capacity(akb.len() + kkb.len());
    buf.extend_from_slice(&akb);
    buf.extend_from_slice(&kkb);
    buf
}

pub fn handle_key(protocol: &ProtocolId, handle: &str) -> String {
    format!("{protocol}:{handle}")
}

impl PersistentStore {
    /// Record `AnchorOrigin` evidence naming `anchor` and the row `scope`
    /// changed.
    pub(crate) fn record_anchor_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        anchor: &Kappa,
        scope: &AnchorScope,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        self.record_mutation_in_txn(
            txn,
            ns,
            MutationOp::AnchorOrigin,
            anchor.clone(),
            now,
            Some(scope.to_context()),
        )
    }

    pub(crate) fn binding_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        binding: &IdentityBinding,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let key = binding_key(ns, &binding.source);
        {
            let mut table = txn
                .open_table(tables::ID_BINDINGS)
                .map_err(crate::error::redb)?;
            let mut bindings: Vec<IdentityBinding> =
                match table.get(key.as_slice()).map_err(crate::error::redb)? {
                    Some(val) => from_canonical(val.value())
                        .map_err(|e| StoreError::Internal(format!("binding decode: {e}")))?,
                    None => Vec::new(),
                };
            if let Some(existing) = bindings.iter_mut().find(|b| b.target == binding.target) {
                *existing = binding.clone();
            } else {
                bindings.push(binding.clone());
            }
            bindings.sort_by_key(|binding| std::cmp::Reverse(binding.verified_at_ms));
            let encoded = canonical_bytes(&bindings);
            table
                .insert(key.as_slice(), encoded.as_slice())
                .map_err(crate::error::redb)?;
            let mut idx = txn
                .open_multimap_table(tables::ID_BINDING_SRC_IDX)
                .map_err(crate::error::redb)?;
            idx.insert(binding.source.as_str(), ns.id().as_slice())
                .map_err(crate::error::redb)?;
        }
        self.record_anchor_in_txn(
            txn,
            ns,
            &binding.target,
            &AnchorScope::Binding {
                source: binding.source.clone(),
            },
            now,
        )
    }

    /// Absent bindings are a no-op and record no mutation.
    pub(crate) fn binding_delete_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        source: &str,
        target: &Kappa,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let key = binding_key(ns, source);
        {
            let mut table = txn
                .open_table(tables::ID_BINDINGS)
                .map_err(crate::error::redb)?;
            let existing: Vec<IdentityBinding> =
                match table.get(key.as_slice()).map_err(crate::error::redb)? {
                    Some(val) => from_canonical(val.value())
                        .map_err(|e| StoreError::Internal(format!("binding decode: {e}")))?,
                    None => return Ok(()),
                };
            let filtered: Vec<IdentityBinding> = existing
                .into_iter()
                .filter(|b| b.target != *target)
                .collect();
            if filtered.is_empty() {
                table.remove(key.as_slice()).map_err(crate::error::redb)?;
                txn.open_multimap_table(tables::ID_BINDING_SRC_IDX)
                    .map_err(crate::error::redb)?
                    .remove(source, ns.id().as_slice())
                    .map_err(crate::error::redb)?;
            } else {
                let encoded = canonical_bytes(&filtered);
                table
                    .insert(key.as_slice(), encoded.as_slice())
                    .map_err(crate::error::redb)?;
            }
        }
        self.record_anchor_in_txn(
            txn,
            ns,
            target,
            &AnchorScope::Binding {
                source: source.to_string(),
            },
            now,
        )
    }

    pub(crate) fn assertion_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        assertion: &IdentityAssertion,
        now: ClockMs,
    ) -> Result<Kappa, StoreError> {
        let bytes = canonical_bytes(assertion);
        let kappa = Kappa::compute(Axis::Sha256, &bytes)?;
        let kappa_key = kappa.key_bytes();
        let asserter_key = assertion.asserter.key_bytes();
        let subject_key = format!("{}\x00{}", assertion.subject, assertion.facet);
        let subject_idx_value = encode_subject_idx_value(&assertion.asserter, &kappa);
        {
            let mut t = txn
                .open_table(tables::ID_ASSERTIONS)
                .map_err(crate::error::redb)?;
            t.insert(kappa_key.as_slice(), bytes.as_slice())
                .map_err(crate::error::redb)?;
            let mut ai = txn
                .open_multimap_table(tables::ID_ASSERTION_ASSERTER_IDX)
                .map_err(crate::error::redb)?;
            ai.insert(asserter_key.as_slice(), kappa_key.as_slice())
                .map_err(crate::error::redb)?;
            let mut si = txn
                .open_multimap_table(tables::ID_ASSERTION_SUBJECT_IDX)
                .map_err(crate::error::redb)?;
            si.insert(subject_key.as_str(), subject_idx_value.as_slice())
                .map_err(crate::error::redb)?;
        }
        self.record_mutation_in_txn(
            txn,
            ns,
            MutationOp::AssertionPublish,
            kappa.clone(),
            now,
            None,
        )?;
        Ok(kappa)
    }

    pub(crate) fn revocation_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        revocation: &Revocation,
        now: ClockMs,
    ) -> Result<Kappa, StoreError> {
        let bytes = canonical_bytes(revocation);
        let kappa = Kappa::compute(Axis::Sha256, &bytes)?;
        let kappa_key = kappa.key_bytes();
        let asserter_key = revocation.asserter.key_bytes();
        {
            let mut t = txn
                .open_table(tables::ID_REVOCATIONS)
                .map_err(crate::error::redb)?;
            t.insert(kappa_key.as_slice(), bytes.as_slice())
                .map_err(crate::error::redb)?;
            let mut idx = txn
                .open_multimap_table(tables::ID_REVOCATION_ASSERTER_IDX)
                .map_err(crate::error::redb)?;
            idx.insert(asserter_key.as_slice(), kappa_key.as_slice())
                .map_err(crate::error::redb)?;
        }
        self.record_mutation_in_txn(
            txn,
            ns,
            MutationOp::RevocationPublish,
            kappa.clone(),
            now,
            None,
        )?;
        self.discoverable(ns, DiscoveryKey::RevocationsBy(revocation.asserter.clone()))?;
        Ok(kappa)
    }

    /// Record that the open transaction of `ns` makes `key` answerable:
    /// the publication registers it in the unsettled index before it
    /// commits, so a query by the predicate finds this namespace from that
    /// commit on, before settlement projects the row.
    fn discoverable(&self, ns: &NamespaceRef, key: DiscoveryKey) -> Result<(), StoreError> {
        self.controller(ns)?
            .installed_rows
            .lock()
            .map_err(|_| StoreError::Internal("installed row set poisoned".into()))?
            .push(key);
        Ok(())
    }

    pub(crate) fn watermark_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        watermark: &Watermark,
        now: ClockMs,
    ) -> Result<Kappa, StoreError> {
        let bytes = canonical_bytes(watermark);
        let kappa = Kappa::compute(Axis::Sha256, &bytes)?;
        let kappa_key = kappa.key_bytes();
        let asserter_key = watermark.asserter.key_bytes();
        {
            let mut t = txn
                .open_table(tables::ID_WATERMARKS)
                .map_err(crate::error::redb)?;
            t.insert(kappa_key.as_slice(), bytes.as_slice())
                .map_err(crate::error::redb)?;
            let mut idx = txn
                .open_multimap_table(tables::ID_WATERMARK_ASSERTER_IDX)
                .map_err(crate::error::redb)?;
            idx.insert(asserter_key.as_slice(), kappa_key.as_slice())
                .map_err(crate::error::redb)?;
        }
        self.record_anchor_in_txn(txn, ns, &kappa, &AnchorScope::Watermark, now)?;
        self.discoverable(ns, DiscoveryKey::WatermarksBy(watermark.asserter.clone()))?;
        Ok(kappa)
    }
}
