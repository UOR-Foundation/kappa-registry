//! Namespace-scoped identity claims written inside a caller-owned writer:
//! bindings, assertions, revocations and watermarks. Each write applies
//! its shared transition (`kappa_store::transition`) through the boundary
//! (`transition_apply`), which installs the exact record as evidence,
//! calls the row helpers here, and records the mutation with the scope
//! that tells settlement which row to project. The anchor-keyed records
//! are in `identity_anchor_write`.

use kappa_store::canonical::{canonical_bytes, from_canonical};
use kappa_store::clock::ClockMs;
use kappa_store::error::StoreError;
use kappa_store::identity::{IdentityAssertion, IdentityBinding, Revocation, Watermark};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::{NamespaceRef, ProtocolId};
use kappa_store::transition::{MemberTransition, RecordTransition};
use kappa_store::work::Meter;
use redb::ReadableTable;

use crate::PersistentStore;
use crate::tables;
use crate::transition_apply::{RedbPayload, TxnWriter};
use crate::unsettled_index::DiscoveryKey;

pub fn binding_key(ns: &NamespaceRef, source: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(16 + source.len());
    key.extend_from_slice(ns.id());
    key.extend_from_slice(source.as_bytes());
    key
}

/// Bytes of the subject index member of `assertion` by `asserter`, checked.
pub fn subject_idx_value_len(asserter: &Kappa, assertion: &Kappa) -> Result<usize, StoreError> {
    asserter
        .key_len()
        .checked_add(assertion.key_len())
        .ok_or_else(|| StoreError::Internal("subject index member length overflow".into()))
}

/// The subject index member, `asserter key || assertion key`, written into
/// `output`, which must be exactly [`subject_idx_value_len`] bytes: the one
/// writer of the format.
pub fn encode_subject_idx_value_into(
    asserter: &Kappa,
    assertion: &Kappa,
    output: &mut [u8],
) -> Result<(), StoreError> {
    if output.len() != subject_idx_value_len(asserter, assertion)? {
        return Err(StoreError::Internal(
            "subject index member output has the wrong length".into(),
        ));
    }
    let (left, right) = output.split_at_mut(asserter.key_len());
    asserter.to_key_bytes(left);
    assertion.to_key_bytes(right);
    Ok(())
}

/// [`encode_subject_idx_value_into`] in one buffer of its exact length.
pub fn encode_subject_idx_value(
    asserter: &Kappa,
    assertion_kappa: &Kappa,
) -> Result<Vec<u8>, StoreError> {
    let length = subject_idx_value_len(asserter, assertion_kappa)?;
    let mut buf = Vec::new();
    buf.try_reserve_exact(length).map_err(|_| {
        StoreError::CapacityExceeded(format!(
            "a subject index member of {length} bytes could not be allocated"
        ))
    })?;
    buf.resize(length, 0);
    encode_subject_idx_value_into(asserter, assertion_kappa, &mut buf)?;
    Ok(buf)
}

pub fn handle_key(protocol: &ProtocolId, handle: &str) -> String {
    format!("{protocol}:{handle}")
}

/// The bindings `ns` holds for `source` in `txn`, newest verification first.
fn bindings_in(
    txn: &redb::WriteTransaction,
    key: &[u8],
) -> Result<Vec<IdentityBinding>, StoreError> {
    txn.open_table(tables::ID_BINDINGS)
        .map_err(crate::error::redb)?
        .get(key)
        .map_err(crate::error::redb)?
        .map_or(Ok(Vec::new()), |value| {
            from_canonical(value.value())
                .map_err(|e| StoreError::Internal(format!("binding decode: {e}")))
        })
}

impl PersistentStore {
    pub(crate) fn binding_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        binding: &IdentityBinding,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        TxnWriter::new(self, txn, ns, now, meter)?
            .apply(
                RecordTransition::Member(MemberTransition::BindingPut(binding.clone())),
                RedbPayload::NoResources,
            )
            .map(drop)
    }

    /// A binding `ns` does not hold is a no-op and records no mutation.
    pub(crate) fn binding_delete_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        source: &str,
        target: &Kappa,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<(), StoreError> {
        let Some(binding) = bindings_in(txn, &binding_key(ns, source))?
            .into_iter()
            .find(|binding| binding.target == *target)
        else {
            return Ok(());
        };
        TxnWriter::new(self, txn, ns, now, meter)?
            .apply(
                RecordTransition::Member(MemberTransition::BindingDelete(binding)),
                RedbPayload::NoResources,
            )
            .map(drop)
    }

    pub(crate) fn assertion_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        assertion: &IdentityAssertion,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<Kappa, StoreError> {
        TxnWriter::new(self, txn, ns, now, meter)?.apply(
            RecordTransition::Assertion(assertion.clone()),
            RedbPayload::NoResources,
        )
    }

    pub(crate) fn revocation_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        revocation: &Revocation,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<Kappa, StoreError> {
        TxnWriter::new(self, txn, ns, now, meter)?.apply(
            RecordTransition::Revocation(revocation.clone()),
            RedbPayload::NoResources,
        )
    }

    pub(crate) fn watermark_put_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ns: &NamespaceRef,
        watermark: &Watermark,
        now: ClockMs,
        meter: &mut dyn Meter,
    ) -> Result<Kappa, StoreError> {
        TxnWriter::new(self, txn, ns, now, meter)?.apply(
            RecordTransition::Watermark(watermark.clone()),
            RedbPayload::NoResources,
        )
    }

    /// Record that the open transaction of `ns` makes `key` answerable:
    /// the publication registers it in the unsettled index before it
    /// commits, so a query by the predicate finds this namespace from that
    /// commit on, before settlement projects the row.
    pub(crate) fn discoverable(
        &self,
        ns: &NamespaceRef,
        key: DiscoveryKey,
    ) -> Result<(), StoreError> {
        self.controller(ns)?
            .installed_rows
            .lock()
            .map_err(|_| StoreError::Internal("installed row set poisoned".into()))?
            .push(key);
        Ok(())
    }
}

impl TxnWriter<'_> {
    /// Hold `binding` for its source, replacing the binding of the same
    /// target, newest verification first, with the source index.
    pub(crate) fn apply_binding_put(&self, binding: &IdentityBinding) -> Result<(), StoreError> {
        let key = binding_key(self.ns, &binding.source);
        let mut bindings = bindings_in(self.txn, &key)?;
        if let Some(existing) = bindings.iter_mut().find(|b| b.target == binding.target) {
            *existing = binding.clone();
        } else {
            bindings.push(binding.clone());
        }
        bindings.sort_by_key(|binding| std::cmp::Reverse(binding.verified_at_ms));
        self.txn
            .open_table(tables::ID_BINDINGS)
            .map_err(crate::error::redb)?
            .insert(key.as_slice(), canonical_bytes(&bindings).as_slice())
            .map_err(crate::error::redb)?;
        self.txn
            .open_multimap_table(tables::ID_BINDING_SRC_IDX)
            .map_err(crate::error::redb)?
            .insert(binding.source.as_str(), self.ns.id().as_slice())
            .map_err(crate::error::redb)?;
        Ok(())
    }

    /// Remove exactly `binding`, which the source must hold, dropping the
    /// source index entry with the last binding.
    pub(crate) fn apply_binding_delete(&self, binding: &IdentityBinding) -> Result<(), StoreError> {
        let key = binding_key(self.ns, &binding.source);
        let existing = bindings_in(self.txn, &key)?;
        if !existing.contains(binding) {
            return Err(StoreError::Internal(
                "binding removal names a binding the namespace does not hold".into(),
            ));
        }
        let remaining: Vec<IdentityBinding> = existing
            .into_iter()
            .filter(|b| b.target != binding.target)
            .collect();
        let mut table = self
            .txn
            .open_table(tables::ID_BINDINGS)
            .map_err(crate::error::redb)?;
        if remaining.is_empty() {
            table.remove(key.as_slice()).map_err(crate::error::redb)?;
            self.txn
                .open_multimap_table(tables::ID_BINDING_SRC_IDX)
                .map_err(crate::error::redb)?
                .remove(binding.source.as_str(), self.ns.id().as_slice())
                .map_err(crate::error::redb)?;
        } else {
            table
                .insert(key.as_slice(), canonical_bytes(&remaining).as_slice())
                .map_err(crate::error::redb)?;
        }
        Ok(())
    }

    /// Hold the assertion whose evidence is `identity`, indexed by asserter
    /// and by subject and facet.
    pub(crate) fn apply_assertion(
        &self,
        identity: &Kappa,
        assertion: &IdentityAssertion,
    ) -> Result<(), StoreError> {
        let kappa_key = identity.key_bytes();
        self.txn
            .open_table(tables::ID_ASSERTIONS)
            .map_err(crate::error::redb)?
            .insert(kappa_key.as_slice(), canonical_bytes(assertion).as_slice())
            .map_err(crate::error::redb)?;
        self.txn
            .open_multimap_table(tables::ID_ASSERTION_ASSERTER_IDX)
            .map_err(crate::error::redb)?
            .insert(
                assertion.asserter.key_bytes().as_slice(),
                kappa_key.as_slice(),
            )
            .map_err(crate::error::redb)?;
        let subject_key = format!("{}\x00{}", assertion.subject, assertion.facet);
        self.txn
            .open_multimap_table(tables::ID_ASSERTION_SUBJECT_IDX)
            .map_err(crate::error::redb)?
            .insert(
                subject_key.as_str(),
                encode_subject_idx_value(&assertion.asserter, identity)?.as_slice(),
            )
            .map_err(crate::error::redb)?;
        Ok(())
    }

    /// Hold the revocation whose evidence is `identity`, indexed by
    /// asserter, and make it discoverable by its asserter.
    pub(crate) fn apply_revocation(
        &self,
        identity: &Kappa,
        revocation: &Revocation,
    ) -> Result<(), StoreError> {
        let kappa_key = identity.key_bytes();
        self.txn
            .open_table(tables::ID_REVOCATIONS)
            .map_err(crate::error::redb)?
            .insert(kappa_key.as_slice(), canonical_bytes(revocation).as_slice())
            .map_err(crate::error::redb)?;
        self.txn
            .open_multimap_table(tables::ID_REVOCATION_ASSERTER_IDX)
            .map_err(crate::error::redb)?
            .insert(
                revocation.asserter.key_bytes().as_slice(),
                kappa_key.as_slice(),
            )
            .map_err(crate::error::redb)?;
        self.store.discoverable(
            self.ns,
            DiscoveryKey::RevocationsBy(revocation.asserter.clone()),
        )
    }

    /// Hold the watermark whose evidence is `identity`, indexed by
    /// asserter, and make it discoverable by its asserter.
    pub(crate) fn apply_watermark(
        &self,
        identity: &Kappa,
        watermark: &Watermark,
    ) -> Result<(), StoreError> {
        let kappa_key = identity.key_bytes();
        self.txn
            .open_table(tables::ID_WATERMARKS)
            .map_err(crate::error::redb)?
            .insert(kappa_key.as_slice(), canonical_bytes(watermark).as_slice())
            .map_err(crate::error::redb)?;
        self.txn
            .open_multimap_table(tables::ID_WATERMARK_ASSERTER_IDX)
            .map_err(crate::error::redb)?
            .insert(
                watermark.asserter.key_bytes().as_slice(),
                kappa_key.as_slice(),
            )
            .map_err(crate::error::redb)?;
        self.store.discoverable(
            self.ns,
            DiscoveryKey::WatermarksBy(watermark.asserter.clone()),
        )
    }
}
