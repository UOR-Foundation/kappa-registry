//! Identity records written by an execution into the candidate view.
//! Each write prepares its shared transition and applies it through
//! `apply_write`, which installs evidence, dispatches the row effect to the
//! `apply_*` helpers here, appends the mutation, and queues the index
//! change. The helpers change the candidate's rows and indexes and emit
//! nothing themselves.
//!
//! Native claims and succession reservations protect admission. Locator
//! freshness is decided by shared policy against the candidate's record.

use std::cmp::Reverse;

use kappa_store::transition::{MemberTransition, RecordTransition};

use kappa_types::error::StoreError;
use kappa_types::identity::{
    DeviceBinding, HandleRecord, IdentityAssertion, IdentityBinding, LocatorRecord, PrekeyBinding,
    Revocation, RevocationCommitment, Succession, Watermark,
};
use kappa_types::kappa::Kappa;
use kappa_types::namespace::ProtocolId;

use super::claims::ClaimKey;
use super::execution::{MemoryPayload, WriteCx};

pub fn handle_key(protocol: &ProtocolId, handle: &str) -> String {
    format!("{protocol}:{handle}")
}

impl WriteCx<'_> {
    /// Apply an identity transition whose evidence supplies every value.
    fn prepare_and_apply(&mut self, record: RecordTransition) -> Result<Kappa, StoreError> {
        self.apply_record_transition(record, MemoryPayload::NoResources)
    }

    pub fn binding_put(&mut self, binding: &IdentityBinding) -> Result<(), StoreError> {
        self.prepare_and_apply(RecordTransition::Member(MemberTransition::BindingPut(
            binding.clone(),
        )))?;
        Ok(())
    }

    pub fn binding_delete(&mut self, source: &str, target: &Kappa) -> Result<(), StoreError> {
        let Some(bindings) = self.view.identity.bindings.get(source) else {
            return Ok(());
        };
        let Some(binding) = bindings.iter().find(|b| &b.target == target).cloned() else {
            return Ok(());
        };
        self.prepare_and_apply(RecordTransition::Member(MemberTransition::BindingDelete(
            binding,
        )))?;
        Ok(())
    }

    pub fn assertion_put(&mut self, assertion: &IdentityAssertion) -> Result<Kappa, StoreError> {
        self.prepare_and_apply(RecordTransition::Assertion(assertion.clone()))
    }

    pub fn revocation_put(&mut self, revocation: &Revocation) -> Result<Kappa, StoreError> {
        self.prepare_and_apply(RecordTransition::Revocation(revocation.clone()))
    }

    pub fn watermark_put(&mut self, watermark: &Watermark) -> Result<Kappa, StoreError> {
        self.prepare_and_apply(RecordTransition::Watermark(watermark.clone()))
    }

    pub fn handle_put(&mut self, record: &HandleRecord) -> Result<(), StoreError> {
        let key = handle_key(&record.protocol, &record.handle);
        self.reserve(ClaimKey::Handle(key))?;
        self.prepare_and_apply(RecordTransition::Member(MemberTransition::HandlePut(
            record.clone(),
        )))?;
        Ok(())
    }

    /// Attests only when this namespace holds the record and it still
    /// equals `expected`; a stale or absent record returns false and
    /// records no mutation.
    pub fn handle_attest(&mut self, expected: &HandleRecord) -> Result<bool, StoreError> {
        let key = handle_key(&expected.protocol, &expected.handle);
        let Some(attested) = kappa_store::identity_ops::prepare_handle_attestation(
            self.view.identity.handles.get(&key),
            expected,
            self.now,
        ) else {
            return Ok(false);
        };
        self.prepare_and_apply(RecordTransition::Member(MemberTransition::HandlePut(
            attested,
        )))?;
        Ok(true)
    }

    /// A handle this namespace does not hold is a no-op and records no
    /// mutation.
    pub fn handle_delete(&mut self, protocol: &ProtocolId, handle: &str) -> Result<(), StoreError> {
        let key = handle_key(protocol, handle);
        let Some(record) = self.view.identity.handles.get(&key).cloned() else {
            return Ok(());
        };
        self.release(ClaimKey::Handle(key));
        self.prepare_and_apply(RecordTransition::Member(MemberTransition::HandleDelete(
            record,
        )))?;
        Ok(())
    }

    pub fn device_binding_put(&mut self, binding: &DeviceBinding) -> Result<(), StoreError> {
        self.prepare_and_apply(RecordTransition::Member(MemberTransition::DevicePut(
            binding.clone(),
        )))?;
        Ok(())
    }

    /// Absent anchors are a no-op; a present anchor records its mutation
    /// even when no binding matched `device_key`.
    pub fn device_binding_revoke(
        &mut self,
        anchor: &Kappa,
        device_key: &[u8],
    ) -> Result<(), StoreError> {
        let Some(bindings) = self.view.identity.devices.get(anchor) else {
            return Ok(());
        };
        let Some(binding) = bindings
            .iter()
            .find(|b| b.device_key == device_key)
            .cloned()
        else {
            return Ok(());
        };
        self.prepare_and_apply(RecordTransition::Member(MemberTransition::DeviceRevoke(
            binding,
        )))?;
        Ok(())
    }

    pub fn prekey_binding_put(&mut self, binding: &PrekeyBinding) -> Result<(), StoreError> {
        self.prepare_and_apply(RecordTransition::Member(MemberTransition::PrekeyPut(
            binding.clone(),
        )))?;
        Ok(())
    }

    /// An anchor's locator record is held by one namespace; one whose
    /// epoch precedes the stored record is refused.
    pub fn locator_put(&mut self, record: &LocatorRecord) -> Result<(), StoreError> {
        self.reserve(ClaimKey::Locator(record.anchor.clone()))?;
        kappa_store::identity_ops::verify_locator_freshness(
            self.view.identity.locators.get(&record.anchor),
            record,
        )?;
        self.prepare_and_apply(RecordTransition::Member(MemberTransition::LocatorPut(
            record.clone(),
        )))?;
        Ok(())
    }

    pub fn revocation_commitment_put(
        &mut self,
        commitment: &RevocationCommitment,
    ) -> Result<(), StoreError> {
        self.reserve(ClaimKey::Commitment(commitment.anchor.clone()))?;
        self.prepare_and_apply(RecordTransition::Member(MemberTransition::CommitmentPut(
            commitment.clone(),
        )))?;
        Ok(())
    }

    /// Admit the signed succession record against the succession graph,
    /// hold it in this view, and commit its identity to the ledger.
    pub fn succession_put(&mut self, record: &Succession) -> Result<Kappa, StoreError> {
        self.reserve_succession(record)?;
        self.prepare_and_apply(RecordTransition::Succession(record.clone()))
    }

    // -- Application helpers (called only by `apply_write`) ------------------

    /// Hold the assertion named by `evidence`, indexed by its asserter and
    /// by its subject and facet. One already held is unchanged.
    pub(super) fn apply_assertion(&mut self, evidence: &Kappa, assertion: IdentityAssertion) {
        let identity = &mut self.view.identity;
        let asserter = assertion.asserter.clone();
        let subject = format!("{}\x00{}", assertion.subject, assertion.facet);
        if identity
            .assertions
            .insert(evidence.clone(), assertion)
            .is_none()
        {
            identity
                .assertion_asserters
                .entry(asserter)
                .or_default()
                .insert(evidence.clone());
            identity
                .assertion_subjects
                .entry(subject)
                .or_default()
                .insert(evidence.clone());
        }
    }

    /// Hold the revocation named by `evidence`, indexed by its asserter.
    /// One already held is unchanged.
    pub(super) fn apply_revocation(&mut self, evidence: &Kappa, revocation: Revocation) {
        let identity = &mut self.view.identity;
        let asserter = revocation.asserter.clone();
        if identity
            .revocations
            .insert(evidence.clone(), revocation)
            .is_none()
        {
            identity
                .revocation_asserters
                .entry(asserter)
                .or_default()
                .insert(evidence.clone());
        }
    }

    /// Hold the watermark named by `evidence`, indexed by its asserter.
    /// One already held is unchanged.
    pub(super) fn apply_watermark(&mut self, evidence: &Kappa, watermark: Watermark) {
        let identity = &mut self.view.identity;
        let asserter = watermark.asserter.clone();
        if identity
            .watermarks
            .insert(evidence.clone(), watermark)
            .is_none()
        {
            identity
                .watermark_asserters
                .entry(asserter)
                .or_default()
                .insert(evidence.clone());
        }
    }

    /// Hold the succession record under its old anchor.
    pub(super) fn apply_succession(&mut self, succession: Succession) {
        self.view
            .identity
            .successions
            .insert(succession.old_anchor.clone(), succession);
    }

    /// The row effect of one identity member transition, with the indexes
    /// its reads use.
    pub(super) fn apply_member(&mut self, member: MemberTransition) {
        let identity = &mut self.view.identity;
        match member {
            MemberTransition::BindingPut(binding) => {
                let bindings = identity.bindings.entry(binding.source.clone()).or_default();
                if let Some(existing) = bindings.iter_mut().find(|b| b.target == binding.target) {
                    *existing = binding.clone();
                } else {
                    bindings.push(binding.clone());
                }
                bindings.sort_by_key(|b| Reverse(b.verified_at_ms));
                identity
                    .binding_targets
                    .entry(binding.target)
                    .or_default()
                    .insert(binding.source);
            }
            MemberTransition::BindingDelete(binding) => {
                if let Some(bindings) = identity.bindings.get_mut(&binding.source) {
                    bindings.retain(|b| b.target != binding.target);
                    if bindings.is_empty() {
                        identity.bindings.remove(&binding.source);
                    }
                }
                if let Some(sources) = identity.binding_targets.get_mut(&binding.target) {
                    sources.remove(&binding.source);
                    if sources.is_empty() {
                        identity.binding_targets.remove(&binding.target);
                    }
                }
            }
            MemberTransition::HandlePut(record) => {
                let key = handle_key(&record.protocol, &record.handle);
                let anchor = record.anchor.clone();
                if let Some(previous) = identity.handles.insert(key.clone(), record)
                    && previous.anchor != anchor
                    && let Some(keys) = identity.handle_anchors.get_mut(&previous.anchor)
                {
                    keys.remove(&key);
                    if keys.is_empty() {
                        identity.handle_anchors.remove(&previous.anchor);
                    }
                }
                identity
                    .handle_anchors
                    .entry(anchor)
                    .or_default()
                    .insert(key);
            }
            MemberTransition::HandleDelete(record) => {
                let key = handle_key(&record.protocol, &record.handle);
                if let Some(removed) = identity.handles.remove(&key)
                    && let Some(keys) = identity.handle_anchors.get_mut(&removed.anchor)
                {
                    keys.remove(&key);
                    if keys.is_empty() {
                        identity.handle_anchors.remove(&removed.anchor);
                    }
                }
            }
            MemberTransition::DevicePut(binding) => {
                identity
                    .devices
                    .entry(binding.anchor.clone())
                    .or_default()
                    .push(binding);
            }
            MemberTransition::DeviceRevoke(binding) => {
                if let Some(bindings) = identity.devices.get_mut(&binding.anchor) {
                    bindings.retain(|b| b.device_key != binding.device_key);
                    if bindings.is_empty() {
                        identity.devices.remove(&binding.anchor);
                    }
                }
            }
            MemberTransition::PrekeyPut(binding) => {
                identity
                    .prekeys
                    .entry(binding.anchor.clone())
                    .or_default()
                    .push(binding);
            }
            MemberTransition::LocatorPut(record) => {
                identity.locators.insert(record.anchor.clone(), record);
            }
            MemberTransition::CommitmentPut(commitment) => {
                identity
                    .commitments
                    .insert(commitment.anchor.clone(), commitment);
            }
        }
    }
}
