//! Identity records written by an execution into the candidate view.
//! Each write records its ledger mutation in the same candidate.
//!
//! Records are the namespace's own and keyed by full identities; the
//! registry-wide indexes over them are projections (`projection`).
//! Assertions, revocations and watermarks are immutable evidence: their
//! indexes are historical and only grow. A handle, an anchor's locator
//! record and an anchor's revocation commitment are exclusive claims; a
//! succession link is admitted against every namespace's links by the
//! succession graph.

use kappa_store::identity_scope::AnchorScope;
use kappa_types::VerifiedContent;
use kappa_types::axis::Axis;
use kappa_types::canonical::canonical_bytes;
use kappa_types::epoch::MutationOp;
use kappa_types::error::StoreError;
use kappa_types::identity::{
    DeviceBinding, HandleRecord, IdentityAssertion, IdentityBinding, LocatorRecord, PrekeyBinding,
    Revocation, RevocationCommitment, Succession, Watermark,
};
use kappa_types::kappa::Kappa;
use kappa_types::namespace::ProtocolId;

use super::claims::ClaimKey;
use super::execution::WriteCx;

pub fn handle_key(protocol: &ProtocolId, handle: &str) -> String {
    format!("{protocol}:{handle}")
}

impl WriteCx<'_> {
    /// Record `AnchorOrigin` evidence with the scope naming the row that
    /// changed, as the persistent backend records it.
    pub fn anchor_origin(&mut self, anchor: &Kappa, scope: &AnchorScope) {
        self.record(
            MutationOp::AnchorOrigin,
            anchor.clone(),
            Some(scope.to_context()),
        );
    }

    pub fn binding_put(&mut self, binding: &IdentityBinding) {
        let bindings = self
            .view
            .identity
            .bindings
            .entry(binding.source.clone())
            .or_default();
        if let Some(existing) = bindings.iter_mut().find(|b| b.target == binding.target) {
            *existing = binding.clone();
        } else {
            bindings.push(binding.clone());
        }
        bindings.sort_by_key(|binding| std::cmp::Reverse(binding.verified_at_ms));
        self.view
            .identity
            .binding_targets
            .entry(binding.target.clone())
            .or_default()
            .insert(binding.source.clone());
        self.anchor_origin(
            &binding.target,
            &AnchorScope::Binding {
                source: binding.source.clone(),
            },
        );
    }

    /// An absent source is a no-op and records no mutation; a present
    /// source records its mutation even when no binding matched `target`.
    pub fn binding_delete(&mut self, source: &str, target: &Kappa) {
        let Some(bindings) = self.view.identity.bindings.get_mut(source) else {
            return;
        };
        bindings.retain(|b| b.target != *target);
        if bindings.is_empty() {
            self.view.identity.bindings.remove(source);
        }
        if let Some(sources) = self.view.identity.binding_targets.get_mut(target) {
            sources.remove(source);
            if sources.is_empty() {
                self.view.identity.binding_targets.remove(target);
            }
        }
        self.anchor_origin(
            target,
            &AnchorScope::Binding {
                source: source.to_string(),
            },
        );
    }

    pub fn assertion_put(&mut self, assertion: &IdentityAssertion) -> Result<Kappa, StoreError> {
        let kappa = Kappa::compute(Axis::Sha256, &canonical_bytes(assertion))?;
        let identity = &mut self.view.identity;
        if identity
            .assertions
            .insert(kappa.clone(), assertion.clone())
            .is_none()
        {
            identity
                .assertion_asserters
                .entry(assertion.asserter.clone())
                .or_default()
                .insert(kappa.clone());
            identity
                .assertion_subjects
                .entry(format!("{}\x00{}", assertion.subject, assertion.facet))
                .or_default()
                .insert(kappa.clone());
        }
        self.record(MutationOp::AssertionPublish, kappa.clone(), None);
        Ok(kappa)
    }

    pub fn revocation_put(&mut self, revocation: &Revocation) -> Result<Kappa, StoreError> {
        let kappa = Kappa::compute(Axis::Sha256, &canonical_bytes(revocation))?;
        let identity = &mut self.view.identity;
        if identity
            .revocations
            .insert(kappa.clone(), revocation.clone())
            .is_none()
        {
            identity
                .revocation_asserters
                .entry(revocation.asserter.clone())
                .or_default()
                .insert(kappa.clone());
        }
        self.record(MutationOp::RevocationPublish, kappa.clone(), None);
        Ok(kappa)
    }

    pub fn watermark_put(&mut self, watermark: &Watermark) -> Result<Kappa, StoreError> {
        let kappa = Kappa::compute(Axis::Sha256, &canonical_bytes(watermark))?;
        let identity = &mut self.view.identity;
        if identity
            .watermarks
            .insert(kappa.clone(), watermark.clone())
            .is_none()
        {
            identity
                .watermark_asserters
                .entry(watermark.asserter.clone())
                .or_default()
                .insert(kappa.clone());
        }
        self.anchor_origin(&kappa, &AnchorScope::Watermark);
        Ok(kappa)
    }

    /// Set the handle row, moving its anchor index membership.
    fn set_handle(&mut self, key: &str, record: HandleRecord) {
        let identity = &mut self.view.identity;
        if let Some(previous) = identity.handles.insert(key.to_owned(), record.clone())
            && previous.anchor != record.anchor
            && let Some(keys) = identity.handle_anchors.get_mut(&previous.anchor)
        {
            keys.remove(key);
            if keys.is_empty() {
                identity.handle_anchors.remove(&previous.anchor);
            }
        }
        identity
            .handle_anchors
            .entry(record.anchor)
            .or_default()
            .insert(key.to_owned());
    }

    pub fn handle_put(&mut self, record: &HandleRecord) -> Result<(), StoreError> {
        let key = handle_key(&record.protocol, &record.handle);
        self.reserve(ClaimKey::Handle(key.clone()))?;
        self.set_handle(&key, record.clone());
        self.anchor_origin(&record.anchor, &AnchorScope::Handle { key });
        Ok(())
    }

    /// Attests only when this namespace holds the record and it still
    /// equals `expected`; a stale or absent record returns false and records
    /// no mutation.
    pub fn handle_attest(&mut self, expected: &HandleRecord) -> bool {
        let key = handle_key(&expected.protocol, &expected.handle);
        let Some(stored) = self.view.identity.handles.get(&key) else {
            return false;
        };
        if canonical_bytes(stored) != canonical_bytes(expected) {
            return false;
        }
        let mut attested = stored.clone();
        attested.attested_at_ms = Some(self.now.as_i64());
        self.set_handle(&key, attested);
        self.anchor_origin(&expected.anchor, &AnchorScope::Handle { key });
        true
    }

    /// A handle this namespace does not hold is a no-op and records no
    /// mutation.
    pub fn handle_delete(&mut self, protocol: &ProtocolId, handle: &str) {
        let key = handle_key(protocol, handle);
        let identity = &mut self.view.identity;
        let Some(record) = identity.handles.remove(&key) else {
            return;
        };
        if let Some(keys) = identity.handle_anchors.get_mut(&record.anchor) {
            keys.remove(&key);
            if keys.is_empty() {
                identity.handle_anchors.remove(&record.anchor);
            }
        }
        self.release(ClaimKey::Handle(key.clone()));
        self.anchor_origin(&record.anchor, &AnchorScope::Handle { key });
    }

    pub fn device_binding_put(&mut self, binding: &DeviceBinding) {
        self.view
            .identity
            .devices
            .entry(binding.anchor.clone())
            .or_default()
            .push(binding.clone());
        self.anchor_origin(&binding.anchor, &AnchorScope::Device);
    }

    /// Absent anchors are a no-op; a present anchor records its mutation
    /// even when no binding matched `device_key`.
    pub fn device_binding_revoke(&mut self, anchor: &Kappa, device_key: &[u8]) {
        let Some(bindings) = self.view.identity.devices.get_mut(anchor) else {
            return;
        };
        bindings.retain(|b| b.device_key != device_key);
        if bindings.is_empty() {
            self.view.identity.devices.remove(anchor);
        }
        self.anchor_origin(anchor, &AnchorScope::Device);
    }

    pub fn prekey_binding_put(&mut self, binding: &PrekeyBinding) {
        self.view
            .identity
            .prekeys
            .entry(binding.anchor.clone())
            .or_default()
            .push(binding.clone());
        self.anchor_origin(&binding.anchor, &AnchorScope::Prekey);
    }

    /// An anchor's locator record is held by one namespace; one whose epoch
    /// precedes the stored record is refused.
    pub fn locator_put(&mut self, record: &LocatorRecord) -> Result<(), StoreError> {
        self.reserve(ClaimKey::Locator(record.anchor.clone()))?;
        if let Some(existing) = self.view.identity.locators.get(&record.anchor)
            && record.locator_epoch < existing.locator_epoch
        {
            return Err(StoreError::Rejected(format!(
                "stale locator: presented epoch {} < stored epoch {}",
                record.locator_epoch, existing.locator_epoch,
            )));
        }
        self.view
            .identity
            .locators
            .insert(record.anchor.clone(), record.clone());
        self.anchor_origin(&record.anchor, &AnchorScope::Locator);
        Ok(())
    }

    pub fn revocation_commitment_put(
        &mut self,
        commitment: &RevocationCommitment,
    ) -> Result<(), StoreError> {
        self.reserve(ClaimKey::Commitment(commitment.anchor.clone()))?;
        self.view
            .identity
            .commitments
            .insert(commitment.anchor.clone(), commitment.clone());
        self.anchor_origin(&commitment.anchor, &AnchorScope::Commitment);
        Ok(())
    }

    /// Admit the signed succession record against the succession graph,
    /// hold it in this view, and commit its identity to the ledger.
    pub fn succession_put(&mut self, record: &Succession) -> Result<Kappa, StoreError> {
        self.reserve_succession(record)?;
        self.view
            .identity
            .successions
            .insert(record.old_anchor.clone(), record.clone());
        let content = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(record))?;
        self.publish_content(&content)?;
        self.anchor_origin(content.kappa(), &AnchorScope::Succession);
        Ok(content.kappa().clone())
    }
}
