//! Ownership of an activation while its governing publication is resumed.

use std::sync::{Arc, atomic::Ordering};

use kappa_store::{StoreError, VerifiedContent};

use super::{ActivationHold, ActivationIntent};
use crate::PersistentStore;
use crate::custody::CustodyRecord;

impl PersistentStore {
    /// Under the exclusive activation gate, no publication can acquire new
    /// custody. Retained epochs keep their signing authority until resolved.
    pub(super) fn require_clear_publication_custody(&self) -> Result<(), StoreError> {
        if !self
            .live_custody
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
        {
            return Err(StoreError::Conflict(
                "authority rotation waits for retained publications".into(),
            ));
        }
        let mut meter = kappa_store::work::WorkMeter::new(self.step_limit);
        meter.charge(kappa_store::work::Dimension::Handles, 1)?;
        let Some(entries) =
            crate::instance_record::Kind::Custody.traversal(self.namespaces.root())?
        else {
            return Ok(());
        };
        for entry in entries {
            meter.charge(kappa_store::work::Dimension::Entries, 1)?;
            let entry = entry?;
            if crate::instance_record::is_staged(&entry) {
                continue;
            }
            let instance = crate::instance_record::instance(&entry)?;
            return Err(StoreError::Conflict(format!(
                "authority rotation waits for retained publication of {instance}"
            )));
        }
        Ok(())
    }

    pub(crate) fn retained_activation(
        &self,
        record: &CustodyRecord,
    ) -> Result<ActivationHold<'_>, StoreError> {
        let gate = self
            .activation
            .write()
            .map_err(|_| StoreError::Internal("authority activation lock poisoned".into()))?;
        let activation = record.activation.as_ref().ok_or_else(|| {
            StoreError::Rejected("ordinary custody requested activation ownership".into())
        })?;
        let (_, intent) = self.authority_rows()?;
        let intent = intent.ok_or_else(|| {
            StoreError::Unavailable("retained activation has no durable intent".into())
        })?;
        if intent.position != activation.position
            || intent.record != activation.record
            || intent.domain.control != record.namespace()?
            || intent.domain.incarnation != record.incarnation()?
            || *self.authority.load().anchor() != activation.outgoing
        {
            return Err(StoreError::Conflict(
                "retained activation ownership changed".into(),
            ));
        }
        let candidate = self.retained_authority.load_full().ok_or_else(|| {
            StoreError::Unavailable("retained activation signing capability is unavailable".into())
        })?;
        let transition = candidate.transitions().last().ok_or_else(|| {
            StoreError::Rejected("retained activation has no authority transition".into())
        })?;
        VerifiedContent::verify(&intent.record, &transition.to_bytes()?)?;
        if transition.activation().domain != intent.domain
            || candidate.transitions().len() as u64 != intent.position
        {
            return Err(StoreError::Rejected(
                "retained authority differs from its intent".into(),
            ));
        }
        Ok(ActivationHold::new(
            gate,
            candidate,
            intent,
            record.predecessor.clone(),
            activation.outgoing.clone(),
        ))
    }

    /// Called only after the exact governing root is committed, while the
    /// hold still excludes every other authority publication.
    pub(crate) fn finish_retained_activation(&self, hold: ActivationHold<'_>) {
        let candidate = Arc::clone(hold.candidate());
        self.authority.store(Arc::clone(&candidate));
        self.retained_authority.store(None);
        self.authority_unresolved.store(false, Ordering::SeqCst);
        let activation = hold.custody();
        let transition = candidate.transitions().last();
        let projection = transition.map(|transition| {
            let intent = ActivationIntent {
                position: activation.position,
                domain: transition.activation().domain,
                record: activation.record,
            };
            transition
                .to_bytes()
                .and_then(|bytes| self.project_activation(intent.position, &bytes, Some(&intent)))
        });
        drop(hold);
        if let Some(Err(error)) = projection {
            tracing::warn!(%error, "committed activation projection remains pending");
        }
    }
}
