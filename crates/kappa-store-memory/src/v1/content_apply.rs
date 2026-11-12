//! Application of content transitions to the candidate view.
//!
//! Called only by the application boundary (`WriteCx::apply_write`), after
//! the transition and its payload were bound and validated. Each helper
//! changes the candidate's rows and selections and emits nothing itself: the
//! boundary retains the evidence, appends the mutation and queues the index
//! change once. A helper refuses any state its transition does not
//! correspond to; the refusal latches the execution.

use std::collections::BTreeSet;
use std::sync::Arc;

use kappa_store::{Kappa, StoreError, VerifiedContent};
use kappa_types::content::{
    ContentAdmissionEvidence, ContentAdmissionRecord, ContentRetirementRecord,
};

use super::content::MemoryPrepared;
use super::execution::WriteCx;
use super::view::{Admission, Representation};

fn distinct_components(components: &[(Kappa, u64)]) -> BTreeSet<&Kappa> {
    components.iter().map(|(component, _)| component).collect()
}

impl WriteCx<'_> {
    /// Hold `value` under `identity`'s metadata `key`, or remove the key when
    /// the transition deletes it.
    pub(super) fn apply_blob_meta(&mut self, identity: &Kappa, key: &str, value: Option<&[u8]>) {
        let entry = (identity.clone(), key.to_owned());
        match value {
            Some(value) => {
                self.view.blob_meta.insert(entry, value.to_vec());
            }
            None => {
                self.view.blob_meta.remove(&entry);
            }
        }
    }

    /// Refuse a second admission of `identity`.
    fn check_unadmitted(&self, identity: &Kappa) -> Result<(), StoreError> {
        if self.view.admitted.contains_key(identity) {
            return Err(StoreError::Internal(format!(
                "content {identity} admitted twice"
            )));
        }
        Ok(())
    }

    /// Install the prepared allocation and admit its holder.
    pub(super) fn apply_prepared_admission(
        &mut self,
        record: &ContentAdmissionRecord,
        prepared: MemoryPrepared,
    ) -> Result<(), StoreError> {
        let identity = record.admission().identity();
        self.check_unadmitted(identity)?;
        let MemoryPrepared {
            total_size,
            file,
            segments,
            compression,
            ..
        } = prepared;
        let representation = match compression {
            Some(compression) => Representation::Compressed {
                storage: self
                    .store
                    .allocations
                    .install(&compression.storage, file, segments)?,
                algorithm: compression.algorithm,
                decoded: compression.decoded,
            },
            None => Representation::File(self.store.allocations.install(identity, file, segments)?),
        };
        self.view.admitted.insert(
            identity.clone(),
            Admission {
                representation,
                size: total_size,
            },
        );
        Ok(())
    }

    /// Install the verified record bytes and admit them.
    pub(super) fn apply_record_admission(
        &mut self,
        record: &ContentAdmissionRecord,
        content: &VerifiedContent,
    ) -> Result<(), StoreError> {
        let identity = record.admission().identity();
        self.check_unadmitted(identity)?;
        let allocation = self
            .store
            .allocations
            .install_bytes(identity, content.content())?;
        self.view.admitted.insert(
            identity.clone(),
            Admission {
                representation: Representation::File(allocation),
                size: record.admission().logical_size(),
            },
        );
        Ok(())
    }

    /// Admit an alias selecting its admitted target of the same length.
    pub(super) fn apply_alias_admission(
        &mut self,
        record: &ContentAdmissionRecord,
    ) -> Result<(), StoreError> {
        let ContentAdmissionEvidence::Alias(alias) = record.evidence() else {
            return Err(StoreError::Internal(
                "alias admission without alias evidence".into(),
            ));
        };
        let identity = record.admission().identity();
        self.check_unadmitted(identity)?;
        match self.view.admitted.get(alias.target()) {
            Some(target) if target.size == alias.length() => {}
            Some(target) => {
                return Err(StoreError::Internal(format!(
                    "alias {identity} declares {} bytes for {}, which admits {}",
                    alias.length(),
                    alias.target(),
                    target.size
                )));
            }
            None => {
                return Err(StoreError::Internal(format!(
                    "alias {identity} names {}, which the namespace does not admit",
                    alias.target()
                )));
            }
        }
        self.view.admitted.insert(
            identity.clone(),
            Admission {
                representation: Representation::Alias(alias.target().clone()),
                size: record.admission().logical_size(),
            },
        );
        self.view.select(alias.target(), identity);
        Ok(())
    }

    /// Admit a composite over its admitted components, each selected once.
    pub(super) fn apply_composite_admission(
        &mut self,
        record: &ContentAdmissionRecord,
    ) -> Result<(), StoreError> {
        let ContentAdmissionEvidence::Composition(composition) = record.evidence() else {
            return Err(StoreError::Internal(
                "composite admission without composition evidence".into(),
            ));
        };
        let identity = record.admission().identity();
        self.check_unadmitted(identity)?;
        let components: Vec<(Kappa, u64)> = composition
            .components()
            .iter()
            .map(|component| (component.identity.clone(), component.length))
            .collect();
        if let Some((missing, _)) = components
            .iter()
            .find(|(component, _)| !self.view.admitted.contains_key(component))
        {
            return Err(StoreError::Internal(format!(
                "composite {identity} names {missing}, which the namespace does not admit"
            )));
        }
        for component in distinct_components(&components) {
            self.view.select(component, identity);
        }
        self.view.admitted.insert(
            identity.clone(),
            Admission {
                representation: Representation::Composite(Arc::from(components)),
                size: record.admission().logical_size(),
            },
        );
        Ok(())
    }

    /// Remove exactly the admission `record` names and release what it
    /// selected. No other admission may still select it, and its blob
    /// metadata must already be removed by its own transitions.
    pub(super) fn apply_retirement(
        &mut self,
        record: &ContentRetirementRecord,
    ) -> Result<(), StoreError> {
        let removed = record.removed();
        let identity = removed.identity();
        match self.view.admitted.get(identity) {
            Some(held) if held.size == removed.logical_size() => {}
            Some(held) => {
                return Err(StoreError::Internal(format!(
                    "retirement of {identity} names {} bytes; the admission holds {}",
                    removed.logical_size(),
                    held.size
                )));
            }
            None => {
                return Err(StoreError::Internal(format!(
                    "retirement of {identity}, which the namespace does not admit"
                )));
            }
        }
        if self
            .view
            .selected_by
            .get(identity)
            .is_some_and(|owners| !owners.is_empty())
        {
            return Err(StoreError::Internal(format!(
                "retirement of {identity} while another admission selects it"
            )));
        }
        if self
            .view
            .blob_meta
            .range((identity.clone(), String::new())..)
            .next()
            .is_some_and(|((owner, _), _)| owner == identity)
        {
            return Err(StoreError::Internal(format!(
                "retirement of {identity} before its blob metadata was removed"
            )));
        }
        let Some(admission) = self.view.admitted.remove(identity) else {
            return Err(StoreError::Internal(format!(
                "admission of {identity} vanished"
            )));
        };
        match &admission.representation {
            Representation::Alias(holder) => self.view.unselect(holder, identity),
            Representation::Composite(components) => {
                for component in distinct_components(components) {
                    self.view.unselect(component, identity);
                }
            }
            Representation::File(_)
            | Representation::Compressed { .. }
            | Representation::Inline { .. } => {}
        }
        Ok(())
    }
}
