//! Installation, composition and retirement of content in the candidate
//! view.
//!
//! The domain methods (`install_prepared`, `publish_record`, `compose`,
//! `retire`, `blob_meta_*`) read the candidate, validate, and prepare each
//! transition with its owned payload; the application boundary
//! (`WriteCx::apply_write`) consumes it and calls the `apply_*` helpers of
//! `content_apply`.
//!
//! Evidence is held apart from logical admission (`NamespaceView::evidence`):
//! `install_evidence` retains the bytes a transition or publication names
//! without admitting them, and `retain_generated` retains a record generated
//! from a signed root in memory, its bytes moved in and its retention charge
//! carried with them.

use kappa_store::execution::Retirement;
use kappa_store::transition::RecordTransition;
use kappa_store::{
    CompositionEvidence, IngestResult, Kappa, PreparedContent, StoreError, VerifiedContent,
};
use kappa_types::capacity::Reservation;
use kappa_types::content::{
    ContentAdmission, ContentAdmissionEvidence, ContentAdmissionRecord, ContentAlias,
    ContentComponent, ContentComposition, ContentRetirementRecord, MetadataTransition,
};

use super::blob_read;
use super::content::{MemoryPrepared, canonical_order};
use super::execution::{MemoryPayload, WriteCx};
use super::segments::Segments;
use super::view::{Admission, Held, Representation};

impl WriteCx<'_> {
    fn content_admission(&self, identity: &Kappa, size: u64) -> ContentAdmission {
        ContentAdmission::new(
            *self.ns.id(),
            self.incarnation_bytes(),
            identity.clone(),
            size,
        )
    }

    // -- Evidence -----------------------------------------------------------

    /// Retain the identity-verified bytes of evidence a transition or
    /// publication names, without admitting them as content. Evidence an
    /// identity is already admitted under is still retained as evidence, so
    /// retiring the admission never releases what history names.
    pub(super) fn install_evidence(&mut self, content: &VerifiedContent) -> Result<(), StoreError> {
        let identity = content.kappa();
        if self.view.evidence.contains_key(identity) {
            return Ok(());
        }
        let allocation = self
            .store
            .allocations
            .install_bytes(identity, content.content())?;
        self.view.evidence.insert(
            identity.clone(),
            Admission {
                representation: Representation::File(allocation),
                size: content.content().len() as u64,
            },
        );
        Ok(())
    }

    /// Retain `content`, a record generated from a signed root, in the
    /// process's memory: its bytes are moved into the view with their
    /// segment digests, and `charge` stays with them in every view that
    /// holds them. Evidence this view already holds under the identity is
    /// kept, and the charge, accounting for nothing, is released.
    pub(super) fn retain_generated(&mut self, content: VerifiedContent, charge: Reservation) {
        if self.view.evidence.contains_key(content.kappa()) {
            return;
        }
        let (identity, bytes) = content.into_parts();
        let size = bytes.len() as u64;
        let segments = Segments::of(&bytes);
        self.view.evidence.insert(
            identity,
            Admission {
                representation: Representation::Inline {
                    bytes: Held::new(bytes, charge),
                    segments,
                },
                size,
            },
        );
    }

    // -- Domain methods -----------------------------------------------------

    /// Admit `aliases` as selectors of `holder`, each through its own
    /// `ContentAlias` transition. An alias already selecting `holder` is
    /// kept; one selecting anything else is a conflict.
    fn install_aliases(
        &mut self,
        holder: &Kappa,
        size: u64,
        aliases: &[Kappa],
    ) -> Result<(), StoreError> {
        for alias in aliases {
            if alias == holder {
                continue;
            }
            if alias.axis().discriminant() < holder.axis().discriminant() {
                return Err(StoreError::Internal(format!(
                    "alias {alias} would name a holder under a higher axis"
                )));
            }
            if let Some(existing) = self.view.admitted.get(alias) {
                if existing.representation == Representation::Alias(holder.clone()) {
                    continue;
                }
                return Err(StoreError::Conflict(format!(
                    "digest alias {alias} already holds another representation"
                )));
            }
            let binding = ContentAlias::new(alias.clone(), holder.clone(), size)?;
            let record = ContentAdmissionRecord::new(
                self.content_admission(alias, size),
                ContentAdmissionEvidence::Alias(binding),
            )?;
            self.apply_record_transition(
                RecordTransition::ContentAlias(record),
                MemoryPayload::NoResources,
            )?;
        }
        Ok(())
    }

    /// Publish verified bytes the execution holds (`ExecutionWrites::blob_put`).
    /// Bytes this namespace already holds only as evidence are admitted
    /// here; an identity it already admitted is not admitted again.
    pub fn publish_record(&mut self, content: &VerifiedContent) -> Result<bool, StoreError> {
        let identity = content.kappa();
        if self.view.admitted.contains_key(identity) {
            return Ok(false);
        }
        let size = content.content().len() as u64;
        let record = ContentAdmissionRecord::new(
            self.content_admission(identity, size),
            ContentAdmissionEvidence::VerifiedBytes,
        )?;
        // The payload owns its own verified copy of the bytes it installs.
        let owned = VerifiedContent::verify(identity, content.content())?;
        self.apply_record_transition(
            RecordTransition::RecordPublish(record),
            MemoryPayload::ExplicitRecord(owned),
        )?;
        let mut aliases = Vec::new();
        for axis in self.store.axes_for(identity.axis()).into_iter().skip(1) {
            aliases.push(Kappa::compute(axis, content.content())?);
        }
        let (holder, aliases) = canonical_order(identity.clone(), aliases);
        self.install_aliases(&holder, size, &aliases)?;
        Ok(true)
    }

    /// Install prepared content: its holder's admission when new, then each
    /// newly admitted alias.
    pub fn install_prepared(
        &mut self,
        prepared: Box<dyn PreparedContent>,
    ) -> Result<IngestResult, StoreError> {
        let prepared = prepared
            .as_any()
            .downcast::<MemoryPrepared>()
            .map_err(|_| StoreError::Rejected("content was prepared by another store".into()))?;
        prepared.validate_owner(self.store)?;
        let requested = prepared.identity.clone();
        let requested_aliases = prepared.aliases.clone();
        let total_size = prepared.total_size;
        let (holder, aliases) = canonical_order(requested.clone(), requested_aliases.clone());
        let newly = !self.view.admitted.contains_key(&holder);
        if newly {
            let record = ContentAdmissionRecord::new(
                self.content_admission(&holder, total_size),
                ContentAdmissionEvidence::VerifiedBytes,
            )?;
            self.apply_record_transition(
                RecordTransition::ContentPublish(record),
                MemoryPayload::PreparedContent(prepared),
            )?;
        }
        self.install_aliases(&holder, total_size, &aliases)?;
        Ok(IngestResult::new(requested, newly).with_additional(requested_aliases))
    }

    /// Install the composite `evidence` describes over components this
    /// namespace admitted.
    pub fn compose(&mut self, evidence: &CompositionEvidence) -> Result<IngestResult, StoreError> {
        let requested = evidence.identity().clone();
        let requested_aliases = evidence.aliases().to_vec();
        let (holder, aliases) = canonical_order(requested.clone(), requested_aliases.clone());
        let newly = !self.view.admitted.contains_key(&holder);
        if newly {
            for (component, length) in evidence.components() {
                if component == &holder || aliases.contains(component) {
                    return Err(StoreError::Rejected("composite names itself".into()));
                }
                if !self.view.admitted.contains_key(component) {
                    return Err(StoreError::NotFound(format!(
                        "composite component {component} in {}",
                        self.ns
                    )));
                }
                let resolved = blob_read::plan(self.view, component, &mut *self.meter)?.total();
                if resolved != *length {
                    return Err(StoreError::Rejected(format!(
                        "composite declares {length} bytes for {component} whose size is {resolved}"
                    )));
                }
            }
            let composition = ContentComposition::new(
                holder.clone(),
                evidence
                    .components()
                    .iter()
                    .map(|(identity, length)| ContentComponent {
                        identity: identity.clone(),
                        length: *length,
                    })
                    .collect(),
                evidence.total_bytes(),
            )?;
            let record = ContentAdmissionRecord::new(
                self.content_admission(&holder, evidence.total_bytes()),
                ContentAdmissionEvidence::Composition(composition),
            )?;
            self.apply_record_transition(
                RecordTransition::ContentCompose(record),
                MemoryPayload::NoResources,
            )?;
        }
        self.install_aliases(&holder, evidence.total_bytes(), &aliases)?;
        Ok(IngestResult::new(requested, newly).with_additional(requested_aliases))
    }

    /// The digest family of `identity` in this view: its holder first,
    /// then every alias selecting the holder.
    fn family(&self, identity: &Kappa, admission: &Admission) -> Vec<Kappa> {
        let holder = match &admission.representation {
            Representation::Alias(holder) => holder.clone(),
            _ => identity.clone(),
        };
        let mut members = vec![holder.clone()];
        for selector in self.view.selected_by.get(&holder).into_iter().flatten() {
            if self
                .view
                .admitted
                .get(selector)
                .is_some_and(|a| a.representation == Representation::Alias(holder.clone()))
            {
                members.push(selector.clone());
            }
        }
        members
    }

    /// Release this namespace's admission of `identity` and its digest
    /// family, unless a local dependency retains it. Every dependency is
    /// checked before the first transition. Each member, aliases before
    /// the holder, first has its blob metadata removed by its own
    /// transitions, then its admission retired by a `ContentRetire` naming
    /// the exact admission. Evidence history names stays retained.
    pub fn retire(&mut self, identity: &Kappa) -> Result<Retirement, StoreError> {
        let Some(admission) = self.view.admitted.get(identity).cloned() else {
            return Ok(Retirement::Absent);
        };
        let family = self.family(identity, &admission);
        for member in &family {
            let selected_outside = self
                .view
                .selected_by
                .get(member)
                .is_some_and(|owners| owners.iter().any(|owner| !family.contains(owner)));
            if selected_outside
                || self.view.references.contains_key(member)
                || self.view.edges.retains(member)
            {
                return Ok(Retirement::Retained);
            }
        }
        let mut removals = Vec::with_capacity(family.len());
        for member in family.iter().rev() {
            let size = self
                .view
                .admitted
                .get(member)
                .map(|admission| admission.size)
                .ok_or_else(|| {
                    StoreError::Internal(format!("family member {member} is not admitted"))
                })?;
            let keys: Vec<String> = self
                .view
                .blob_meta
                .range((member.clone(), String::new())..)
                .take_while(|((owner, _), _)| owner == member)
                .map(|((_, key), _)| key.clone())
                .collect();
            removals.push((member.clone(), size, keys));
        }
        for (member, size, keys) in removals {
            for key in keys {
                self.blob_meta_delete(&member, &key)?;
            }
            let retirement = ContentRetirementRecord::new(self.content_admission(&member, size));
            self.apply_record_transition(
                RecordTransition::ContentRetire(retirement),
                MemoryPayload::NoResources,
            )?;
        }
        Ok(Retirement::Retired)
    }

    /// Admit metadata of `identity` in this namespace.
    pub fn blob_meta_put(
        &mut self,
        identity: &Kappa,
        key: &str,
        value: &[u8],
    ) -> Result<(), StoreError> {
        let meta = MetadataTransition::blob_meta(
            *self.ns.id(),
            self.incarnation_bytes(),
            identity.clone(),
            key.to_owned(),
            Some(value.to_vec()),
        );
        self.apply_record_transition(RecordTransition::Metadata(meta), MemoryPayload::NoResources)
            .map(drop)
    }

    /// Deleting metadata this namespace does not hold is a no-op and
    /// records no mutation.
    pub fn blob_meta_delete(&mut self, identity: &Kappa, key: &str) -> Result<(), StoreError> {
        if !self
            .view
            .blob_meta
            .contains_key(&(identity.clone(), key.to_owned()))
        {
            return Ok(());
        }
        let meta = MetadataTransition::blob_meta(
            *self.ns.id(),
            self.incarnation_bytes(),
            identity.clone(),
            key.to_owned(),
            None,
        );
        self.apply_record_transition(RecordTransition::Metadata(meta), MemoryPayload::NoResources)
            .map(drop)
    }
}
