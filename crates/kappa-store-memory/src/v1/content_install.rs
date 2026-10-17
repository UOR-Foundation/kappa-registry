//! Installation, composition and retirement of content in the candidate
//! view.
//!
//! Each namespace selects its own representation for every identity it
//! admits: a file allocation, an alias of another identity it admitted, a
//! composite of identities it admitted, or a compressed allocation. The
//! physical allocation is shared with every namespace that admitted the
//! same bytes (`allocation`); the selection is this view's alone, so no
//! other namespace's admission or retirement changes it.
//!
//! Installation records every other verified identity of the same bytes as
//! an alias selecting the canonical holder (the lowest axis), with
//! `ContentAlias` evidence; composition records `ContentCompose` evidence;
//! retirement records `ContentRetire`. A record the store produces
//! (`publish_content`) is admitted under its identity and every mandatory
//! axis without recording a mutation, so the seal can install the records
//! it produces after the ledger is fixed.
//!
//! Retirement releases this namespace's admission only, of the identity and
//! the digest aliases of the same bytes together. A local dependency
//! retains it: a composite or foreign alias of this view selecting a member,
//! a direct tag or the epoch head naming one, or a retaining edge targeting
//! one.

use std::collections::BTreeSet;
use std::sync::Arc;

use kappa_store::execution::Retirement;
use kappa_store::{
    CompositionEvidence, IngestResult, Kappa, MutationOp, PreparedContent, StoreError,
    VerifiedContent,
};
use kappa_types::Axis;
use kappa_types::canonical::canonical_bytes;
use kappa_types::content::{ContentAlias, ContentComponent, ContentComposition};

use super::blob_read;
use super::content::{MemoryPrepared, canonical_order};
use super::execution::WriteCx;
use super::view::{Admission, Representation};

/// Each component of a composite once, however often the composite lists
/// it: selection is a relation between the composite and a component.
fn distinct_components(components: &[(Kappa, u64)]) -> BTreeSet<&Kappa> {
    components.iter().map(|(component, _)| component).collect()
}

impl WriteCx<'_> {
    /// Admit `alias` as selecting `holder`. An alias this view already
    /// admitted must select the same holder.
    fn admit_alias(
        &mut self,
        alias: &Kappa,
        holder: &Kappa,
        size: u64,
    ) -> Result<bool, StoreError> {
        match self.view.admitted.get(alias) {
            Some(Admission {
                representation: Representation::Alias(selected),
                ..
            }) if selected == holder => Ok(false),
            Some(_) => Err(StoreError::Conflict(format!(
                "digest alias {alias} already holds another representation in this namespace"
            ))),
            None => {
                self.view.admitted.insert(
                    alias.clone(),
                    Admission {
                        representation: Representation::Alias(holder.clone()),
                        size,
                    },
                );
                self.view.select(holder, alias);
                Ok(true)
            }
        }
    }

    /// Admit `aliases` as selectors of `holder`, recording each new binding
    /// as `ContentAlias` evidence.
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
            if !self.admit_alias(alias, holder, size)? {
                continue;
            }
            let binding = ContentAlias::new(alias.clone(), holder.clone(), size)?;
            let evidence = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(&binding))?;
            self.publish_content(&evidence)?;
            self.record(MutationOp::ContentAlias, evidence.kappa().clone(), None);
        }
        Ok(())
    }

    /// Admit verified bytes the store or the execution produced under their
    /// identity and every mandatory axis. Records no mutation. Returns
    /// whether this namespace had not admitted the identity.
    pub fn publish_content(&mut self, content: &VerifiedContent) -> Result<bool, StoreError> {
        let identity = content.kappa();
        if self.view.admitted.contains_key(identity) {
            return Ok(false);
        }
        let mut aliases = Vec::new();
        for axis in self.store.axes_for(identity.axis()).into_iter().skip(1) {
            aliases.push(Kappa::compute(axis, content.content())?);
        }
        let (holder, aliases) = canonical_order(identity.clone(), aliases);
        let size = content.content().len() as u64;
        if !self.view.admitted.contains_key(&holder) {
            let allocation = self
                .store
                .allocations
                .install_bytes(&holder, content.content())?;
            self.view.admitted.insert(
                holder.clone(),
                Admission {
                    representation: Representation::File(allocation),
                    size,
                },
            );
        }
        for alias in &aliases {
            self.admit_alias(alias, &holder, size)?;
        }
        Ok(true)
    }

    /// Publish verified bytes the execution holds (`ExecutionWrites::blob_put`).
    /// A record this namespace did not already admit is admitted by a
    /// `RecordPublish` mutation naming it, as the persistent backend
    /// records it.
    pub fn publish_record(&mut self, content: &VerifiedContent) -> Result<bool, StoreError> {
        let new = self.publish_content(content)?;
        if new {
            self.record(MutationOp::RecordPublish, content.kappa().clone(), None);
        }
        Ok(new)
    }

    /// Install prepared content.
    pub fn install_prepared(
        &mut self,
        prepared: Box<dyn PreparedContent>,
    ) -> Result<IngestResult, StoreError> {
        let prepared = prepared
            .as_any()
            .downcast::<MemoryPrepared>()
            .map_err(|_| StoreError::Rejected("content was prepared by another store".into()))?;
        let MemoryPrepared {
            identity,
            aliases,
            total_size,
            file,
            segments,
            compression,
        } = *prepared;
        let requested = identity.clone();
        let requested_aliases = aliases.clone();
        // Compressed or not, the logical identities are the same verified
        // set: the canonical holder takes the representation, the others
        // alias it. A compressed holder's allocation is identified by the
        // compressed bytes, not by the logical identity.
        let (holder, aliases) = canonical_order(identity, aliases);
        let newly = !self.view.admitted.contains_key(&holder);
        if newly {
            let representation = match compression {
                Some(compression) => Representation::Compressed {
                    storage: self.store.allocations.install(
                        &compression.storage,
                        file,
                        segments,
                    )?,
                    algorithm: compression.algorithm,
                    decoded: compression.decoded,
                },
                None => {
                    Representation::File(self.store.allocations.install(&holder, file, segments)?)
                }
            };
            self.view.admitted.insert(
                holder.clone(),
                Admission {
                    representation,
                    size: total_size,
                },
            );
        }
        self.install_aliases(&holder, total_size, &aliases)?;
        Ok(IngestResult::new(requested, newly).with_additional(requested_aliases))
    }

    /// Install the composite `evidence` describes over components this
    /// namespace admitted, each with the evidenced length. The payload is
    /// never written. A newly installed composite records `ContentCompose`
    /// evidence.
    pub fn compose(&mut self, evidence: &CompositionEvidence) -> Result<IngestResult, StoreError> {
        let requested = evidence.identity().clone();
        let requested_aliases = evidence.aliases().to_vec();
        let (holder, aliases) = canonical_order(requested.clone(), requested_aliases.clone());
        let newly = !self.view.admitted.contains_key(&holder);
        if newly {
            // Components resolve through the reader's own resolver, so the
            // composite is one every read can serve: aliases, nested
            // composites and compressed components resolve, within the
            // resolver's depth and piece bounds; a chain back to the
            // composite is refused.
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
                let resolved = blob_read::plan(self.view, component)?.total();
                if resolved != *length {
                    return Err(StoreError::Rejected(format!(
                        "composite declares {length} bytes for {component} whose size is {resolved}"
                    )));
                }
            }
            for component in distinct_components(evidence.components()) {
                self.view.select(component, &holder);
            }
            self.view.admitted.insert(
                holder.clone(),
                Admission {
                    representation: Representation::Composite(Arc::from(evidence.components())),
                    size: evidence.total_bytes(),
                },
            );
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
            let record = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(&composition))?;
            self.publish_content(&record)?;
            self.record(MutationOp::ContentCompose, record.kappa().clone(), None);
        }
        self.install_aliases(&holder, evidence.total_bytes(), &aliases)?;
        Ok(IngestResult::new(requested, newly).with_additional(requested_aliases))
    }

    /// The digest family of `identity` in this view: its holder (the
    /// identity itself unless it is a digest alias) followed by every digest
    /// alias selecting that holder. The members are identities of the same
    /// bytes.
    fn family(&self, identity: &Kappa, admission: &Admission) -> Vec<Kappa> {
        let holder = match &admission.representation {
            Representation::Alias(holder) => holder.clone(),
            _ => identity.clone(),
        };
        let mut members = vec![holder.clone()];
        for selector in self.view.selected_by.get(&holder).into_iter().flatten() {
            if self.view.admitted.get(selector).is_some_and(|admission| {
                admission.representation == Representation::Alias(holder.clone())
            }) {
                members.push(selector.clone());
            }
        }
        members
    }

    /// Release this namespace's admission of `identity` and of every other
    /// identity of the same bytes it admitted (the digest family), unless a
    /// local dependency names one of them: a direct tag or the epoch head, a
    /// retaining edge, or a representation outside the family selecting it.
    /// Each released identity records `ContentRetire`, and its blob metadata
    /// in this namespace goes with it.
    pub fn retire(&mut self, identity: &Kappa) -> Retirement {
        let Some(admission) = self.view.admitted.get(identity).cloned() else {
            return Retirement::Absent;
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
                return Retirement::Retained;
            }
        }
        // Aliases first, so the holder is selected by nothing when it goes.
        for member in family.iter().rev() {
            let Some(admission) = self.view.admitted.remove(member) else {
                continue;
            };
            match &admission.representation {
                Representation::Alias(holder) => self.view.unselect(holder, member),
                Representation::Composite(components) => {
                    for component in distinct_components(components) {
                        self.view.unselect(component, member);
                    }
                }
                Representation::File(_) | Representation::Compressed { .. } => {}
            }
            let metadata: Vec<(Kappa, String)> = self
                .view
                .blob_meta
                .range((member.clone(), String::new())..)
                .take_while(|((owner, _), _)| owner == member)
                .map(|(key, _)| key.clone())
                .collect();
            for key in metadata {
                self.view.blob_meta.remove(&key);
            }
            self.record(MutationOp::ContentRetire, member.clone(), None);
        }
        Retirement::Retired
    }

    /// Admit metadata of `identity` in this namespace.
    pub fn blob_meta_put(&mut self, identity: &Kappa, key: &str, value: &[u8]) {
        self.view
            .blob_meta
            .insert((identity.clone(), key.to_owned()), value.to_vec());
    }

    pub fn blob_meta_delete(&mut self, identity: &Kappa, key: &str) {
        self.view
            .blob_meta
            .remove(&(identity.clone(), key.to_owned()));
    }
}
