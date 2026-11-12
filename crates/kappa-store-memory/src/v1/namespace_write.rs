//! Namespace record, alias, and configuration transitions applied to the
//! candidate view. Every record change and metadata change goes through the
//! shared transition boundary (`apply_write`).
//!
//! The record is the namespace's own; its aliases are directory claims
//! (`claims`), reserved under the alias admission rule when written and
//! released through the transition that removes them, so a name is never
//! free while a published view still holds it.

use kappa_store::traits::namespace::{NamespaceAlias, NamespaceInfo};
use kappa_store::transition::RecordTransition;

use kappa_types::content::MetadataTransition;
use kappa_types::{Kappa, NamespaceRef, ProtocolId, StoreError};

use super::claims::ClaimKey;
use super::execution::{MemoryPayload, WriteCx};
use super::view::NamespaceView;

pub fn namespace_info_in(
    view: &NamespaceView,
    ns: &NamespaceRef,
) -> Result<NamespaceInfo, StoreError> {
    view.record
        .clone()
        .ok_or_else(|| StoreError::NotFound(format!("namespace: {ns}")))
}

pub fn namespace_get_meta_in(
    view: &NamespaceView,
    ns: &NamespaceRef,
    key: &str,
) -> Result<Vec<u8>, StoreError> {
    view.meta
        .get(key)
        .cloned()
        .ok_or_else(|| StoreError::NotFound(format!("namespace config {ns}:{key}")))
}

impl WriteCx<'_> {
    fn record_namespace(&mut self, record: NamespaceInfo) -> Result<(), StoreError> {
        self.apply_record_transition(
            RecordTransition::NamespaceUpdate(record),
            MemoryPayload::NoResources,
        )
        .map(drop)
    }

    /// Reserve the directory claim of `alias` for this attempt.
    fn claim_alias(&mut self, alias: &NamespaceAlias) -> Result<(), StoreError> {
        self.reserve_alias(&alias.name, alias.scope())
    }

    /// Release this namespace's directory claim of `alias` with the
    /// publication.
    fn release_alias(&mut self, alias: &NamespaceAlias) {
        self.release(ClaimKey::Alias {
            name: alias.name.clone(),
            protocol: alias.scope().to_owned(),
        });
    }

    /// Create the namespace under its display name within `protocol`.
    pub fn namespace_create(
        &mut self,
        owner: Option<&Kappa>,
        protocol: Option<&ProtocolId>,
    ) -> Result<(), StoreError> {
        if self.view.record.is_some() {
            return Err(StoreError::AlreadyExists(format!("namespace: {}", self.ns)));
        }
        let record = NamespaceInfo::created(self.ns, owner, protocol, self.now.as_i64());
        for alias in &record.aliases {
            self.claim_alias(alias)?;
        }
        self.record_namespace(record)
    }

    pub fn namespace_transfer(&mut self, new_owner: &Kappa) -> Result<(), StoreError> {
        let mut record = namespace_info_in(self.view, self.ns)?;
        record.transfer(new_owner)?;
        self.record_namespace(record)
    }

    /// Tombstone the namespace and release every alias it holds.
    pub fn namespace_delete(&mut self) -> Result<(), StoreError> {
        let mut record = namespace_info_in(self.view, self.ns)?;
        for alias in record.tombstone()? {
            self.release_alias(&alias);
        }
        self.record_namespace(record)
    }

    /// Rename the alias `old_name` within `protocol`, which this namespace
    /// must hold, to `new_name`.
    pub fn namespace_rename(
        &mut self,
        old_name: &str,
        new_name: &str,
        protocol: Option<&ProtocolId>,
    ) -> Result<NamespaceRef, StoreError> {
        let mut record = namespace_info_in(self.view, self.ns)?;
        let old = NamespaceAlias::new(old_name, protocol);
        let new = NamespaceAlias::new(new_name, protocol);
        record.rename_alias(&old, new.clone())?;
        self.release_alias(&old);
        self.claim_alias(&new)?;
        let renamed = NamespaceRef::resolved(*self.ns.id(), new_name.to_owned(), protocol.cloned());
        self.record_namespace(record)?;
        Ok(renamed)
    }

    /// Add an alias, enforcing `MAX_ALIASES_PER_NAMESPACE`.
    pub fn namespace_add_alias(
        &mut self,
        alias: &str,
        protocol: Option<&ProtocolId>,
    ) -> Result<(), StoreError> {
        let mut record = namespace_info_in(self.view, self.ns)?;
        let alias = NamespaceAlias::new(alias, protocol);
        record.add_alias(alias.clone())?;
        self.claim_alias(&alias)?;
        self.record_namespace(record)
    }

    /// Apply the namespace record `info` to the candidate: the record, and
    /// the alias set its scoped names define. Called only by `apply_write`.
    pub(super) fn apply_namespace_record(&mut self, info: NamespaceInfo) {
        self.view.aliases = info
            .aliases
            .iter()
            .map(|alias| (alias.name.clone(), alias.scope().to_owned()))
            .collect();
        self.view.record = Some(info);
    }

    pub fn namespace_put_meta(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        if key.is_empty() {
            return Err(StoreError::Rejected(
                "namespace metadata key must be nonempty".into(),
            ));
        }
        let meta = MetadataTransition::namespace_meta(
            *self.ns.id(),
            self.incarnation_bytes(),
            key.to_string(),
            Some(value.to_vec()),
        );
        self.apply_record_transition(RecordTransition::Metadata(meta), MemoryPayload::NoResources)
            .map(drop)
    }

    /// Hold `value` under the namespace metadata `key`, or remove the key
    /// when the transition deletes it. Called only by `apply_write`.
    pub(super) fn apply_namespace_meta(&mut self, key: &str, value: Option<&[u8]>) {
        match value {
            Some(value) => {
                self.view.meta.insert(key.to_owned(), value.to_vec());
            }
            None => {
                self.view.meta.remove(key);
            }
        }
    }

    /// Deleting an absent key is a no-op and records no mutation.
    pub fn namespace_delete_meta(&mut self, key: &str) -> Result<(), StoreError> {
        if !self.view.meta.contains_key(key) {
            return Ok(());
        }
        let meta = MetadataTransition::namespace_meta(
            *self.ns.id(),
            self.incarnation_bytes(),
            key.to_string(),
            None,
        );
        self.apply_record_transition(RecordTransition::Metadata(meta), MemoryPayload::NoResources)
            .map(drop)
    }
}
