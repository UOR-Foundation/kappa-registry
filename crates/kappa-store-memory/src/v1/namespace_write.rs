//! Namespace record, alias, and configuration transitions applied to the
//! candidate view. Ledger semantics match the persistent backend: every
//! record change publishes the canonical record and records
//! `NamespaceUpdate` with its identity.
//!
//! The record is the namespace's own; its aliases are directory claims
//! (`claims`), reserved under the alias admission rule when written and
//! released through the transition that removes them, so a name is never
//! free while a published view still holds it.

use kappa_store::traits::namespace::NamespaceInfo;
use kappa_types::canonical::canonical_bytes;
use kappa_types::page::MAX_ALIASES_PER_NAMESPACE;
use kappa_types::{Axis, Kappa, MutationOp, NamespaceRef, ProtocolId, StoreError, VerifiedContent};

use super::claims::ClaimKey;
use super::execution::WriteCx;
use super::view::NamespaceView;

fn scope(protocol: Option<&ProtocolId>) -> String {
    protocol
        .map(ProtocolId::as_str)
        .unwrap_or_default()
        .to_owned()
}

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
        let content = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(&record))?;
        self.view.record = Some(record);
        self.publish_content(&content)?;
        self.record(MutationOp::NamespaceUpdate, content.kappa().clone(), None);
        Ok(())
    }

    fn live_record(&self, action: &str) -> Result<NamespaceInfo, StoreError> {
        let record = namespace_info_in(self.view, self.ns)?;
        if record.tombstoned {
            return Err(StoreError::Rejected(format!(
                "cannot {action} a deleted namespace"
            )));
        }
        Ok(record)
    }

    fn take_alias(&mut self, name: &str, protocol: &str) -> Result<(), StoreError> {
        self.reserve_alias(name, protocol)?;
        self.view
            .aliases
            .insert((name.to_owned(), protocol.to_owned()));
        Ok(())
    }

    fn drop_alias(&mut self, name: &str, protocol: &str) {
        self.view
            .aliases
            .remove(&(name.to_owned(), protocol.to_owned()));
        self.release(ClaimKey::Alias {
            name: name.to_owned(),
            protocol: protocol.to_owned(),
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
        let name = self.ns.display_name().to_owned();
        self.take_alias(&name, &scope(protocol))?;
        self.record_namespace(NamespaceInfo {
            ns: self.ns.clone(),
            name: name.clone(),
            owner_anchor: owner.cloned(),
            created_at_ms: self.now.as_i64(),
            aliases: vec![name],
            protocol: protocol.cloned(),
            tombstoned: false,
            last_epoch: 0,
        })
    }

    pub fn namespace_transfer(&mut self, new_owner: &Kappa) -> Result<(), StoreError> {
        let mut record = self.live_record("transfer")?;
        record.owner_anchor = Some(new_owner.clone());
        self.record_namespace(record)
    }

    /// Tombstone the namespace and release every alias it holds.
    pub fn namespace_delete(&mut self) -> Result<(), StoreError> {
        let mut record = namespace_info_in(self.view, self.ns)?;
        if record.tombstoned {
            return Err(StoreError::Rejected("namespace is already deleted".into()));
        }
        let held: Vec<(String, String)> = self.view.aliases.iter().cloned().collect();
        for (name, protocol) in held {
            self.drop_alias(&name, &protocol);
        }
        record.tombstoned = true;
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
        let scoped = scope(protocol);
        if !self
            .view
            .aliases
            .contains(&(old_name.to_owned(), scoped.clone()))
        {
            return Err(StoreError::NotFound(format!(
                "namespace alias {old_name} of {}",
                self.ns
            )));
        }
        let mut record = self.live_record("rename")?;
        self.drop_alias(old_name, &scoped);
        self.take_alias(new_name, &scoped)?;
        record.aliases.retain(|alias| alias != old_name);
        if !record.aliases.iter().any(|alias| alias == new_name) {
            record.aliases.push(new_name.to_owned());
        }
        new_name.clone_into(&mut record.name);
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
        let mut record = self.live_record("alias")?;
        if record.aliases.len() >= MAX_ALIASES_PER_NAMESPACE {
            return Err(StoreError::Rejected(format!(
                "namespace has {} aliases, max {MAX_ALIASES_PER_NAMESPACE}",
                record.aliases.len()
            )));
        }
        self.take_alias(alias, &scope(protocol))?;
        if !record.aliases.iter().any(|existing| existing == alias) {
            record.aliases.push(alias.to_owned());
        }
        self.record_namespace(record)
    }

    /// Publish the canonical metadata record and commit it to the ledger.
    fn record_metadata(&mut self, key: &str, value: Option<&[u8]>) -> Result<(), StoreError> {
        let record = kappa_types::epoch::MetadataRecord {
            namespace_id: self.ns.id().to_vec(),
            key: key.to_string(),
            value: value.map(<[u8]>::to_vec),
        };
        let content = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(&record))?;
        self.publish_content(&content)?;
        self.record(
            MutationOp::MetadataUpdate,
            content.kappa().clone(),
            Some(key.to_string()),
        );
        Ok(())
    }

    pub fn namespace_put_meta(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        if key.is_empty() {
            return Err(StoreError::Rejected(
                "namespace metadata key must be nonempty".into(),
            ));
        }
        self.view.meta.insert(key.to_string(), value.to_vec());
        self.record_metadata(key, Some(value))
    }

    /// Deleting an absent key is a no-op and records no mutation.
    pub fn namespace_delete_meta(&mut self, key: &str) -> Result<(), StoreError> {
        if self.view.meta.remove(key).is_none() {
            return Ok(());
        }
        self.record_metadata(key, None)
    }
}
