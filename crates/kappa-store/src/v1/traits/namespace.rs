use dcbor::prelude::*;

use kappa_types::AuthorityState;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::{NamespaceRef, ProtocolId};
use kappa_types::page::{MAX_ALIASES_PER_NAMESPACE, NamespaceFilter, Page, PageRequest};

/// Apply alias policy to facts captured by a backend's coherent write view.
pub fn validate_alias_admission(
    name: &str,
    protocol: Option<&ProtocolId>,
    exact_exists: bool,
    global_exists: bool,
    scoped_exists: bool,
) -> Result<(), StoreError> {
    kappa_types::namespace::validate_alias_name(name)
        .map_err(|error| StoreError::Rejected(error.to_string()))?;
    if exact_exists || protocol.map_or(scoped_exists, |_| global_exists) {
        return Err(StoreError::Conflict(format!(
            "namespace alias collision: {name}"
        )));
    }
    Ok(())
}

/// One name a namespace holds in the directory: global (`protocol` absent)
/// or scoped to one protocol. Each is one exclusive directory claim.
///
/// CBOR key assignments (PERMANENT): 0: name, 1: protocol
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct NamespaceAlias {
    #[cbor(n = 0)]
    pub name: String,
    #[cbor(n = 1)]
    pub protocol: Option<ProtocolId>,
}

impl NamespaceAlias {
    pub fn new(name: impl Into<String>, protocol: Option<&ProtocolId>) -> Self {
        Self {
            name: name.into(),
            protocol: protocol.cloned(),
        }
    }

    /// The claim scope: the protocol, or empty for a global name.
    pub fn scope(&self) -> &str {
        self.protocol.as_ref().map_or("", ProtocolId::as_str)
    }
}

/// Namespace info returned by `namespace_info` and `namespace_list`.
///
/// CBOR key assignments (PERMANENT):
///   0: ns, 1: name, 2: `owner_anchor`, 3: `created_at_ms`,
///   4: aliases, 5: protocol, 6: tombstoned, 7: `last_epoch`
///
/// `aliases` are the scoped names the namespace holds, in the order they
/// were taken; the record is the authoritative list of its claims.
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct NamespaceInfo {
    #[cbor(n = 0)]
    pub ns: NamespaceRef,
    #[cbor(n = 1)]
    pub name: String,
    #[cbor(n = 2)]
    pub owner_anchor: Option<Kappa>,
    #[cbor(n = 3)]
    pub created_at_ms: i64,
    #[cbor(n = 4)]
    pub aliases: Vec<NamespaceAlias>,
    #[cbor(n = 5)]
    pub protocol: Option<ProtocolId>,
    #[cbor(n = 6)]
    pub tombstoned: bool,
    /// Epoch number of the last sealed epoch in this namespace.
    /// 0 for namespaces that have never had an epoch sealed.
    /// Updated by `epoch_advance` after sealing.
    /// The relay reads this from `namespace_list` to skip unchanged repos.
    #[cbor(n = 7)]
    pub last_epoch: u64,
}

/// Every record change a namespace lifecycle operation makes. Backends apply
/// the changed record through their transition boundary and make the
/// directory claims and releases these name; neither decides the record
/// itself.
impl NamespaceInfo {
    /// The record a creation of `ns` within `protocol` writes: its display
    /// name, held as its one alias.
    pub fn created(
        ns: &NamespaceRef,
        owner: Option<&Kappa>,
        protocol: Option<&ProtocolId>,
        created_at_ms: i64,
    ) -> Self {
        let name = ns.display_name().to_owned();
        Self {
            ns: ns.clone(),
            aliases: vec![NamespaceAlias::new(name.clone(), protocol)],
            name,
            owner_anchor: owner.cloned(),
            created_at_ms,
            protocol: protocol.cloned(),
            tombstoned: false,
            last_epoch: 0,
        }
    }

    /// Refuse `action` on a deleted namespace.
    pub fn check_live(&self, action: &str) -> Result<(), StoreError> {
        if self.tombstoned {
            return Err(StoreError::Rejected(format!(
                "cannot {action} a deleted namespace"
            )));
        }
        Ok(())
    }

    /// Hold `alias` as well, within `MAX_ALIASES_PER_NAMESPACE`; an alias
    /// already held is kept once. The caller claims it in the directory.
    pub fn add_alias(&mut self, alias: NamespaceAlias) -> Result<(), StoreError> {
        self.check_live("alias")?;
        if self.aliases.len() >= MAX_ALIASES_PER_NAMESPACE {
            return Err(StoreError::Rejected(format!(
                "namespace has {} aliases, max {MAX_ALIASES_PER_NAMESPACE}",
                self.aliases.len()
            )));
        }
        if !self.aliases.contains(&alias) {
            self.aliases.push(alias);
        }
        Ok(())
    }

    /// Rename the alias `old`, which the record must hold, to `new`, which
    /// becomes the record's name. The caller releases `old` and claims
    /// `new` in the directory.
    pub fn rename_alias(
        &mut self,
        old: &NamespaceAlias,
        new: NamespaceAlias,
    ) -> Result<(), StoreError> {
        self.check_live("rename")?;
        if !self.aliases.contains(old) {
            return Err(StoreError::NotFound(format!(
                "namespace alias {} of {}",
                old.name, self.ns
            )));
        }
        self.aliases.retain(|alias| alias != old);
        self.name.clone_from(&new.name);
        if !self.aliases.contains(&new) {
            self.aliases.push(new);
        }
        Ok(())
    }

    /// Give the namespace to `owner`; returns the owner it had.
    pub fn transfer(&mut self, owner: &Kappa) -> Result<Option<Kappa>, StoreError> {
        self.check_live("transfer")?;
        Ok(self.owner_anchor.replace(owner.clone()))
    }

    /// Tombstone the namespace; returns every alias it released, which the
    /// caller releases in the directory. A deleted record holds no alias.
    pub fn tombstone(&mut self) -> Result<Vec<NamespaceAlias>, StoreError> {
        if self.tombstoned {
            return Err(StoreError::Rejected("namespace is already deleted".into()));
        }
        self.tombstoned = true;
        Ok(std::mem::take(&mut self.aliases))
    }

    /// The authority record an epoch of the instance `(namespace,
    /// incarnation)` commits when its final record is `record`. A namespace
    /// without a record is governed by the node's authority lineage under
    /// its canonical identifier-derived scope.
    pub fn authority_state(
        record: Option<&Self>,
        namespace: [u8; 16],
        incarnation: [u8; 16],
    ) -> Result<AuthorityState, StoreError> {
        record.map_or_else(
            || {
                AuthorityState::new(
                    namespace,
                    incarnation,
                    None,
                    hex::encode(namespace),
                    None,
                    false,
                )
            },
            |record| {
                AuthorityState::new(
                    namespace,
                    incarnation,
                    record.owner_anchor.clone(),
                    record.name.clone(),
                    record.protocol.clone(),
                    record.tombstoned,
                )
            },
        )
    }
}

/// Published namespace records, alias resolution, and namespace-scoped
/// metadata.
///
/// Lifecycle changes (create, rename, transfer, alias, delete)
/// and metadata writes go through `ExecutionWrites`, so each publishes with
/// its ledger record; `execution::namespace_ensure` creates a namespace in
/// its own epoch.
pub trait NamespaceStore: Send + Sync {
    fn namespace_resolve(
        &self,
        path: &str,
        protocol: Option<&ProtocolId>,
    ) -> Result<NamespaceRef, StoreError>;

    fn namespace_exists(
        &self,
        path: &str,
        protocol: Option<&ProtocolId>,
    ) -> Result<bool, StoreError>;

    fn namespace_info(&self, ns: &NamespaceRef) -> Result<NamespaceInfo, StoreError>;

    /// List namespaces matching filters, paginated.
    ///
    /// `NamespaceFilter` carries: protocol, `owner_anchor`, tombstoned,
    /// `created_after_ms`, `last_epoch_after`. All Option, all AND'd.
    /// `Default()` gives no filters.
    ///
    /// `PageRequest` carries: limit (always present, always clamped
    /// by the handler), after (cursor, None starts from beginning).
    ///
    /// Returns `Page<NamespaceInfo>` with `next_after` cursor for the
    /// next page, or None if this is the last page.
    fn namespace_list(
        &self,
        filter: &NamespaceFilter,
        page: &PageRequest,
    ) -> Result<Page<NamespaceInfo>, StoreError>;

    fn namespace_get_meta(&self, ns: &NamespaceRef, key: &str) -> Result<Vec<u8>, StoreError>;

    /// List namespace metadata keys matching a prefix, paginated.
    /// Returns the original key strings, not hashed values.
    fn namespace_list_meta_keys(
        &self,
        ns: &NamespaceRef,
        prefix: &str,
        page: &PageRequest,
    ) -> Result<Page<String>, StoreError>;
}

#[cfg(test)]
mod alias_policy_tests {
    use super::{ProtocolId, validate_alias_admission};

    #[test]
    fn global_and_scoped_aliases_share_one_collision_policy()
    -> Result<(), Box<dyn std::error::Error>> {
        let protocol = ProtocolId::new("custom")?;
        for exact in [false, true] {
            for global in [false, true] {
                for scoped in [false, true] {
                    assert_eq!(
                        validate_alias_admission("name", None, exact, global, scoped).is_ok(),
                        !(exact || scoped)
                    );
                    assert_eq!(
                        validate_alias_admission("name", Some(&protocol), exact, global, scoped)
                            .is_ok(),
                        !(exact || global)
                    );
                }
            }
        }
        let oversized = "n".repeat(kappa_types::namespace::MAX_ALIAS_NAME_BYTES + 1);
        for name in ["", "a\0b", oversized.as_str()] {
            assert!(validate_alias_admission(name, None, false, false, false).is_err());
            assert!(validate_alias_admission(name, Some(&protocol), false, false, false).is_err());
        }
        Ok(())
    }
}
