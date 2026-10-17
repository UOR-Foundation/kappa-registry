use dcbor::prelude::*;

use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::{NamespaceRef, ProtocolId};
use kappa_types::page::{NamespaceFilter, Page, PageRequest};

/// Apply alias policy to facts captured by a backend's coherent write view.
pub fn validate_alias_admission(
    name: &str,
    protocol: Option<&ProtocolId>,
    exact_exists: bool,
    global_exists: bool,
    scoped_exists: bool,
) -> Result<(), StoreError> {
    if name.is_empty() || name.contains('\0') {
        return Err(StoreError::Rejected(
            "namespace name must be nonempty and contain no NUL".into(),
        ));
    }
    if exact_exists || protocol.map_or(scoped_exists, |_| global_exists) {
        return Err(StoreError::Conflict(format!(
            "namespace alias collision: {name}"
        )));
    }
    Ok(())
}

/// Namespace info returned by `namespace_info` and `namespace_list`.
///
/// CBOR key assignments (PERMANENT):
///   0: ns, 1: name, 2: `owner_anchor`, 3: `created_at_ms`,
///   4: aliases, 5: protocol, 6: tombstoned, 7: `last_epoch`
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
    pub aliases: Vec<String>,
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
        for name in ["", "a\0b"] {
            assert!(validate_alias_admission(name, None, false, false, false).is_err());
            assert!(validate_alias_admission(name, Some(&protocol), false, false, false).is_err());
        }
        Ok(())
    }
}
