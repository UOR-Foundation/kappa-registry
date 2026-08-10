//! Git ref management over KappaStore tags.
//!
//! Git refs map to kappa tags. refs/heads/main in namespace "myrepo"
//! is tag "refs/heads/main" in namespace "myrepo". HEAD is tag "HEAD".
//! Symbolic refs ("ref: refs/heads/main") stored as tag values.

use kappa_core::store::KappaStore;
use kappa_core::types::StoreError;

const SYMREF_PREFIX: &str = "ref: ";
const MAX_SYMREF_DEPTH: usize = 10;

/// Errors from ref operations.
#[derive(Debug, thiserror::Error)]
pub enum RefError {
    #[error("store error: {0}")]
    Store(#[from] StoreError),
    #[error("ref update rejected: expected {expected}, actual {actual}")]
    UpdateRejected { expected: String, actual: String },
    #[error("symbolic ref loop or depth exceeded for {name}")]
    SymrefLoop { name: String },
    #[error("ref not found: {0}")]
    NotFound(String),
}

/// Update a ref atomically with compare-and-swap.
///
/// `old_oid`: None = create (ref must not exist), Some = expected current value.
/// Returns Ok(()) on success, Err(UpdateRejected) if CAS fails.
pub fn update_ref(
    store: &dyn KappaStore,
    namespace: &str,
    ref_name: &str,
    new_oid: &str,
    old_oid: Option<&str>,
) -> Result<(), RefError> {
    match old_oid {
        None => {
            // Create: use tag_set_batch with expected_version=0 (create-if-absent)
            let updates = vec![kappa_core::types::TagUpdate {
                name: ref_name.to_string(),
                kappa: new_oid.to_string(),
                expected_version: Some(0),
            }];
            store.tag_set_batch(namespace, &updates).map_err(|e| match e {
                StoreError::Conflict(_) => RefError::UpdateRejected {
                    expected: "(none)".into(),
                    actual: "(exists)".into(),
                },
                other => RefError::Store(other),
            })
        }
        Some(expected) => {
            // Atomic CAS via tag_set_batch with expected_version.
            // Read current to get the version number, then batch-set
            // with that version as the expectation. If another writer
            // changed the ref between read and write, the version won't
            // match and the batch fails atomically. No TOCTOU.
            let current = store.tag_get(namespace, ref_name).map_err(|e| match e {
                StoreError::NotFound(_) => RefError::UpdateRejected {
                    expected: expected.to_string(),
                    actual: "(none)".to_string(),
                },
                other => RefError::Store(other),
            })?;

            // Resolve symbolic refs for the comparison value
            let resolved = if current.kappa.starts_with(SYMREF_PREFIX) {
                resolve_ref(store, namespace, ref_name)?
                    .ok_or_else(|| RefError::NotFound(ref_name.to_string()))?
            } else {
                current.kappa.clone()
            };

            if resolved != expected {
                return Err(RefError::UpdateRejected {
                    expected: expected.to_string(),
                    actual: resolved,
                });
            }

            // Atomic write with version CAS
            let updates = vec![kappa_core::types::TagUpdate {
                name: ref_name.to_string(),
                kappa: new_oid.to_string(),
                expected_version: Some(current.version),
            }];
            store.tag_set_batch(namespace, &updates).map_err(|e| match e {
                StoreError::Conflict(_) => RefError::UpdateRejected {
                    expected: expected.to_string(),
                    actual: "(concurrent modification)".into(),
                },
                other => RefError::Store(other),
            })
        }
    }
}

/// Resolve a ref to its target OID, following symbolic ref chains.
///
/// Returns None if the ref does not exist.
/// Follows "ref: {target}" chains up to MAX_SYMREF_DEPTH.
pub fn resolve_ref(
    store: &dyn KappaStore,
    namespace: &str,
    ref_name: &str,
) -> Result<Option<String>, RefError> {
    let mut current = ref_name.to_string();
    for _ in 0..MAX_SYMREF_DEPTH {
        match store.tag_get(namespace, &current) {
            Ok(entry) => {
                if let Some(target) = entry.kappa.strip_prefix(SYMREF_PREFIX) {
                    current = target.to_string();
                } else {
                    return Ok(Some(entry.kappa));
                }
            }
            Err(StoreError::NotFound(_)) => return Ok(None),
            Err(e) => return Err(RefError::Store(e)),
        }
    }
    Err(RefError::SymrefLoop {
        name: ref_name.to_string(),
    })
}

/// Create a symbolic ref: name points to target ref, not to an OID.
pub fn set_symbolic_ref(
    store: &dyn KappaStore,
    namespace: &str,
    name: &str,
    target: &str,
) -> Result<(), RefError> {
    let value = format!("{}{}", SYMREF_PREFIX, target);
    store.tag_set(namespace, name, &value)?;
    Ok(())
}

/// List all refs matching a prefix.
/// Returns (ref_name, target_oid_or_symref) pairs.
pub fn list_refs(
    store: &dyn KappaStore,
    namespace: &str,
    prefix: &str,
) -> Result<Vec<(String, String)>, RefError> {
    let tags = store.tag_prefix(namespace, prefix)?;
    Ok(tags
        .into_iter()
        .map(|t| (t.name, t.kappa))
        .collect())
}

/// Delete a ref.
pub fn delete_ref(
    store: &dyn KappaStore,
    namespace: &str,
    ref_name: &str,
) -> Result<(), RefError> {
    store.tag_delete(namespace, ref_name)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_core::clock::ntp_lamport::NtpLamportClock;
    use kappa_core::store::memory::{InMemoryStore, MemoryStoreConfig};
    use std::sync::Arc;

    fn test_store() -> (Arc<InMemoryStore>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let clock = Arc::new(NtpLamportClock::new());
        let store = InMemoryStore::new(
            MemoryStoreConfig::new(tmp.path().join("blobs")),
            clock,
        )
        .unwrap();
        (Arc::new(store), tmp)
    }

    #[test]
    fn create_and_resolve_ref() {
        let (store, _tmp) = test_store();
        update_ref(&*store, "repo", "refs/heads/main", "sha1:aaa", None).unwrap();
        let resolved = resolve_ref(&*store, "repo", "refs/heads/main").unwrap();
        assert_eq!(resolved, Some("sha1:aaa".into()));
    }

    #[test]
    fn cas_update_ref() {
        let (store, _tmp) = test_store();
        update_ref(&*store, "repo", "refs/heads/main", "sha1:aaa", None).unwrap();
        update_ref(&*store, "repo", "refs/heads/main", "sha1:bbb", Some("sha1:aaa")).unwrap();
        let resolved = resolve_ref(&*store, "repo", "refs/heads/main").unwrap();
        assert_eq!(resolved, Some("sha1:bbb".into()));
    }

    #[test]
    fn cas_rejects_wrong_old() {
        let (store, _tmp) = test_store();
        update_ref(&*store, "repo", "refs/heads/main", "sha1:aaa", None).unwrap();
        let result = update_ref(&*store, "repo", "refs/heads/main", "sha1:bbb", Some("sha1:wrong"));
        assert!(matches!(result, Err(RefError::UpdateRejected { .. })));
    }

    #[test]
    fn symbolic_ref_resolution() {
        let (store, _tmp) = test_store();
        update_ref(&*store, "repo", "refs/heads/main", "sha1:aaa", None).unwrap();
        set_symbolic_ref(&*store, "repo", "HEAD", "refs/heads/main").unwrap();
        let resolved = resolve_ref(&*store, "repo", "HEAD").unwrap();
        assert_eq!(resolved, Some("sha1:aaa".into()));
    }

    #[test]
    fn symbolic_ref_chain() {
        let (store, _tmp) = test_store();
        update_ref(&*store, "repo", "refs/heads/main", "sha1:aaa", None).unwrap();
        set_symbolic_ref(&*store, "repo", "refs/heads/dev", "refs/heads/main").unwrap();
        set_symbolic_ref(&*store, "repo", "HEAD", "refs/heads/dev").unwrap();
        let resolved = resolve_ref(&*store, "repo", "HEAD").unwrap();
        assert_eq!(resolved, Some("sha1:aaa".into()));
    }

    #[test]
    fn resolve_missing_returns_none() {
        let (store, _tmp) = test_store();
        let resolved = resolve_ref(&*store, "repo", "refs/heads/nonexistent").unwrap();
        assert!(resolved.is_none());
    }

    #[test]
    fn list_refs_by_prefix() {
        let (store, _tmp) = test_store();
        update_ref(&*store, "repo", "refs/heads/main", "sha1:aaa", None).unwrap();
        update_ref(&*store, "repo", "refs/heads/dev", "sha1:bbb", None).unwrap();
        update_ref(&*store, "repo", "refs/tags/v1.0", "sha1:ccc", None).unwrap();
        let heads = list_refs(&*store, "repo", "refs/heads/").unwrap();
        assert_eq!(heads.len(), 2);
        let tags = list_refs(&*store, "repo", "refs/tags/").unwrap();
        assert_eq!(tags.len(), 1);
    }

    #[test]
    fn delete_ref_removes_it() {
        let (store, _tmp) = test_store();
        update_ref(&*store, "repo", "refs/heads/main", "sha1:aaa", None).unwrap();
        delete_ref(&*store, "repo", "refs/heads/main").unwrap();
        let resolved = resolve_ref(&*store, "repo", "refs/heads/main").unwrap();
        assert!(resolved.is_none());
    }
}
