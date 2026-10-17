//! Git refs as namespace tags.
//!
//! Mutations run through an execution, so ref updates publish with the
//! repository's signed epoch. Every precondition is checked with
//! non-latching reads before the write, so a rejected ref leaves the
//! execution usable for the remaining refs of the same push.

use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::tag::TagUpdate;
use kappa_store::traits::tag::TagStore;
use kappa_store::{ExecutionReads, ExecutionWrites};

const MAX_SYMREF_DEPTH: usize = 10;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
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

impl RefError {
    /// True when the ref was rejected by a precondition and nothing was
    /// written; false for store failures, which latch the execution.
    pub const fn is_rejection(&self) -> bool {
        matches!(
            self,
            Self::UpdateRejected { .. } | Self::SymrefLoop { .. } | Self::NotFound(_)
        )
    }
}

/// Update a ref with compare-and-swap.
///
/// `old_kappa`: None = create, Some = expected current value, resolved
/// through symbolic refs.
pub fn update_ref<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    ref_name: &str,
    new_kappa: &Kappa,
    old_kappa: Option<&Kappa>,
) -> Result<(), RefError> {
    let current = execution.tag_get_raw(ref_name)?;
    let update = match (old_kappa, current) {
        (None, None) => TagUpdate::CreateIfAbsent {
            kappa: new_kappa.clone(),
        },
        (None, Some(_)) => {
            return Err(RefError::UpdateRejected {
                expected: "(none)".into(),
                actual: "(exists)".into(),
            });
        }
        (Some(expected), None) => {
            return Err(RefError::UpdateRejected {
                expected: expected.to_string(),
                actual: "(none)".into(),
            });
        }
        (Some(expected), Some(current)) => {
            let resolved = if current.symref.is_some() {
                resolve_ref_in(execution, ref_name)?
                    .ok_or_else(|| RefError::NotFound(ref_name.to_string()))?
            } else {
                current.kappa.clone()
            };
            if resolved != *expected {
                return Err(RefError::UpdateRejected {
                    expected: expected.to_string(),
                    actual: resolved.to_string(),
                });
            }
            TagUpdate::CompareAndSwap {
                kappa: new_kappa.clone(),
                expected_version: current.version,
            }
        }
    };
    execution.tag_put(ref_name, &update)?;
    Ok(())
}

/// Resolve a ref within an execution's view, following symbolic refs.
pub fn resolve_ref_in<E: ExecutionReads + ?Sized>(
    execution: &E,
    ref_name: &str,
) -> Result<Option<Kappa>, RefError> {
    let mut current = ref_name.to_string();
    for _ in 0..MAX_SYMREF_DEPTH {
        match execution.tag_get_raw(&current)? {
            Some(entry) => match entry.symref {
                Some(target) => current = target,
                None => return Ok(Some(entry.kappa)),
            },
            None => return Ok(None),
        }
    }
    Err(RefError::SymrefLoop {
        name: ref_name.to_string(),
    })
}

/// Resolve a published ref to its target kappa, following symbolic refs.
pub fn resolve_ref<S: TagStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    ref_name: &str,
) -> Result<Option<Kappa>, RefError> {
    let mut current = ref_name.to_string();
    for _ in 0..MAX_SYMREF_DEPTH {
        match store.tag_get(namespace, &current) {
            Ok(entry) => {
                if let Some(ref target) = entry.symref {
                    current = target.clone();
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

/// Create a symbolic ref.
pub fn set_symbolic_ref<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    name: &str,
    target: &str,
) -> Result<(), RefError> {
    execution.tag_put(
        name,
        &TagUpdate::SetSymref {
            target: target.to_string(),
        },
    )?;
    Ok(())
}

/// List all published refs matching a prefix.
pub fn list_refs<S: TagStore + ?Sized>(
    store: &S,
    namespace: &NamespaceRef,
    prefix: &str,
) -> Result<Vec<(String, String)>, RefError> {
    let prefix_opt = if prefix.is_empty() {
        None
    } else {
        Some(prefix)
    };
    let mut request = kappa_store::PageRequest::first(1024);
    let mut refs = Vec::new();
    loop {
        let page = store.tag_list(namespace, prefix_opt, &request)?;
        refs.extend(page.items.into_iter().map(|tag| {
            let value = tag
                .symref
                .map_or_else(|| tag.kappa.to_string(), |target| format!("ref: {target}"));
            (tag.name, value)
        }));
        let Some(next) = page.next_after else {
            return Ok(refs);
        };
        if request
            .after
            .as_ref()
            .is_some_and(|previous| previous >= &next)
        {
            return Err(StoreError::Internal("ref pagination did not advance".into()).into());
        }
        request.after = Some(next);
    }
}

/// Delete a ref. `expected` is the value the caller observed, resolved
/// through symbolic refs; `None` deletes whatever the ref holds.
pub fn delete_ref<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    ref_name: &str,
    expected: Option<&Kappa>,
) -> Result<(), RefError> {
    if execution.tag_get_raw(ref_name)?.is_none() {
        return Err(RefError::NotFound(ref_name.to_string()));
    }
    if let Some(expected) = expected {
        let resolved = resolve_ref_in(execution, ref_name)?;
        if resolved.as_ref() != Some(expected) {
            return Err(RefError::UpdateRejected {
                expected: expected.to_string(),
                actual: resolved.map_or_else(|| "(none)".into(), |kappa| kappa.to_string()),
            });
        }
    }
    execution.tag_delete(ref_name)?;
    Ok(())
}

#[cfg(test)]
#[path = "refs_tests.rs"]
mod tests;
