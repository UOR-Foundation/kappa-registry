//! Namespace-indexed blob metadata.
//!
//! Per-blob metadata is global: `blob_meta_put` attaches a value to content
//! wherever it is stored. A namespace that finds its blobs by a metadata
//! value also records an index entry in its own metadata, written by the
//! same execution, so the index publishes with the blob it names, is part
//! of the namespace's authenticated state, and replays with it.
//!
//! Index entry key: `_meta/{key_len}/{key}{value_len}/{value}/{kappa}`, with
//! byte lengths. The length prefixes make the `(key, value)` prefix
//! unambiguous whatever characters the key and value contain, so a query
//! for one pair never matches another.

use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::page::{Page, PageRequest};

use crate::execution::ExecutionWrites;
use crate::traits::namespace::NamespaceStore;

/// Namespace metadata prefix reserved for the blob metadata index.
pub const META_INDEX_PREFIX: &str = "_meta/";

/// Index key prefix shared by every blob carrying `key = value`.
pub fn meta_index_prefix(key: &str, value: &str) -> String {
    format!(
        "{META_INDEX_PREFIX}{}/{key}{}/{value}/",
        key.len(),
        value.len()
    )
}

/// Attach `key = value` to `identity` and index it in the execution's
/// namespace, in that execution.
pub fn blob_meta_put_indexed(
    execution: &mut (impl ExecutionWrites + ?Sized),
    identity: &Kappa,
    key: &str,
    value: &str,
) -> Result<(), StoreError> {
    execution.blob_meta_put(identity, key, value.as_bytes())?;
    execution.namespace_put_meta(&format!("{}{identity}", meta_index_prefix(key, value)), &[])
}

/// Blobs of namespace `ns` indexed with `key = value`, in identity order.
///
/// The page cursor is the last returned identity.
pub fn meta_query<S: NamespaceStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    key: &str,
    value: &str,
    page: &PageRequest,
) -> Result<Page<Kappa>, StoreError> {
    let prefix = meta_index_prefix(key, value);
    let request = PageRequest {
        limit: page.limit,
        after: page.after.as_ref().map(|after| format!("{prefix}{after}")),
    };
    let entries = store.namespace_list_meta_keys(ns, &prefix, &request)?;
    let identity = |entry: &str| -> Result<String, StoreError> {
        entry
            .strip_prefix(&prefix)
            .map(str::to_owned)
            .ok_or_else(|| StoreError::Internal(format!("meta index escaped prefix: {entry}")))
    };
    let items = entries
        .items
        .iter()
        .map(|entry| Ok(Kappa::parse(&identity(entry)?)?))
        .collect::<Result<Vec<_>, StoreError>>()?;
    let next_after = entries.next_after.as_deref().map(identity).transpose()?;
    Ok(Page { items, next_after })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_of_distinct_pairs_never_nest() {
        let pairs = [
            ("object-type", "manifest"),
            ("object-type", "manifest-list"),
            ("object-type", "man"),
            ("object-typ", "e/manifest"),
            ("object-type/", "manifest"),
            ("", "object-type/manifest"),
            ("a/b", "c"),
            ("a", "b/c"),
        ];
        for (i, (k1, v1)) in pairs.iter().enumerate() {
            for (j, (k2, v2)) in pairs.iter().enumerate() {
                let (p1, p2) = (meta_index_prefix(k1, v1), meta_index_prefix(k2, v2));
                assert_eq!(
                    i == j,
                    p2.starts_with(&p1),
                    "{k1:?}={v1:?} against {k2:?}={v2:?}: {p1} / {p2}"
                );
            }
        }
    }

    #[test]
    fn prefix_lengths_count_bytes() {
        assert_eq!(
            meta_index_prefix("\u{e9}", "\u{fc}"),
            "_meta/2/\u{e9}2/\u{fc}/"
        );
    }
}
