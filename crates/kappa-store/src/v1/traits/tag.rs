use kappa_cursor::KappaCursor;

use kappa_types::error::StoreError;
use kappa_types::namespace::NamespaceRef;
use kappa_types::page::{Page, PageRequest};
use kappa_types::tag::TagEntry;

/// Published named pointers to kappa digests.
///
/// Tags are the mutable layer over the immutable content-addressed store.
/// This trait reads published state; tag writes (CAS, symbolic references,
/// atomic batches) go through `ExecutionWrites` and publish with their epoch.
pub trait TagStore: Send + Sync {
    /// Get a tag by name. Resolves symbolic references.
    fn tag_get(&self, ns: &NamespaceRef, name: &str) -> Result<TagEntry, StoreError>;

    /// Get a tag without resolving symbolic references.
    fn tag_get_raw(&self, ns: &NamespaceRef, name: &str) -> Result<TagEntry, StoreError>;

    /// List tags with optional prefix filter, paginated.
    ///
    /// The prefix filter serves Git ref listing (prefix "refs/"),
    /// OCI tag listing (no prefix), Nix narinfo scanning (prefix
    /// "narinfo:"), AT Protocol record listing (prefix "record/"),
    /// and internal metadata listing (prefix "_versions/").
    fn tag_list(
        &self,
        ns: &NamespaceRef,
        prefix: Option<&str>,
        page: &PageRequest,
    ) -> Result<Page<TagEntry>, StoreError>;

    /// Cursor over tag names in sorted order within a namespace.
    ///
    /// Yields tag name bytes in lexicographic order. Supports
    /// O(depth) seek for pagination and prefix queries without
    /// materializing the full tag set.
    ///
    /// Includes internal tags: public list visibility is not a retention rule.
    /// The returned cursor must retain one captured name set. Implementations
    /// must not synthesize completeness using an oversized public list request.
    fn tag_cursor(
        &self,
        ns: &NamespaceRef,
        prefix: Option<&str>,
    ) -> Result<Box<dyn KappaCursor + '_>, StoreError>;
}
