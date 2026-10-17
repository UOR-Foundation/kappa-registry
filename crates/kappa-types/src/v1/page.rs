use crate::kappa::Kappa;
use crate::namespace::ProtocolId;

/// Pagination parameters for all list operations across all traits.
///
/// Constructed by `kappa_handler::page_request_from(cx, max_limit)`.
/// The handler never assembles these fields manually. The infrastructure
/// clamps limit, validates cursor format, and returns a `PageRequest`
/// that every store method trusts without further validation.
///
/// `limit` is always present and always clamped. No `Option<usize>`.
/// `after` is the cursor -- the last item's sort key from the previous
/// page. `None` starts from the beginning.
#[derive(Debug, Clone)]
pub struct PageRequest {
    pub limit: usize,
    pub after: Option<String>,
}

impl PageRequest {
    pub const fn new(limit: usize, after: Option<String>) -> Self {
        Self { limit, after }
    }

    pub const fn first(limit: usize) -> Self {
        Self { limit, after: None }
    }
}

/// Result of a paginated list operation.
///
/// The store fetches `limit + 1` items. If `limit + 1` items exist,
/// `next_after` is the `limit`-th item's sort key, and `items` is
/// truncated to `limit`. If fewer than `limit + 1` items exist,
/// `next_after` is `None` (no more pages).
#[derive(Debug, Clone)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_after: Option<String>,
}

impl<T> Page<T> {
    pub const fn empty() -> Self {
        Self {
            items: Vec::new(),
            next_after: None,
        }
    }

    /// Construct from a vec that may contain `limit + 1` items.
    /// If the vec has more than `limit` items, the last item's
    /// sort key (extracted by `key_fn`) becomes `next_after`,
    /// and the vec is truncated to `limit`.
    pub fn from_oversized(mut items: Vec<T>, limit: usize, key_fn: impl Fn(&T) -> String) -> Self {
        if limit == 0 {
            return Self::empty();
        }
        if items.len() > limit {
            let next = key_fn(&items[limit - 1]);
            items.truncate(limit);
            Self {
                items,
                next_after: Some(next),
            }
        } else {
            Self {
                items,
                next_after: None,
            }
        }
    }

    pub const fn len(&self) -> usize {
        self.items.len()
    }
    pub const fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub const fn has_more(&self) -> bool {
        self.next_after.is_some()
    }
}

/// Maximum aliases per namespace.
///
/// Enforced by the trait's default
/// implementation of `namespace_add_alias`. Both store backends
/// inherit the enforcement. A third backend gets it for free.
/// 64 aliases x 50 bytes x 10K concurrent deletes = 32 MB.
pub const MAX_ALIASES_PER_NAMESPACE: usize = 64;

/// Domain-specific filters for `namespace_list`.
/// Default gives no filters (returns all non-tombstoned namespaces).
/// Each field is additive (AND).
#[derive(Debug, Clone, Default)]
pub struct NamespaceFilter {
    pub protocol: Option<ProtocolId>,
    pub owner_anchor: Option<Kappa>,
    pub tombstoned: Option<bool>,
    pub created_after_ms: Option<i64>,
    pub last_epoch_after: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_request_first() {
        let pr = PageRequest::first(100);
        assert_eq!(pr.limit, 100);
        assert!(pr.after.is_none());
    }

    #[test]
    fn page_empty() {
        let p: Page<String> = Page::empty();
        assert!(p.is_empty());
        assert!(!p.has_more());
    }

    #[test]
    fn zero_limit_is_empty_without_underflow_or_cursor() {
        let page = Page::from_oversized(vec!["item".to_string()], 0, Clone::clone);
        assert!(page.is_empty());
        assert!(!page.has_more());
    }

    #[test]
    fn page_from_oversized_truncates() {
        let items: Vec<String> = (0..11).map(|i| format!("item-{i:02}")).collect();
        let page = Page::from_oversized(items, 10, Clone::clone);
        assert_eq!(page.len(), 10);
        assert!(page.has_more());
        assert_eq!(page.next_after, Some("item-09".to_string()));
    }

    #[test]
    fn page_from_oversized_exact_fit() {
        let items: Vec<String> = (0..10).map(|i| format!("item-{i:02}")).collect();
        let page = Page::from_oversized(items, 10, Clone::clone);
        assert_eq!(page.len(), 10);
        assert!(!page.has_more());
    }

    #[test]
    fn page_from_oversized_under_limit() {
        let items: Vec<String> = (0..3).map(|i| format!("item-{i}")).collect();
        let page = Page::from_oversized(items, 10, Clone::clone);
        assert_eq!(page.len(), 3);
        assert!(!page.has_more());
    }

    #[test]
    fn namespace_filter_default_is_empty() {
        let f = NamespaceFilter::default();
        assert!(f.protocol.is_none());
        assert!(f.owner_anchor.is_none());
        assert!(f.tombstoned.is_none());
        assert!(f.created_after_ms.is_none());
        assert!(f.last_epoch_after.is_none());
    }
}
