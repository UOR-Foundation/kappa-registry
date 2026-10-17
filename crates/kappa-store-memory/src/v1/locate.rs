//! Registry-wide reads through projections and claims, decided by the
//! published namespace views.
//!
//! A projection names candidate namespaces; a claim names the one
//! namespace that may hold an exclusive row. Neither decides: every answer
//! is read from the candidate's published view, confirmed to have reached
//! the contribution's revision in its incarnation (`InMemoryStore::confirm`).
//! A candidate whose publication is still in progress is skipped, so a read
//! that overlaps a publication may miss it and a read that begins after
//! the publication returned finds it.
//!
//! Work is bounded by candidates examined, not only by answers returned.
//! A walk that reaches `CANDIDATE_BOUND` before it has examined every
//! candidate reports itself incomplete: a positive answer found before then
//! stands, and an absence or a complete listing is reported unavailable.

use std::fmt::Display;
use std::hash::Hash;
use std::ops::Bound;
use std::sync::Arc;

use kappa_types::error::StoreError;
use kappa_types::page::Page;

use super::InMemoryStore;
use super::claims::ClaimKey;
use super::locator::Locator;
use super::projection::after;
use super::view::{NamespaceId, NamespaceView};

/// Candidates examined per projection page.
pub const CANDIDATE_PAGE: usize = 16;
/// Candidates one keyed lookup examines before it reports itself
/// incomplete.
pub const CANDIDATE_BOUND: usize = 1024;
/// Keys a listing examines per requested item before it returns a short
/// page with its continuation.
pub const LISTING_FACTOR: usize = 4;

/// The error for a walk that reached `CANDIDATE_BOUND`.
pub fn incomplete(what: &dyn Display) -> StoreError {
    StoreError::Unavailable(format!(
        "{what}: more than {CANDIDATE_BOUND} candidate namespaces examined"
    ))
}

impl InMemoryStore {
    /// The confirmed published views of `key`'s candidates from `from`, in
    /// namespace order, examining at most `CANDIDATE_BOUND`; `visit`
    /// returns true to stop. Returns whether the walk stopped or examined
    /// every candidate.
    pub(crate) fn located_from<K: Ord + Hash + Clone>(
        &self,
        locator: &Locator<K>,
        key: &K,
        mut from: Bound<NamespaceId>,
        mut visit: impl FnMut(NamespaceId, &Arc<NamespaceView>) -> bool,
    ) -> bool {
        let mut examined = 0usize;
        loop {
            let page = locator.observe_from(key, from.as_ref(), CANDIDATE_PAGE);
            for candidate in &page.candidates {
                examined += 1;
                if let Some(view) = self.confirm(*candidate)
                    && visit(candidate.namespace, &view)
                {
                    return true;
                }
            }
            match page.more {
                Some(next) if examined < CANDIDATE_BOUND => from = Bound::Excluded(next),
                Some(_) => return false,
                None => return true,
            }
        }
    }

    /// `located_from` over every candidate.
    pub(crate) fn located<K: Ord + Hash + Clone>(
        &self,
        locator: &Locator<K>,
        key: &K,
        visit: impl FnMut(NamespaceId, &Arc<NamespaceView>) -> bool,
    ) -> bool {
        self.located_from(locator, key, Bound::Unbounded, visit)
    }

    /// The first row `read` finds in a confirmed candidate view of `key`.
    pub(crate) fn find<K: Ord + Hash + Clone, T>(
        &self,
        locator: &Locator<K>,
        key: &K,
        read: impl Fn(&NamespaceView) -> Option<T>,
        what: &dyn Display,
    ) -> Result<T, StoreError> {
        let mut found = None;
        let complete = self.located(locator, key, |_, view| {
            found = read(view);
            found.is_some()
        });
        match found {
            Some(value) => Ok(value),
            None if complete => Err(StoreError::NotFound(what.to_string())),
            None => Err(incomplete(what)),
        }
    }

    /// Everything `read` gathers from every confirmed candidate view of
    /// `key`; an incomplete walk is unavailable, never a shorter answer.
    pub(crate) fn gather<K: Ord + Hash + Clone, T>(
        &self,
        locator: &Locator<K>,
        key: &K,
        mut read: impl FnMut(NamespaceId, &NamespaceView, &mut Vec<T>),
        what: &dyn Display,
    ) -> Result<Vec<T>, StoreError> {
        let mut out = Vec::new();
        let complete = self.located(locator, key, |namespace, view| {
            read(namespace, view, &mut out);
            false
        });
        if complete {
            Ok(out)
        } else {
            Err(incomplete(what))
        }
    }

    /// The published view of the namespace holding the exclusive `key`, in
    /// the claim's incarnation. A claim in any state names its candidate;
    /// the caller decides from the row the view holds.
    pub(crate) fn claimed(&self, key: &ClaimKey) -> Option<Arc<NamespaceView>> {
        let holder = self.claims.observe(key).holder?;
        self.holder_view(holder)
    }

    /// A page of the keys of `locator` after `start`, in key order. `read`
    /// adds a key's items from each confirmed candidate view; under
    /// `Holders::First` the first view contributing ends the key, under
    /// `Holders::Every` every candidate is read. A key's items are never
    /// split across pages, so the cursor (the key) loses none; a single key
    /// with more than `limit` items is returned whole. At most
    /// `limit * LISTING_FACTOR` keys are examined; a page that did not fill
    /// within them continues after the last key examined. A key whose
    /// candidates cannot all be examined fails the listing as unavailable.
    pub(crate) fn listing<K: Ord + Hash + Clone + Display, T>(
        &self,
        locator: &Locator<K>,
        start: Option<&K>,
        limit: usize,
        holders: Holders,
        mut read: impl FnMut(&K, &NamespaceView, &mut Vec<T>),
        cursor: impl Fn(&K) -> String,
    ) -> Result<Page<T>, StoreError> {
        if limit == 0 {
            return Ok(Page::empty());
        }
        let budget = limit
            .saturating_mul(LISTING_FACTOR)
            .max(limit.saturating_add(1));
        let keys = locator.range(after(start), budget, CANDIDATE_PAGE);
        // Fewer keys than the budget means the projection has no more.
        let more_keys = keys.len() == budget;
        let mut items: Vec<T> = Vec::new();
        let mut last_kept: Option<K> = None;
        let mut last_examined = None;
        let mut full = false;
        for (key, candidates, more) in keys {
            let mut found = Vec::new();
            let mut stop = false;
            for candidate in &candidates {
                if let Some(view) = self.confirm(*candidate) {
                    let before = found.len();
                    read(&key, &view, &mut found);
                    if holders == Holders::First && found.len() > before {
                        stop = true;
                        break;
                    }
                }
            }
            if !stop && let Some(next) = more {
                let complete =
                    self.located_from(locator, &key, Bound::Excluded(next), |_, view| {
                        let before = found.len();
                        read(&key, view, &mut found);
                        holders == Holders::First && found.len() > before
                    });
                if !complete {
                    return Err(incomplete(&key));
                }
            }
            if found.is_empty() {
                last_examined = Some(key);
                continue;
            }
            // A key that would overfill a nonempty page starts the next one:
            // the page reports a continuation only once a further item is
            // known to exist, as `Page::from_oversized` does.
            if !items.is_empty() && items.len() + found.len() > limit {
                full = true;
                break;
            }
            items.append(&mut found);
            last_kept = Some(key.clone());
            last_examined = Some(key);
        }
        let next_after = if full {
            last_kept.as_ref().map(&cursor)
        } else if more_keys {
            last_examined.as_ref().map(&cursor)
        } else {
            None
        };
        Ok(Page { items, next_after })
    }
}

/// Which candidate views a listing reads per key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Holders {
    /// Exclusive or identical rows: the first confirmed view decides.
    First,
    /// Rows each namespace holds independently.
    Every,
}
