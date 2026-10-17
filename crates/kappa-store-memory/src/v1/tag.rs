//! Tags of a namespace view: writes against the candidate, reads against
//! a published or candidate view. The digest, count, references and ledger
//! move together because they share one view.

use std::ops::Bound::{Excluded, Included, Unbounded};

use kappa_store::traits::tag::TagStore;
use kappa_types::epoch::MutationOp;
use kappa_types::error::StoreError;
use kappa_types::namespace::NamespaceRef;
use kappa_types::page::{Page, PageRequest};
use kappa_types::tag::{TagEntry, TagUpdate};

use super::InMemoryStore;
use super::execution::WriteCx;
use super::view::NamespaceView;

impl WriteCx<'_> {
    pub fn tag_put(&mut self, name: &str, update: &TagUpdate) -> Result<TagEntry, StoreError> {
        let old = self.view.tags.get(name).cloned();
        let entry = kappa_store::tag_update::prepare_tag_update(
            self.ns,
            name,
            old.as_ref(),
            update,
            self.now,
        )?;
        self.apply_tag(old.as_ref(), entry.clone())?;
        Ok(entry)
    }

    pub fn tag_delete(&mut self, name: &str) -> Result<TagEntry, StoreError> {
        let removed = self
            .view
            .tags
            .remove(name)
            .ok_or_else(|| StoreError::NotFound(format!("{}/{name}", self.ns)))?;
        self.view.digest.remove_tag(name, &removed.kappa);
        if removed.symref.is_none() && !self.view.release(&removed.kappa) {
            return Err(StoreError::Internal(format!(
                "reference index lacked the tag {name} being deleted"
            )));
        }
        self.record(
            MutationOp::TagDelete,
            removed.kappa.clone(),
            Some(name.to_string()),
        );
        Ok(removed)
    }

    /// Every precondition is checked against the pre-batch state before any
    /// member is applied; a rejected member leaves the candidate to be
    /// discarded.
    pub fn tag_batch(
        &mut self,
        updates: &[(String, TagUpdate)],
    ) -> Result<Vec<TagEntry>, StoreError> {
        kappa_store::tag_update::validate_tag_batch(updates)?;
        let prepared = updates
            .iter()
            .map(|(name, update)| {
                let old = self.view.tags.get(name.as_str()).cloned();
                kappa_store::tag_update::prepare_tag_update(
                    self.ns,
                    name,
                    old.as_ref(),
                    update,
                    self.now,
                )
                .map(|entry| (old, entry))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut results = Vec::with_capacity(prepared.len());
        for (old, entry) in prepared {
            self.apply_tag(old.as_ref(), entry.clone())?;
            results.push(entry);
        }
        Ok(results)
    }

    fn apply_tag(&mut self, old: Option<&TagEntry>, entry: TagEntry) -> Result<(), StoreError> {
        if let Some(old) = old {
            self.view.digest.remove_tag(&entry.name, &old.kappa);
        }
        self.view.digest.insert_tag(&entry.name, &entry.kappa);
        // A symbolic tag names a tag, not content, so only direct targets
        // are referenced, and a direct tag reset to the same target changes
        // nothing.
        let old_target = old
            .filter(|tag| tag.symref.is_none())
            .map(|tag| tag.kappa.clone());
        let new_target = entry.symref.is_none().then(|| entry.kappa.clone());
        if old_target != new_target {
            if let Some(previous) = &old_target
                && !self.view.release(previous)
            {
                return Err(StoreError::Internal(format!(
                    "reference index lacked the tag {} being moved",
                    entry.name
                )));
            }
            if let Some(next) = &new_target {
                self.view.reference(next);
            }
        }
        self.record(
            MutationOp::TagSet,
            entry.kappa.clone(),
            Some(entry.name.clone()),
        );
        self.view.tags.insert(entry.name.clone(), entry);
        Ok(())
    }
}

pub fn tag_get_raw_in(
    view: &NamespaceView,
    ns: &NamespaceRef,
    name: &str,
) -> Result<TagEntry, StoreError> {
    view.tags
        .get(name)
        .cloned()
        .ok_or_else(|| StoreError::NotFound(format!("{ns}/{name}")))
}

pub fn tag_get_in(
    view: &NamespaceView,
    ns: &NamespaceRef,
    name: &str,
) -> Result<TagEntry, StoreError> {
    kappa_store::tag_resolution::resolve_tag(name, |target| tag_get_raw_in(view, ns, target))
}

impl TagStore for InMemoryStore {
    fn tag_cursor(
        &self,
        ns: &NamespaceRef,
        prefix: Option<&str>,
    ) -> Result<Box<dyn kappa_cursor::KappaCursor + '_>, StoreError> {
        let view = self.view(ns.id());
        let keys = view
            .tags
            .range::<_, str>((Included(prefix.unwrap_or("")), Unbounded))
            .take_while(|(name, _)| prefix.is_none_or(|prefix| name.starts_with(prefix)))
            .map(|(name, _)| name.as_bytes().to_vec())
            .collect();
        Ok(Box::new(kappa_cursor::SliceCursor::from_sorted(keys)))
    }

    fn tag_get(&self, ns: &NamespaceRef, name: &str) -> Result<TagEntry, StoreError> {
        tag_get_in(&self.view(ns.id()), ns, name)
    }

    fn tag_get_raw(&self, ns: &NamespaceRef, name: &str) -> Result<TagEntry, StoreError> {
        tag_get_raw_in(&self.view(ns.id()), ns, name)
    }

    fn tag_list(
        &self,
        ns: &NamespaceRef,
        prefix: Option<&str>,
        page: &PageRequest,
    ) -> Result<Page<TagEntry>, StoreError> {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        let view = self.view(ns.id());
        let lower = match (prefix, page.after.as_deref()) {
            (Some(prefix), Some(after)) if after < prefix => Included(prefix),
            (_, Some(after)) => Excluded(after),
            (Some(prefix), None) => Included(prefix),
            (None, None) => Unbounded,
        };
        let include_internal = prefix.is_some_and(|prefix| prefix.starts_with('_'));
        let entries = view
            .tags
            .range::<_, str>((lower, Unbounded))
            .take_while(|(name, _)| prefix.is_none_or(|prefix| name.starts_with(prefix)))
            .filter(|(name, _)| include_internal || !name.starts_with('_'))
            .take(page.limit.saturating_add(1))
            .map(|(_, entry)| entry.clone())
            .collect();
        Ok(Page::from_oversized(entries, page.limit, |entry| {
            entry.name.clone()
        }))
    }
}
