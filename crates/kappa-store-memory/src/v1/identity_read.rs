//! Handle reads, shared by the store and by executions.
//!
//! A handle is an exclusive claim: its row is read from the view of the
//! namespace holding the claim. An execution reads its own candidate when
//! its namespace holds the claim, so it sees its private writes, and every
//! other holder's published view otherwise. Handles by anchor merge every
//! namespace the anchor projection names; an execution's own namespace is
//! read from its candidate in place of its published view.

use std::collections::BTreeMap;
use std::ops::Bound::{Excluded, Unbounded};

use kappa_types::error::StoreError;
use kappa_types::identity::HandleRecord;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::ProtocolId;
use kappa_types::page::{Page, PageRequest};

use super::InMemoryStore;
use super::claims::ClaimKey;
use super::execution::ReadCx;
use super::identity_write::handle_key;
use super::locate::incomplete;
use super::view::{NamespaceId, NamespaceView};

/// Add to `merged` up to `take` handles of `anchor` that `view` holds
/// after `after`, keeping only the `take` smallest keys overall.
fn merge_anchor_handles(
    view: &NamespaceView,
    anchor: &Kappa,
    after: Option<&str>,
    take: usize,
    merged: &mut BTreeMap<String, HandleRecord>,
) {
    let Some(keys) = view.identity.handle_anchors.get(anchor) else {
        return;
    };
    let lower = after.map_or(Unbounded, Excluded);
    for key in keys.range::<_, str>((lower, Unbounded)).take(take) {
        if let Some(record) = view.identity.handles.get(key)
            && record.anchor == *anchor
        {
            merged.insert(key.clone(), record.clone());
        }
    }
    while merged.len() > take {
        merged.pop_last();
    }
}

impl InMemoryStore {
    /// The published handle record, read from the claim holder's view.
    pub(crate) fn handle_published(
        &self,
        protocol: &ProtocolId,
        handle: &str,
    ) -> Option<HandleRecord> {
        let key = handle_key(protocol, handle);
        self.claimed(&ClaimKey::Handle(key.clone()))?
            .identity
            .handles
            .get(&key)
            .cloned()
    }

    /// A page of the handles of `anchor` across every namespace holding
    /// one, in handle key order. `own` substitutes an execution's
    /// candidate for its namespace's published view.
    pub(crate) fn handles_by_anchor(
        &self,
        anchor: &Kappa,
        page: &PageRequest,
        own: Option<(NamespaceId, &NamespaceView)>,
    ) -> Result<Page<HandleRecord>, StoreError> {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        let after = page.after.as_deref();
        let take = page.limit.saturating_add(1);
        let mut merged = BTreeMap::new();
        let complete = self.located(
            &self.projections.handle_anchors,
            anchor,
            |namespace, view| {
                if own.is_none_or(|(own, _)| own != namespace) {
                    merge_anchor_handles(view, anchor, after, take, &mut merged);
                }
                false
            },
        );
        if !complete {
            return Err(incomplete(&format_args!("handles of {anchor}")));
        }
        if let Some((_, candidate)) = own {
            merge_anchor_handles(candidate, anchor, after, take, &mut merged);
        }
        Ok(Page::from_oversized(
            merged.into_values().collect(),
            page.limit,
            |record| handle_key(&record.protocol, &record.handle),
        ))
    }
}

impl ReadCx<'_> {
    /// The handle record this execution observes: its own candidate's when
    /// its namespace holds the claim, the holder's published row otherwise.
    pub fn handle(&self, protocol: &ProtocolId, handle: &str) -> Option<HandleRecord> {
        let key = handle_key(protocol, handle);
        let holder = self
            .store
            .claims
            .observe(&ClaimKey::Handle(key.clone()))
            .holder?;
        if holder == self.holder {
            return self.view.identity.handles.get(&key).cloned();
        }
        self.store
            .holder_view(holder)?
            .identity
            .handles
            .get(&key)
            .cloned()
    }

    pub fn handles_by_anchor(
        &self,
        anchor: &Kappa,
        page: &PageRequest,
    ) -> Result<Page<HandleRecord>, StoreError> {
        self.store
            .handles_by_anchor(anchor, page, Some((self.holder.namespace, self.view)))
    }
}
