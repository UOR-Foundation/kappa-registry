//! The directory: alias resolution through claims confirmed against the
//! holder's view, records from each namespace's own view, and listing
//! through the name projection.

use std::ops::Bound::{Excluded, Included, Unbounded};

use kappa_store::{NamespaceInfo, NamespaceStore};
use kappa_types::page::{NamespaceFilter, Page, PageRequest};
use kappa_types::{NamespaceRef, ProtocolId, StoreError};

use super::InMemoryStore;
use super::claims::ClaimKey;
use super::locate::Holders;
use super::namespace_write::{namespace_get_meta_in, namespace_info_in};

fn matches(record: &NamespaceInfo, filter: &NamespaceFilter) -> bool {
    let tombstone = filter
        .tombstoned
        .map_or(!record.tombstoned, |wanted| record.tombstoned == wanted);
    tombstone
        && filter
            .protocol
            .as_ref()
            .is_none_or(|protocol| record.protocol.as_ref() == Some(protocol))
        && filter
            .owner_anchor
            .as_ref()
            .is_none_or(|owner| record.owner_anchor.as_ref() == Some(owner))
        && filter
            .created_after_ms
            .is_none_or(|timestamp| record.created_at_ms > timestamp)
        && filter
            .last_epoch_after
            .is_none_or(|epoch| record.last_epoch > epoch)
}

impl InMemoryStore {
    /// The namespace holding the alias `path` in `protocol`, confirmed by
    /// its published view.
    fn resolve(&self, path: &str, protocol: Option<&ProtocolId>) -> Option<NamespaceRef> {
        let scope = protocol
            .map(ProtocolId::as_str)
            .unwrap_or_default()
            .to_owned();
        let key = ClaimKey::Alias {
            name: path.to_owned(),
            protocol: scope.clone(),
        };
        let holder = self.claims.observe(&key).holder?;
        let view = self.holder_view(holder)?;
        view.aliases
            .contains(&(path.to_owned(), scope))
            .then(|| NamespaceRef::resolved(holder.namespace, path.to_string(), protocol.cloned()))
    }
}

impl NamespaceStore for InMemoryStore {
    fn namespace_resolve(
        &self,
        path: &str,
        protocol: Option<&ProtocolId>,
    ) -> Result<NamespaceRef, StoreError> {
        self.resolve(path, protocol)
            .ok_or_else(|| StoreError::NotFound(format!("namespace: {path}")))
    }

    fn namespace_exists(
        &self,
        path: &str,
        protocol: Option<&ProtocolId>,
    ) -> Result<bool, StoreError> {
        Ok(self.resolve(path, protocol).is_some())
    }

    fn namespace_info(&self, ns: &NamespaceRef) -> Result<NamespaceInfo, StoreError> {
        namespace_info_in(&self.view(ns.id()), ns)
    }

    fn namespace_list(
        &self,
        filter: &NamespaceFilter,
        page: &PageRequest,
    ) -> Result<Page<NamespaceInfo>, StoreError> {
        // Records of one name in different protocol scopes share a key and
        // are never split across pages.
        self.listing(
            &self.projections.names,
            page.after.as_ref(),
            page.limit,
            Holders::Every,
            |name, view, out| {
                if let Some(record) = &view.record
                    && record.name == *name
                    && matches(record, filter)
                {
                    out.push(record.clone());
                }
            },
            Clone::clone,
        )
    }

    fn namespace_get_meta(&self, ns: &NamespaceRef, key: &str) -> Result<Vec<u8>, StoreError> {
        namespace_get_meta_in(&self.view(ns.id()), ns, key)
    }

    fn namespace_list_meta_keys(
        &self,
        ns: &NamespaceRef,
        prefix: &str,
        page: &PageRequest,
    ) -> Result<Page<String>, StoreError> {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        let view = self.view(ns.id());
        let lower = match page.after.as_deref() {
            Some(after) if after >= prefix => Excluded(after),
            _ => Included(prefix),
        };
        let keys = view
            .meta
            .range::<_, str>((lower, Unbounded))
            .take_while(|(key, _)| key.starts_with(prefix))
            .take(page.limit.saturating_add(1))
            .map(|(key, _)| key.clone())
            .collect();
        Ok(Page::from_oversized(keys, page.limit, Clone::clone))
    }
}
