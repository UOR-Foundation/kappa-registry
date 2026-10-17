use std::ops::Bound::{Excluded, Included, Unbounded};

use kappa_store::canonical::from_canonical;
use kappa_store::error::StoreError;
use kappa_store::namespace::NamespaceRef;
use kappa_store::page::{Page, PageRequest};
use kappa_store::tag::TagEntry;
use kappa_store::traits::tag::TagStore;

use crate::PersistentStore;
use crate::tables::TAGS;

pub(crate) fn tag_key(ns: &NamespaceRef, name: &str) -> Vec<u8> {
    let uuid = ns.id();
    let mut k = Vec::with_capacity(16 + name.len());
    k.extend_from_slice(uuid);
    k.extend_from_slice(name.as_bytes());
    k
}

/// The AEAD context of the `TAGS` row at `key`.
pub(crate) fn tag_context(key: &[u8]) -> String {
    crate::encrypted::bound("tag", key)
}

fn ns_prefix(ns: &NamespaceRef) -> Vec<u8> {
    ns.id().to_vec()
}

fn name_from_key(key: &[u8]) -> Result<String, StoreError> {
    if key.len() < 16 {
        return Err(StoreError::Internal(
            "tag key shorter than UUID prefix".into(),
        ));
    }
    String::from_utf8(key[16..].to_vec())
        .map_err(|e| StoreError::Internal(format!("tag name not utf8: {e}")))
}

impl TagStore for PersistentStore {
    fn tag_cursor(
        &self,
        ns: &NamespaceRef,
        prefix: Option<&str>,
    ) -> Result<Box<dyn kappa_cursor::KappaCursor + '_>, StoreError> {
        let start = tag_key(ns, prefix.unwrap_or(""));
        let end = Self::prefix_successor(&start);
        let snapshot = self.namespace_snapshot(ns)?;
        let table = snapshot.table(TAGS)?;
        let upper = end
            .as_deref()
            .map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded);
        let mut keys = Vec::new();
        for item in table
            .range::<&[u8]>((std::ops::Bound::Included(start.as_slice()), upper))
            .map_err(crate::error::redb)?
        {
            let (key, _) = item.map_err(crate::error::redb)?;
            keys.push(name_from_key(key.value())?.into_bytes());
        }
        Ok(Box::new(kappa_cursor::SliceCursor::from_sorted(keys)))
    }

    fn tag_get(&self, ns: &NamespaceRef, name: &str) -> Result<TagEntry, StoreError> {
        let snapshot = self.namespace_snapshot(ns)?;
        let table = snapshot.table(TAGS)?;
        kappa_store::tag_resolution::resolve_tag(name, |target| {
            let ref_key = tag_key(ns, target);
            let ref_guard = table
                .get(ref_key.as_slice())
                .map_err(crate::error::redb)?
                .ok_or_else(|| {
                    StoreError::NotFound(format!("{ns}/{name} (broken symref to {target})"))
                })?;
            let ref_decrypted = self.decrypt_bytes(&tag_context(&ref_key), ref_guard.value())?;
            Ok(from_canonical(&ref_decrypted)?)
        })
    }

    fn tag_get_raw(&self, ns: &NamespaceRef, name: &str) -> Result<TagEntry, StoreError> {
        let key = tag_key(ns, name);
        let snapshot = self.namespace_snapshot(ns)?;
        let table = snapshot.table(TAGS)?;
        let guard = table
            .get(key.as_slice())
            .map_err(crate::error::redb)?
            .ok_or_else(|| StoreError::NotFound(format!("{ns}/{name}")))?;
        let decrypted = self.decrypt_bytes(&tag_context(&key), guard.value())?;
        Ok(from_canonical(&decrypted)?)
    }

    // Tag writes are `EpochExecution::tag_put`, `tag_delete`, and
    // `tag_batch_update`, which call `tag_put_in_txn` / `tag_delete_in_txn`
    // inside the execution's writer and publish with its epoch.

    fn tag_list(
        &self,
        ns: &NamespaceRef,
        prefix: Option<&str>,
        page: &PageRequest,
    ) -> Result<Page<TagEntry>, StoreError> {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        let ns_pfx = ns_prefix(ns);
        let scan_start = prefix.map_or_else(|| ns_pfx.clone(), |prefix| tag_key(ns, prefix));
        let scan_end = Self::prefix_successor(&scan_start);

        let cursor_key = page.after.as_deref().map(|after| tag_key(ns, after));
        let lower = match cursor_key.as_ref() {
            Some(cursor) if cursor >= &scan_start => Excluded(cursor.as_slice()),
            _ => Included(scan_start.as_slice()),
        };
        if scan_end
            .as_ref()
            .is_some_and(|end| cursor_key.as_ref().is_some_and(|cursor| cursor >= end))
        {
            return Ok(Page::empty());
        }
        let upper = scan_end.as_deref().map_or(Unbounded, Excluded);
        let snapshot = self.namespace_snapshot(ns)?;
        let table = snapshot.table(TAGS)?;
        let mut entries = Vec::new();
        let iter_result = table.range::<&[u8]>((lower, upper));
        let include_internal = prefix.is_some_and(|prefix| prefix.starts_with('_'));

        for item in iter_result.map_err(crate::error::redb)? {
            let (k, v) = item.map_err(crate::error::redb)?;
            let raw_key = k.value();
            if !raw_key.starts_with(&ns_pfx) {
                break;
            }
            let name = name_from_key(raw_key)?;

            if !include_internal && name.starts_with('_') {
                continue;
            }

            let decrypted = self.decrypt_bytes(&tag_context(raw_key), v.value())?;
            let entry: TagEntry = from_canonical(&decrypted)?;
            entries.push(entry);

            if entries.len() > page.limit {
                break;
            }
        }

        Ok(Page::from_oversized(entries, page.limit, |entry| {
            entry.name.clone()
        }))
    }
}
