use std::ops::Bound::{Excluded, Included, Unbounded};

use kappa_store::canonical::from_canonical;
use kappa_store::error::StoreError;
use kappa_store::namespace::NamespaceRef;
use kappa_store::page::{Page, PageRequest};
use kappa_store::tag::TagEntry;
use kappa_store::traits::tag::TagStore;
use kappa_store::work::{Dimension, Meter, reserve_charged};
use redb::ReadableTable;

use crate::PersistentStore;
use crate::tables::TAGS;

/// Table-encryption context label of `TAGS` rows.
const TAG_CONTEXT: &str = "tag";

/// Bytes of a `TAGS` key before the tag name: the namespace identity.
const TAG_KEY_PREFIX: u64 = 16;

pub(crate) fn tag_key(ns: &NamespaceRef, name: &str) -> Vec<u8> {
    let uuid = ns.id();
    let mut k = Vec::with_capacity(16 + name.len());
    k.extend_from_slice(uuid);
    k.extend_from_slice(name.as_bytes());
    k
}

/// The AEAD context of the `TAGS` row at `key`.
pub(crate) fn tag_context(key: &[u8]) -> String {
    crate::encrypted::bound(TAG_CONTEXT, key)
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

/// What decoding the `TAGS` row `value` at `key` costs: the row read, its
/// context built, its plaintext and its decoded entry allocated, and its
/// plaintext decoded.
fn row_charges(key: &[u8], value: &[u8]) -> [(Dimension, u64); 5] {
    let row = value.len() as u64;
    [
        (Dimension::BytesRead, row),
        (
            Dimension::BytesAllocated,
            crate::encrypted::bound_allocation(TAG_CONTEXT, key.len()),
        ),
        (Dimension::BytesAllocated, row),
        (Dimension::BytesDecoded, row),
        (Dimension::BytesAllocated, row),
    ]
}

/// The entry the `TAGS` row `value` at `key` holds, its decoding charged to
/// `work` first.
fn decode_row(
    store: &PersistentStore,
    key: &[u8],
    value: &[u8],
    work: &mut dyn Meter,
) -> Result<TagEntry, StoreError> {
    work.charge_all(&row_charges(key, value))?;
    let plaintext = store.decrypt_bytes(&tag_context(key), value)?;
    Ok(from_canonical(&plaintext)?)
}

/// The tag `name` of `ns` as `table` holds it, on `work`: its key built and
/// looked up, then its row decoded, each charged before it runs. The one
/// point read of a tag row, whatever transaction holds the table.
pub(crate) fn tag_row(
    store: &PersistentStore,
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    ns: &NamespaceRef,
    name: &str,
    work: &mut dyn Meter,
) -> Result<Option<TagEntry>, StoreError> {
    work.charge_all(&[
        (
            Dimension::BytesAllocated,
            TAG_KEY_PREFIX.saturating_add(name.len() as u64),
        ),
        (Dimension::Entries, 1),
    ])?;
    let key = tag_key(ns, name);
    let Some(guard) = table.get(key.as_slice()).map_err(crate::error::redb)? else {
        return Ok(None);
    };
    decode_row(store, &key, guard.value(), work).map(Some)
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

    /// The tag `name` of `ns` with its symbolic references resolved, every
    /// row read on one read operation's meter.
    fn tag_get(&self, ns: &NamespaceRef, name: &str) -> Result<TagEntry, StoreError> {
        let mut work = self.read_meter();
        let snapshot = self.namespace_snapshot(ns)?;
        let table = snapshot.table(TAGS)?;
        kappa_store::tag_resolution::resolve_tag(name, |target| {
            tag_row(self, &table, ns, target, &mut work)?.ok_or_else(|| {
                StoreError::NotFound(format!("{ns}/{name} (broken symref to {target})"))
            })
        })
    }

    fn tag_get_raw(&self, ns: &NamespaceRef, name: &str) -> Result<TagEntry, StoreError> {
        let snapshot = self.namespace_snapshot(ns)?;
        let table = snapshot.table(TAGS)?;
        tag_row(self, &table, ns, name, &mut self.read_meter())?
            .ok_or_else(|| StoreError::NotFound(format!("{ns}/{name}")))
    }

    // Tag writes are `EpochExecution::tag_put`, `tag_delete`, and
    // `tag_batch_update`, which call `tag_put_in_txn` / `tag_delete_in_txn`
    // inside the execution's writer and publish with its epoch.

    /// One page of the tags of `ns` on one read operation's meter: each row
    /// examined is charged before the range yields it, its name and its
    /// decoding before they run, and the page's growth before it grows.
    fn tag_list(
        &self,
        ns: &NamespaceRef,
        prefix: Option<&str>,
        page: &PageRequest,
    ) -> Result<Page<TagEntry>, StoreError> {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        let mut work = self.read_meter();
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
        let mut range = table
            .range::<&[u8]>((lower, upper))
            .map_err(crate::error::redb)?;
        let include_internal = prefix.is_some_and(|prefix| prefix.starts_with('_'));

        loop {
            work.charge(Dimension::Entries, 1)?;
            let Some(item) = range.next() else {
                break;
            };
            let (k, v) = item.map_err(crate::error::redb)?;
            let raw_key = k.value();
            if !raw_key.starts_with(&ns_pfx) {
                break;
            }
            work.charge(
                Dimension::BytesAllocated,
                (raw_key.len() as u64).saturating_sub(TAG_KEY_PREFIX),
            )?;
            let name = name_from_key(raw_key)?;

            if !include_internal && name.starts_with('_') {
                continue;
            }

            reserve_charged(&mut work, &mut entries)?;
            entries.push(decode_row(self, raw_key, v.value(), &mut work)?);

            if entries.len() > page.limit {
                break;
            }
        }

        Ok(Page::from_oversized(entries, page.limit, |entry| {
            entry.name.clone()
        }))
    }
}
