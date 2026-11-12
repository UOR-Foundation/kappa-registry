//! Handle locators identify candidates; committed namespace rows decide.
//! Every locator read runs on the one meter of the operation that asked.

use std::collections::BTreeSet;

use kappa_store::identity::HandleRecord;
use kappa_store::namespace::ProtocolId;
use kappa_store::work::{Dimension, Meter};
use kappa_store::{Kappa, Page, PageRequest, StoreError};
use redb::ReadableDatabase;

use crate::namespace_snapshot::InstanceAdmission;
use crate::projection::Family;
use crate::storage_instance::StorageInstance;
use crate::unsettled_index::DiscoveryKey;
use crate::{PersistentStore, tables};

impl PersistentStore {
    fn current_handle(
        &self,
        key: &str,
        work: &mut dyn Meter,
    ) -> Result<Option<HandleRecord>, StoreError> {
        if let Some(error) = self.discovery_coverage().unavailable(key) {
            return Err(error);
        }
        let owners = |work: &mut dyn Meter| -> Result<_, StoreError> {
            Ok(self
                .projection()?
                .get(Family::Handle, key.as_bytes(), work)?
                .into_iter()
                .map(|visible| visible.instance)
                .collect::<Vec<_>>())
        };
        // Each candidate inserted is charged as one set node of its
        // instance before it is inserted.
        let node = size_of::<StorageInstance>() as u64;
        let mut candidates = BTreeSet::new();
        let mut insert = |found: Vec<StorageInstance>, work: &mut dyn Meter| {
            for instance in found {
                work.charge(Dimension::BytesAllocated, node)?;
                candidates.insert(instance);
            }
            Ok::<(), StoreError>(())
        };
        insert(owners(work)?, work)?;
        work.charge(Dimension::BytesAllocated, key.len() as u64)?;
        insert(
            self.unsettled_candidates(&DiscoveryKey::Handle(key.to_owned()), work)?,
            work,
        )?;
        insert(owners(work)?, work)?;
        let mut found = None;
        for instance in candidates {
            // The storage handle the admission opens, charged before it is
            // opened (`store_access::probe`).
            work.charge(Dimension::Handles, 1)?;
            let snapshot = match self.admit_instance(&instance) {
                InstanceAdmission::Held { snapshot, .. } => snapshot,
                InstanceAdmission::Released(_) => continue,
                InstanceAdmission::CapacityDeferred { limit } => {
                    return Err(StoreError::Unavailable(format!(
                        "handle {key}: candidate {instance} not read; {limit} namespace activities are active"
                    )));
                }
                InstanceAdmission::Unexplained(error) | InstanceAdmission::Unreadable(error) => {
                    return Err(StoreError::Unavailable(format!("handle {key}: {error}")));
                }
            };
            let table = snapshot.table(tables::ID_HANDLES)?;
            work.charge(Dimension::Entries, 1)?;
            let Some(value) = table.get(key).map_err(crate::error::redb)? else {
                continue;
            };
            let record = crate::identity_records::handle_row(value.value(), work)?;
            work.charge(Dimension::BytesAllocated, key.len() as u64)?;
            if crate::identity_write::handle_key(&record.protocol, &record.handle) != key {
                return Err(StoreError::Internal("handle record key mismatch".into()));
            }
            if found.is_some() {
                return Err(StoreError::Conflict(format!(
                    "handle {key} has multiple committed owners"
                )));
            }
            found = Some(record);
        }
        Ok(found)
    }

    pub(crate) fn read_handle(
        &self,
        protocol: &ProtocolId,
        handle: &str,
        work: &mut dyn Meter,
    ) -> Result<HandleRecord, StoreError> {
        let key = crate::identity_write::handle_key(protocol, handle);
        self.current_handle(&key, work)?
            .ok_or_else(|| StoreError::NotFound(format!("handle {key}")))
    }

    /// Merge two ordered key sources, confirming each in native storage.
    /// No list of the handle population is allocated.
    pub(crate) fn read_handles(
        &self,
        page: &PageRequest,
        work: &mut dyn Meter,
    ) -> Result<Page<HandleRecord>, StoreError> {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        if let Some(error) = self.discovery_coverage().unavailable("handle listing") {
            return Err(error);
        }
        let mut after = page.after.clone();
        let mut records = Vec::with_capacity(page.limit.min(1024));
        while records.len() <= page.limit {
            let mut from = after
                .as_ref()
                .map_or_else(Vec::new, |key| key.as_bytes().to_vec());
            if after.is_some() {
                from.push(0);
            }
            let settled = |work: &mut dyn Meter| -> Result<Option<String>, StoreError> {
                self.projection()?
                    .next_key(Family::Handle, &from, work)?
                    .map(|key| {
                        String::from_utf8(key)
                            .map_err(|_| StoreError::Internal("handle key is not UTF-8".into()))
                    })
                    .transpose()
            };
            let first = settled(work)?;
            let pending = self.unsettled_index.next_handle(after.as_deref());
            let last = settled(work)?;
            let Some(key) = first.into_iter().chain(pending).chain(last).min() else {
                break;
            };
            if let Some(record) = self.current_handle(&key, work)? {
                records.push(record);
            }
            after = Some(key);
        }
        Ok(Page::from_oversized(records, page.limit, |record| {
            crate::identity_write::handle_key(&record.protocol, &record.handle)
        }))
    }

    pub(crate) fn read_handles_by_anchor(
        &self,
        anchor: &Kappa,
        page: &PageRequest,
        work: &mut dyn Meter,
    ) -> Result<Page<HandleRecord>, StoreError> {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        let mut keys = BTreeSet::new();
        let settled = |work: &mut dyn Meter| -> Result<Vec<String>, StoreError> {
            self.projection()?
                .members(Family::HandleByAnchor, &anchor.key_bytes(), work)?
                .into_iter()
                .map(|(key, _)| {
                    String::from_utf8(key)
                        .map_err(|_| StoreError::Internal("handle key is not UTF-8".into()))
                })
                .collect()
        };
        keys.extend(settled(work)?);
        // Keep the lookahead item from each source until the merged page
        // decides whether it has a continuation.
        let candidate_page = PageRequest::new(page.limit.saturating_add(1), page.after.clone());
        let pages = self.every_unsettled_holder(
            &DiscoveryKey::HandlesBy(anchor.clone()),
            "handles by anchor",
            work,
            |view: &crate::content_read::ReadView, work: &mut dyn Meter| {
                let txn = view.db.begin_read().map_err(crate::error::redb)?;
                let index = txn
                    .open_multimap_table(tables::ID_HANDLE_ANCHOR_IDX)
                    .map_err(crate::error::redb)?;
                let table = txn
                    .open_table(tables::ID_HANDLES)
                    .map_err(crate::error::redb)?;
                crate::identity_records::handles_by_anchor_from(
                    &index,
                    &table,
                    anchor,
                    &candidate_page,
                    work,
                )
            },
        )?;
        for page in pages {
            keys.extend(
                page.items.into_iter().map(|record| {
                    crate::identity_write::handle_key(&record.protocol, &record.handle)
                }),
            );
        }
        keys.extend(settled(work)?);
        let mut records = Vec::with_capacity(page.limit.min(1024));
        for key in keys {
            if page.after.as_ref().is_some_and(|after| key <= *after) {
                continue;
            }
            if let Some(record) = self.current_handle(&key, work)?
                && record.anchor == *anchor
            {
                records.push(record);
                if records.len() > page.limit {
                    break;
                }
            }
        }
        Ok(Page::from_oversized(records, page.limit, |record| {
            crate::identity_write::handle_key(&record.protocol, &record.handle)
        }))
    }
}
