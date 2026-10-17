//! Published anchor-keyed identity records: successions, handles, device
//! and prekey bindings, locators, and revocation commitments, read from the
//! registry's completed projection (`projection`). Writes are
//! `EpochExecution` methods over `identity_write.rs` and
//! `identity_records.rs`, projected by settlement.

use std::collections::BTreeSet;

use kappa_store::canonical::from_canonical;
use kappa_store::error::StoreError;
use kappa_store::identity::{
    DeviceBinding, HandleRecord, LocatorRecord, PrekeyBinding, RevocationCommitment, Succession,
};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::ProtocolId;
use kappa_store::page::{Page, PageRequest};

use crate::PersistentStore;
use crate::projection::{Family, ProjectionRead};

/// The completed value of `key` in single-valued `family`: of the instances
/// holding one, the one completed last.
fn latest(
    read: &ProjectionRead,
    family: Family,
    key: &[u8],
) -> Result<Option<Vec<u8>>, StoreError> {
    Ok(read
        .get(family, key)?
        .into_iter()
        .max_by_key(|visible| visible.completion)
        .map(|visible| visible.value))
}

/// An optional completed anchor-keyed record.
fn anchor_record<T>(
    read: &ProjectionRead,
    family: Family,
    anchor: &Kappa,
    kind: &str,
) -> Result<Option<T>, StoreError>
where
    T: TryFrom<dcbor::CBOR, Error = dcbor::Error>,
{
    latest(read, family, &anchor.key_bytes())?
        .map(|value| {
            from_canonical(&value).map_err(|e| StoreError::Internal(format!("{kind} decode: {e}")))
        })
        .transpose()
}

/// The completed handle record at handle key `key`, checked to be stored
/// under its own key.
fn handle_at(read: &ProjectionRead, key: &str) -> Result<Option<HandleRecord>, StoreError> {
    let Some(value) = latest(read, Family::Handle, key.as_bytes())? else {
        return Ok(None);
    };
    let record: HandleRecord =
        from_canonical(&value).map_err(|e| StoreError::Internal(format!("handle decode: {e}")))?;
    if key != format!("{}:{}", record.protocol, record.handle) {
        return Err(StoreError::Internal("handle record key mismatch".into()));
    }
    Ok(Some(record))
}

impl PersistentStore {
    pub(crate) fn read_successor(&self, old_anchor: &Kappa) -> Result<Kappa, StoreError> {
        let record: Succession = anchor_record(
            &self.projection()?,
            Family::Succession,
            old_anchor,
            "succession",
        )?
        .ok_or_else(|| StoreError::NotFound(format!("successor of {old_anchor}")))?;
        if record.old_anchor != *old_anchor {
            return Err(StoreError::Internal(
                "succession index anchor mismatch".into(),
            ));
        }
        Ok(record.new_anchor)
    }

    pub(crate) fn read_succession_chain(
        &self,
        anchor: &Kappa,
    ) -> Result<Vec<Succession>, StoreError> {
        let read = self.projection()?;
        let mut chain = Vec::new();
        let mut current = anchor.clone();
        let mut visited = BTreeSet::new();
        visited.insert(current.key_bytes());
        while let Some(record) =
            anchor_record::<Succession>(&read, Family::Succession, &current, "succession")?
        {
            if record.old_anchor != current {
                return Err(StoreError::Internal(
                    "succession index anchor mismatch".into(),
                ));
            }
            if !visited.insert(record.new_anchor.key_bytes()) {
                return Err(StoreError::Rejected(
                    "succession chain contains a cycle".into(),
                ));
            }
            if chain.len() >= kappa_store::identity::SUCCESSION_CHAIN_MAX {
                return Err(StoreError::CapacityExceeded(
                    "succession chain exceeds maximum length".into(),
                ));
            }
            current = record.new_anchor.clone();
            chain.push(record);
        }
        Ok(chain)
    }

    /// The completed handle `protocol:handle`.
    pub(crate) fn read_handle(
        &self,
        protocol: &ProtocolId,
        handle: &str,
    ) -> Result<HandleRecord, StoreError> {
        handle_at(&self.projection()?, &format!("{protocol}:{handle}"))?
            .ok_or_else(|| StoreError::NotFound(format!("handle {protocol}:{handle}")))
    }

    /// Completed handles in key order after the page cursor, one key at a
    /// time: the work is the page, not the handle population.
    pub(crate) fn read_handles(
        &self,
        page: &PageRequest,
    ) -> Result<Page<HandleRecord>, StoreError> {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        let read = self.projection()?;
        let mut from = page.after.as_deref().map_or_else(Vec::new, |after| {
            let mut successor = after.as_bytes().to_vec();
            successor.push(0);
            successor
        });
        let mut records = Vec::with_capacity(page.limit.min(1024));
        while records.len() <= page.limit {
            let Some(key) = read.next_key(Family::Handle, &from)? else {
                break;
            };
            let text = String::from_utf8(key.clone())
                .map_err(|_| StoreError::Internal("handle key is not UTF-8".into()))?;
            if let Some(record) = handle_at(&read, &text)? {
                records.push(record);
            }
            from = key;
            from.push(0);
        }
        Ok(Page::from_oversized(records, page.limit, |record| {
            format!("{}:{}", record.protocol, record.handle)
        }))
    }

    /// Completed handles of `anchor`, in handle key order after the page
    /// cursor. The anchor index is a candidate: each member is confirmed by
    /// its completed handle record naming the anchor, and one that no
    /// longer does is passed over.
    pub(crate) fn read_handles_by_anchor(
        &self,
        anchor: &Kappa,
        page: &PageRequest,
    ) -> Result<Page<HandleRecord>, StoreError> {
        if page.limit == 0 {
            return Ok(Page::empty());
        }
        let read = self.projection()?;
        let mut keys = BTreeSet::new();
        for (member, _) in read.members(Family::HandleByAnchor, &anchor.key_bytes())? {
            let key = String::from_utf8(member)
                .map_err(|_| StoreError::Internal("handle key is not UTF-8".into()))?;
            if page
                .after
                .as_deref()
                .is_some_and(|after| key.as_str() <= after)
            {
                continue;
            }
            keys.insert(key);
        }
        let mut records = Vec::with_capacity(page.limit.min(1000));
        for key in keys {
            if let Some(record) = handle_at(&read, &key)?
                && record.anchor == *anchor
            {
                records.push(record);
                if records.len() > page.limit {
                    break;
                }
            }
        }
        Ok(Page::from_oversized(records, page.limit, |record| {
            format!("{}:{}", record.protocol, record.handle)
        }))
    }

    pub(crate) fn read_device_bindings(
        &self,
        anchor: &Kappa,
    ) -> Result<Vec<DeviceBinding>, StoreError> {
        Ok(anchor_record(
            &self.projection()?,
            Family::DeviceBinding,
            anchor,
            "device binding",
        )?
        .unwrap_or_default())
    }

    pub(crate) fn read_prekey_bindings(
        &self,
        anchor: &Kappa,
    ) -> Result<Vec<PrekeyBinding>, StoreError> {
        Ok(anchor_record(
            &self.projection()?,
            Family::PrekeyBinding,
            anchor,
            "prekey binding",
        )?
        .unwrap_or_default())
    }

    pub(crate) fn read_locator(&self, anchor: &Kappa) -> Result<Option<LocatorRecord>, StoreError> {
        anchor_record(
            &self.projection()?,
            Family::LocatorRecord,
            anchor,
            "locator",
        )
    }

    pub(crate) fn read_revocation_commitment(
        &self,
        anchor: &Kappa,
    ) -> Result<Option<RevocationCommitment>, StoreError> {
        anchor_record(
            &self.projection()?,
            Family::RevocationCommitment,
            anchor,
            "revocation commitment",
        )
    }
}
