//! Published anchor-keyed identity records: successions, handles, device
//! and prekey bindings, locators, and revocation commitments, read from the
//! registry's completed projection (`projection`). Writes are
//! `EpochExecution` methods over `identity_write.rs` and
//! `identity_records.rs`, projected by settlement. Every read runs on the
//! one meter of the operation that asked for it, nested reads included,
//! and is answered completely or refused.

use redb::ReadableDatabase;

use kappa_store::canonical::from_canonical;
use kappa_store::error::StoreError;
use kappa_store::identity::{
    DeviceBinding, LocatorRecord, PrekeyBinding, RevocationCommitment, Succession,
};
use kappa_store::kappa::Kappa;
use kappa_store::work::{Dimension, Meter};

#[path = "identity_handle_read.rs"]
mod handles;

use crate::PersistentStore;
use crate::projection::{Family, ProjectionRead};

/// The completed value of `key` in single-valued `family`, read on `work`:
/// of the instances holding one, the one completed last.
fn latest(
    read: &ProjectionRead,
    family: Family,
    key: &[u8],
    work: &mut dyn Meter,
) -> Result<Option<Vec<u8>>, StoreError> {
    Ok(read
        .get(family, key, work)?
        .into_iter()
        .max_by_key(|visible| visible.completion)
        .map(|visible| visible.value))
}

/// An optional completed anchor-keyed record, read on `work`.
fn anchor_record<T>(
    read: &ProjectionRead,
    family: Family,
    anchor: &Kappa,
    kind: &str,
    work: &mut dyn Meter,
) -> Result<Option<T>, StoreError>
where
    T: TryFrom<dcbor::CBOR, Error = dcbor::Error>,
{
    latest(read, family, &anchor.key_bytes(), work)?
        .map(|value| {
            from_canonical(&value).map_err(|e| StoreError::Internal(format!("{kind} decode: {e}")))
        })
        .transpose()
}

impl PersistentStore {
    /// Successions are immutable. Read the completed projection on both
    /// sides of unsettled discovery so settlement cannot hide a committed
    /// link while handing its registration to the projection.
    fn successor_record(
        &self,
        anchor: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Option<Succession>, StoreError> {
        let mut found: Option<Succession> = None;
        let mut accept = |record: Succession| -> Result<(), StoreError> {
            if record.old_anchor != *anchor {
                return Err(StoreError::Internal(
                    "succession index anchor mismatch".into(),
                ));
            }
            if let Some(previous) = &found {
                if kappa_store::canonical::canonical_bytes(previous)
                    != kappa_store::canonical::canonical_bytes(&record)
                {
                    return Err(StoreError::Conflict(format!(
                        "conflicting committed successions for {anchor}"
                    )));
                }
            } else {
                found = Some(record);
            }
            Ok(())
        };
        let completed = |work: &mut dyn Meter| -> Result<Vec<Succession>, StoreError> {
            self.projection()?
                .get(Family::Succession, &anchor.key_bytes(), work)?
                .into_iter()
                .map(|visible| from_canonical(&visible.value).map_err(StoreError::from))
                .collect()
        };
        for record in completed(work)? {
            accept(record)?;
        }
        let key = crate::unsettled_index::DiscoveryKey::SuccessorOf(anchor.clone());
        // In each candidate's own storage: the anchor's key built and looked
        // up, then the row read, decoded and held, each charged first.
        let records = self.every_unsettled_holder(
            &key,
            &format!("successor of {anchor}"),
            work,
            |view: &crate::content_read::ReadView, work: &mut dyn Meter| {
                let txn = view.db.begin_read().map_err(crate::error::redb)?;
                let table = txn
                    .open_table(crate::tables::ID_SUCCESSIONS)
                    .map_err(crate::error::redb)?;
                work.charge_all(&[
                    (Dimension::BytesAllocated, anchor.key_len() as u64),
                    (Dimension::Entries, 1),
                ])?;
                let Some(value) = table
                    .get(anchor.key_bytes().as_slice())
                    .map_err(crate::error::redb)?
                else {
                    return Ok(None);
                };
                let length = value.value().len() as u64;
                work.charge_all(&[
                    (Dimension::BytesRead, length),
                    (Dimension::BytesDecoded, length),
                    (Dimension::BytesAllocated, length),
                ])?;
                Ok(Some(from_canonical::<Succession>(value.value())?))
            },
        )?;
        for record in records.into_iter().flatten() {
            accept(record)?;
        }
        for record in completed(work)? {
            accept(record)?;
        }
        Ok(found)
    }

    pub(crate) fn read_successor(
        &self,
        old_anchor: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Kappa, StoreError> {
        let record = self
            .successor_record(old_anchor, work)?
            .ok_or_else(|| StoreError::NotFound(format!("successor of {old_anchor}")))?;
        if record.old_anchor != *old_anchor {
            return Err(StoreError::Internal(
                "succession index anchor mismatch".into(),
            ));
        }
        Ok(record.new_anchor)
    }

    /// The chain of successions from `anchor`, every link read on the one
    /// `work`.
    pub(crate) fn read_succession_chain(
        &self,
        anchor: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Vec<Succession>, StoreError> {
        kappa_store::succession_ops::walk_chain(anchor, |current| {
            let Some(record) = self.successor_record(current, work)? else {
                return Ok(None);
            };
            if record.old_anchor != *current {
                return Err(StoreError::Internal(
                    "succession index anchor mismatch".into(),
                ));
            }
            Ok(Some((record.new_anchor.clone(), record)))
        })
    }

    pub(crate) fn read_device_bindings(
        &self,
        anchor: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Vec<DeviceBinding>, StoreError> {
        Ok(anchor_record(
            &self.projection()?,
            Family::DeviceBinding,
            anchor,
            "device binding",
            work,
        )?
        .unwrap_or_default())
    }

    pub(crate) fn read_prekey_bindings(
        &self,
        anchor: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Vec<PrekeyBinding>, StoreError> {
        Ok(anchor_record(
            &self.projection()?,
            Family::PrekeyBinding,
            anchor,
            "prekey binding",
            work,
        )?
        .unwrap_or_default())
    }

    pub(crate) fn read_locator(
        &self,
        anchor: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Option<LocatorRecord>, StoreError> {
        anchor_record(
            &self.projection()?,
            Family::LocatorRecord,
            anchor,
            "locator",
            work,
        )
    }

    pub(crate) fn read_revocation_commitment(
        &self,
        anchor: &Kappa,
        work: &mut dyn Meter,
    ) -> Result<Option<RevocationCommitment>, StoreError> {
        anchor_record(
            &self.projection()?,
            Family::RevocationCommitment,
            anchor,
            "revocation commitment",
            work,
        )
    }
}
