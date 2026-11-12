//! Time continuity across restarts.
//!
//! Each namespace commits its own causal floor (`TIME_STATE` in its
//! database) in the transaction that commits the mutation or epoch, so
//! aborted writes never advance it and committed writes are never visible
//! without it. The registry holds one reserved ceiling
//! (`TIME_RESERVATION`), extended durably before any timestamp above it
//! is issued, so the ceiling alone recovers the time floor of the whole
//! registry; the namespace floors raise it where a namespace committed
//! past a ceiling no longer on disk (never under a correct reservation,
//! always tolerated).
//!
//! The published-time bound authority rotation must pass
//! (`latest_epoch_ms`) is recovered the same way: settlement raises a
//! durable bound of settled epoch times (`EPOCH_TIME_BOUND`) with each
//! epoch it settles, restored at open, and recovery raises it from the head
//! of every instance a restart found unsettled as it visits it.

use redb::ReadableTable;

use kappa_store::clock::{CausalTime, ClockMs};
use kappa_store::error::StoreError;
use kappa_store::work::{Dimension, Meter};

use crate::{
    PersistentStore, tables::EPOCH_TIME_BOUND, tables::TIME_RESERVATION, tables::TIME_STATE,
};

const FLOOR_KEY: &[u8] = b"committed-causal-floor";
const RESERVATION_KEY: &[u8] = b"reserved-causal-ceiling";
const SETTLED_EPOCH_KEY: &[u8] = b"settled-epoch-time";

/// Table-encryption context label of time rows.
const TIME_CONTEXT: &str = "time_floor";

/// The AEAD context of a time row at `key`.
fn time_context(key: &[u8]) -> String {
    crate::encrypted::bound(TIME_CONTEXT, key)
}

impl kappa_store::time::TimeReservationStore for PersistentStore {
    fn acquire_time_authority(&self) -> Result<kappa_store::time::TimeAuthorityLease, StoreError> {
        kappa_store::time::TimeAuthorityLease::acquire(std::sync::Arc::clone(
            &self.time_authority_owned,
        ))
    }
    fn recover_time(&self) -> Result<CausalTime, StoreError> {
        self.recovered_time_floor()
    }

    fn reserve_time(&self, ceiling: CausalTime) -> Result<(), StoreError> {
        Self::reserve_time(self, ceiling)
    }
}

impl PersistentStore {
    /// The restart floor: the registry's reserved ceiling and the greatest
    /// committed floor of every namespace recovered so far (the settlement
    /// pass at open recovers all of them).
    pub fn recovered_time_floor(&self) -> Result<CausalTime, StoreError> {
        let txn = self.registry.begin_read()?;
        let table = txn
            .open_table(TIME_RESERVATION)
            .map_err(crate::error::redb)?;
        let reserved = match table.get(RESERVATION_KEY).map_err(crate::error::redb)? {
            Some(value) => Some(self.decode_time_floor(RESERVATION_KEY, value.value())?),
            None => None,
        };
        drop(txn);
        let committed = self.committed_time_floor()?;
        Ok(CausalTime::recovery_floor(committed, reserved))
    }

    /// Monotonically extend the reservation under the registry writer.
    /// Immediate durability is required even when ordinary writes disable
    /// fsync: an issued timestamp must never outrun its restart bound.
    pub fn reserve_time(&self, ceiling: CausalTime) -> Result<(), StoreError> {
        let mut txn = self.registry.begin_write()?;
        txn.set_durability(redb::Durability::Immediate)
            .map_err(crate::error::redb)?;
        self.reserve_time_in_txn(&txn, ceiling)?;
        match txn.commit() {
            Ok(()) => Ok(()),
            // The caller issues no timestamp above a ceiling not known to
            // be durable. A ceiling that persisted only raises the restart
            // floor, which is always safe.
            Err(
                crate::error::CommitFailure::Known(error)
                | crate::error::CommitFailure::Unknown(error),
            ) => Err(error),
        }
    }

    /// Extend the reservation inside an open registry transaction; the
    /// one writer of `TIME_RESERVATION`.
    pub(crate) fn reserve_time_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        ceiling: CausalTime,
    ) -> Result<(), StoreError> {
        let mut table = txn
            .open_table(TIME_RESERVATION)
            .map_err(crate::error::redb)?;
        let previous = match table.get(RESERVATION_KEY).map_err(crate::error::redb)? {
            Some(value) => Some(self.decode_time_floor(RESERVATION_KEY, value.value())?),
            None => None,
        };
        if previous.is_none_or(|value| ceiling > value) {
            let bytes = self.encrypt_bytes(
                &time_context(RESERVATION_KEY),
                &ceiling.encoded().as_i64().to_be_bytes(),
            )?;
            table
                .insert(RESERVATION_KEY, bytes.as_slice())
                .map_err(crate::error::redb)?;
        }
        Ok(())
    }

    /// The greatest causal timestamp committed by any recovered namespace
    /// of this backend. A local durability bound, not an assertion of UTC
    /// accuracy.
    pub fn committed_time_floor(&self) -> Result<CausalTime, StoreError> {
        let raw = self
            .committed_floor_ms
            .load(std::sync::atomic::Ordering::SeqCst);
        if raw == i64::MIN {
            return CausalTime::new(0, 0).map_err(|error| StoreError::Internal(error.to_string()));
        }
        Ok(CausalTime::from_encoded(ClockMs::from_raw(raw)))
    }

    /// The committed floor recorded in a namespace database, on `work`: the
    /// lookup, then the stored row read, its context built, its plaintext
    /// allocated and decrypted, each charged before it runs. The 8-byte
    /// interpretation of the plaintext allocates nothing.
    pub(crate) fn committed_floor_in(
        &self,
        txn: &redb::ReadTransaction,
        work: &mut dyn Meter,
    ) -> Result<Option<CausalTime>, StoreError> {
        work.charge(Dimension::Entries, 1)?;
        let table = txn.open_table(TIME_STATE).map_err(crate::error::redb)?;
        let Some(value) = table.get(FLOOR_KEY).map_err(crate::error::redb)? else {
            return Ok(None);
        };
        let stored = value.value().len() as u64;
        work.charge_all(&[
            (Dimension::BytesRead, stored),
            (
                Dimension::BytesAllocated,
                crate::encrypted::bound_allocation(TIME_CONTEXT, FLOOR_KEY.len()),
            ),
            (Dimension::BytesAllocated, stored),
            (Dimension::BytesDecoded, stored),
        ])?;
        self.decode_time_floor(FLOOR_KEY, value.value()).map(Some)
    }

    fn decode_time_floor(&self, key: &[u8], stored: &[u8]) -> Result<CausalTime, StoreError> {
        let bytes = self.decrypt_bytes(&time_context(key), stored)?;
        let raw = i64::from_be_bytes(
            bytes
                .try_into()
                .map_err(|_| StoreError::Internal("invalid durable time floor length".into()))?,
        );
        Ok(CausalTime::from_encoded(ClockMs::from_raw(raw)))
    }

    /// Update inside the same namespace transaction as the mutation or
    /// epoch publication. Aborted writes cannot advance the durable bound,
    /// and committed writes cannot become visible without their recovery
    /// bound. The process-wide floor is raised only when the transaction
    /// commits (`raise_committed_floor`).
    pub(crate) fn record_time_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        now: ClockMs,
    ) -> Result<(), StoreError> {
        let mut table = txn.open_table(TIME_STATE).map_err(crate::error::redb)?;
        let previous = match table.get(FLOOR_KEY).map_err(crate::error::redb)? {
            Some(value) => Some(self.decode_time_floor(FLOOR_KEY, value.value())?),
            None => None,
        };
        let current = CausalTime::from_encoded(now);
        let floor = previous.map_or(current, |value| value.max(current));
        if previous == Some(floor) {
            return Ok(());
        }
        let bytes = self.encrypt_bytes(
            &time_context(FLOOR_KEY),
            &floor.encoded().as_i64().to_be_bytes(),
        )?;
        table
            .insert(FLOOR_KEY, bytes.as_slice())
            .map_err(crate::error::redb)?;
        Ok(())
    }

    /// Raise the process-wide committed floor after a namespace
    /// transaction committed at `now`.
    pub(crate) fn raise_committed_floor(&self, now: ClockMs) {
        self.committed_floor_ms
            .fetch_max(now.as_i64(), std::sync::atomic::Ordering::SeqCst);
    }

    /// Raise the durable bound of settled epoch times to `timestamp_ms`
    /// inside the registry transaction that settles the epoch; the one
    /// writer of `EPOCH_TIME_BOUND`.
    pub(crate) fn raise_settled_epoch_time_in_txn(
        &self,
        txn: &redb::WriteTransaction,
        timestamp_ms: i64,
    ) -> Result<(), StoreError> {
        let mut table = txn
            .open_table(EPOCH_TIME_BOUND)
            .map_err(crate::error::redb)?;
        let previous = match table.get(SETTLED_EPOCH_KEY).map_err(crate::error::redb)? {
            Some(value) => Some(self.decode_time_floor(SETTLED_EPOCH_KEY, value.value())?),
            None => None,
        };
        let raised = CausalTime::from_encoded(ClockMs::from_raw(timestamp_ms));
        if previous.is_none_or(|value| raised > value) {
            let bytes = self.encrypt_bytes(
                &time_context(SETTLED_EPOCH_KEY),
                &timestamp_ms.to_be_bytes(),
            )?;
            table
                .insert(SETTLED_EPOCH_KEY, bytes.as_slice())
                .map_err(crate::error::redb)?;
        }
        Ok(())
    }

    /// Bring the durable bound of settled epoch times into the published
    /// time bound (`latest_epoch_ms`), at open: every epoch no pending
    /// marker names is settled, and so bounded by it.
    pub(crate) fn restore_settled_epoch_time(&self) -> Result<(), StoreError> {
        let txn = self.registry.begin_read()?;
        let table = txn
            .open_table(EPOCH_TIME_BOUND)
            .map_err(crate::error::redb)?;
        if let Some(value) = table.get(SETTLED_EPOCH_KEY).map_err(crate::error::redb)? {
            let settled = self.decode_time_floor(SETTLED_EPOCH_KEY, value.value())?;
            // Settled instances no longer have pending markers for recovery
            // to visit. Their durable epoch bound must therefore restore the
            // causal issuance floor as well as the authority rotation bound.
            self.raise_committed_floor(settled.encoded());
            self.latest_epoch_ms.fetch_max(
                settled.encoded().as_i64(),
                std::sync::atomic::Ordering::SeqCst,
            );
        }
        Ok(())
    }
}
