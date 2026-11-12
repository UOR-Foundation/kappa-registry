//! The one decision of whether a projection version is visible
//! (`projection`), its metered row reads, and the bound of its work.
//!
//! A version is visible when its attempt is its epoch's completed attempt
//! (`PROJECTION_COMPLETED`); once compaction retired that row, having purged
//! every other attempt of the epoch first, when its epoch is at or below its
//! instance's checkpoint (`SETTLED`). The instance's last completion
//! (`PROJECTION_INSTANCES`) orders it among instances. Committed reads use
//! this decision as it is; staging adds only its own attempt beside it.

use redb::ReadableTable;

use kappa_store::StoreError;
use kappa_store::work::{Dimension, Meter, Work};

use super::key::{MAX_EPOCH_KEY_BYTES, VersionKey, epoch_key, epoch_key_len};
use crate::settlement::MAX_CHECKPOINT_BYTES;
use crate::storage_instance::MAX_INSTANCE_KEY_BYTES;

/// Bytes of an epoch's completed row: its attempt and completion sequence.
const COMPLETED_ROW_BYTES: u64 = 12;

/// Bytes of an instance's last-completion row.
const INSTANCE_COMPLETION_BYTES: u64 = 8;

/// `[attempt:4][completion sequence:8]` of a completed epoch.
fn decode_completed(bytes: &[u8]) -> Result<(u32, u64), StoreError> {
    let malformed = || StoreError::Internal("malformed projection completion".into());
    let bytes: &[u8; 12] = bytes.try_into().map_err(|_| malformed())?;
    let (attempt, sequence) = bytes.split_at(4);
    Ok((
        u32::from_be_bytes(attempt.try_into().map_err(|_| malformed())?),
        u64::from_be_bytes(sequence.try_into().map_err(|_| malformed())?),
    ))
}

/// The work one [`visibility`] decision may do at most, as one aggregate
/// (`Work::total`): three rows examined (the completed row, the checkpoint,
/// the last completion), each row's longest value read and decoded, and
/// what it allocates: the epoch key, one instance key for both instance
/// lookups, and the root identity a checkpoint decodes to. Refused, naming
/// the dimension, when it does not fit in `u64`.
pub fn visibility_unit() -> Result<Work, Dimension> {
    let rows = [
        COMPLETED_ROW_BYTES,
        MAX_CHECKPOINT_BYTES as u64,
        INSTANCE_COMPLETION_BYTES,
    ];
    Work::total(&[
        (Dimension::Entries, 3),
        (Dimension::BytesRead, rows[0]),
        (Dimension::BytesDecoded, rows[0]),
        (Dimension::BytesRead, rows[1]),
        (Dimension::BytesDecoded, rows[1]),
        (Dimension::BytesRead, rows[2]),
        (Dimension::BytesDecoded, rows[2]),
        (Dimension::BytesAllocated, MAX_EPOCH_KEY_BYTES),
        (Dimension::BytesAllocated, MAX_INSTANCE_KEY_BYTES as u64),
        (Dimension::BytesAllocated, MAX_CHECKPOINT_BYTES as u64),
    ])
}

/// The value of the row at `key` of `table`, examined, read and decoded by
/// `decode` inside `unit`; a value longer than `max`, the longest its
/// encoding holds, is refused before it is converted. A decoding that
/// allocates (`allocates`) accounts its output too.
fn read_row<T>(
    table: &impl ReadableTable<&'static [u8], &'static [u8]>,
    key: &[u8],
    max: u64,
    allocates: bool,
    unit: &mut dyn Meter,
    decode: impl FnOnce(&[u8]) -> Result<T, StoreError>,
) -> Result<Option<T>, StoreError> {
    unit.account(Dimension::Entries, 1)?;
    let Some(value) = table.get(key).map_err(crate::error::redb)? else {
        return Ok(None);
    };
    let bytes = value.value();
    let len = bytes.len() as u64;
    if len > max {
        return Err(StoreError::Internal(format!(
            "projection row of {len} bytes exceeds the {max} bytes its encoding holds"
        )));
    }
    unit.account(Dimension::BytesRead, len)?;
    unit.account(Dimension::BytesDecoded, len)?;
    if allocates {
        unit.account(Dimension::BytesAllocated, len)?;
    }
    decode(bytes).map(Some)
}

/// Whether `version` is of its epoch's completed attempt, and the
/// completion sequence that orders it (see the module documentation).
/// Every row examined, value read and decoded and key built is accounted
/// inside `unit`, admitted at [`visibility_unit`] or within a bound that
/// includes it.
pub fn visibility(
    completed: &impl ReadableTable<&'static [u8], &'static [u8]>,
    settled: &impl ReadableTable<&'static [u8], &'static [u8]>,
    instances: &impl ReadableTable<&'static [u8], &'static [u8]>,
    version: &VersionKey,
    unit: &mut dyn Meter,
) -> Result<Option<u64>, StoreError> {
    unit.account(Dimension::BytesAllocated, epoch_key_len(&version.instance))?;
    let row = read_row(
        completed,
        &epoch_key(&version.instance, version.epoch)?,
        COMPLETED_ROW_BYTES,
        false,
        unit,
        decode_completed,
    )?;
    if let Some((attempt, sequence)) = row {
        return Ok((attempt == version.attempt).then_some(sequence));
    }
    unit.account(
        Dimension::BytesAllocated,
        u64::from(version.instance.key_len()),
    )?;
    let instance = version.instance.key();
    let settled_epoch = read_row(
        settled,
        &instance,
        MAX_CHECKPOINT_BYTES as u64,
        true,
        unit,
        crate::settlement::decode_checkpoint,
    )?
    .map_or(0, |(epoch, _)| epoch);
    if version.epoch > settled_epoch {
        return Ok(None);
    }
    let completion = read_row(
        instances,
        &instance,
        INSTANCE_COMPLETION_BYTES,
        false,
        unit,
        |value| {
            <[u8; 8]>::try_from(value)
                .map(u64::from_be_bytes)
                .map_err(|_| StoreError::Internal("malformed instance completion".into()))
        },
    )?;
    Ok(Some(completion.unwrap_or_default()))
}
