//! The stored encoding of projection keys (`projection`), and the one
//! decision of whether a version is visible.
//!
//! A version key is `[family:1][escaped key]([00 01][escaped member])
//! [00 00][instance length:1][instance key][epoch:8 BE][attempt:4 BE]
//! [sequence:8 BE]`. Escaping turns every zero byte into `00 FF`, so no
//! escaped key contains `00 00` or `00 01`, and escaped keys compare as their
//! unescaped bytes do. An epoch's completed row and its attempts' log
//! entries are keyed by `[instance length:1][instance key][epoch:8 BE]`.

use std::ops::Bound;

use redb::ReadableTable;

use kappa_store::StoreError;

use super::Family;
use crate::PersistentStore;
use crate::storage_instance::StorageInstance;

/// Ends a logical key inside a version key.
pub const END: [u8; 2] = [0x00, 0x00];
/// Separates a membership family's key from its member.
pub const MEMBER: [u8; 2] = [0x00, 0x01];
/// Follows a literal zero byte of a key or member.
const ZERO: u8 = 0xFF;

/// An escaped logical key unescaped: the family byte, the key and the
/// member of a membership family.
pub type SplitLogical = (u8, Vec<u8>, Option<Vec<u8>>);

/// Append `bytes` order-preservingly: a zero byte becomes `00 FF`.
fn escape(out: &mut Vec<u8>, bytes: &[u8]) {
    for &byte in bytes {
        out.push(byte);
        if byte == 0 {
            out.push(ZERO);
        }
    }
}

/// The bytes `escape` wrote.
pub fn unescape(escaped: &[u8]) -> Result<Vec<u8>, StoreError> {
    let mut out = Vec::with_capacity(escaped.len());
    let mut bytes = escaped.iter();
    while let Some(&byte) = bytes.next() {
        out.push(byte);
        if byte == 0 && bytes.next() != Some(&ZERO) {
            return Err(StoreError::Internal(
                "malformed escaped projection key".into(),
            ));
        }
    }
    Ok(out)
}

/// Whether escaped bytes hold a membership separator.
pub fn contains_member(escaped: &[u8]) -> bool {
    escaped.windows(2).any(|pair| pair == MEMBER)
}

/// Every row of `table` whose key starts with `prefix`, in key order. The
/// one prefix scan of the projection tables.
pub fn prefixed<'t>(
    table: &'t impl ReadableTable<&'static [u8], &'static [u8]>,
    prefix: &[u8],
) -> Result<redb::Range<'t, &'static [u8], &'static [u8]>, StoreError> {
    let end = PersistentStore::prefix_successor(prefix);
    let upper = end.as_deref().map_or(Bound::Unbounded, Bound::Excluded);
    table
        .range::<&[u8]>((Bound::Included(prefix), upper))
        .map_err(crate::error::redb)
}

/// The escaped logical key of `key` (and `member`, for a membership
/// family), without its end marker.
pub fn logical(family: Family, key: &[u8], member: Option<&[u8]>) -> Vec<u8> {
    let mut out = vec![family as u8];
    escape(&mut out, key);
    if let Some(member) = member {
        out.extend_from_slice(&MEMBER);
        escape(&mut out, member);
    }
    out
}

/// The family byte, key and member (for a membership family) of an escaped
/// logical key, unescaped.
pub fn split_logical(logical: &[u8]) -> Result<SplitLogical, StoreError> {
    let (&family, body) = logical
        .split_first()
        .ok_or_else(|| StoreError::Internal("empty projection logical key".into()))?;
    match body.windows(2).position(|pair| pair == MEMBER) {
        Some(split) => Ok((
            family,
            unescape(&body[..split])?,
            Some(unescape(&body[split + 2..])?),
        )),
        None => Ok((family, unescape(body)?, None)),
    }
}

/// The version key of `logical` written by `instance`'s `attempt` at
/// `epoch`, the `sequence`-th version the attempt staged.
pub fn version_key(
    logical: &[u8],
    instance: &StorageInstance,
    epoch: u64,
    attempt: u32,
    sequence: u64,
) -> Vec<u8> {
    let length = instance.key_len();
    let instance = instance.key();
    let mut out = Vec::with_capacity(logical.len() + 2 + 1 + instance.len() + 20);
    out.extend_from_slice(logical);
    out.extend_from_slice(&END);
    out.push(length);
    out.extend_from_slice(&instance);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&attempt.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    out
}

/// A decoded version key: the escaped logical key (family byte included)
/// and the writing attempt's coordinates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionKey {
    pub logical: Vec<u8>,
    pub instance: StorageInstance,
    pub epoch: u64,
    pub attempt: u32,
    pub sequence: u64,
}

fn malformed() -> StoreError {
    StoreError::Internal("malformed projection version key".into())
}

impl VersionKey {
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        // The logical key ends at the first `00 00` not part of an escape.
        let mut index = 1;
        let end = loop {
            match (bytes.get(index), bytes.get(index + 1)) {
                (Some(0), Some(0)) => break index,
                (Some(0), Some(_)) => index += 2,
                (Some(_), _) => index += 1,
                (None, _) => return Err(malformed()),
            }
        };
        let rest = bytes.get(end + 2..).ok_or_else(malformed)?;
        let (&length, rest) = rest.split_first().ok_or_else(malformed)?;
        let length = usize::from(length);
        let instance = StorageInstance::from_key(rest.get(..length).ok_or_else(malformed)?)?;
        let tail: &[u8; 20] = rest
            .get(length..)
            .and_then(|tail| tail.try_into().ok())
            .ok_or_else(malformed)?;
        let (epoch, tail) = tail.split_at(8);
        let (attempt, sequence) = tail.split_at(4);
        Ok(Self {
            logical: bytes[..end].to_vec(),
            instance,
            epoch: u64::from_be_bytes(epoch.try_into().map_err(|_| malformed())?),
            attempt: u32::from_be_bytes(attempt.try_into().map_err(|_| malformed())?),
            sequence: u64::from_be_bytes(sequence.try_into().map_err(|_| malformed())?),
        })
    }
}

/// The key of an instance's epoch in `PROJECTION_COMPLETED` and the prefix
/// of its attempts in `PROJECTION_LOG`.
pub fn epoch_key(instance: &StorageInstance, epoch: u64) -> Vec<u8> {
    let length = instance.key_len();
    let instance = instance.key();
    let mut out = Vec::with_capacity(1 + instance.len() + 8);
    out.push(length);
    out.extend_from_slice(&instance);
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

/// `[attempt:4][completion sequence:8]` of a completed epoch.
fn decode_completed(bytes: &[u8]) -> Result<(u32, u64), StoreError> {
    let bytes: &[u8; 12] = bytes
        .try_into()
        .map_err(|_| StoreError::Internal("malformed projection completion".into()))?;
    let (attempt, sequence) = bytes.split_at(4);
    Ok((
        u32::from_be_bytes(attempt.try_into().map_err(|_| malformed())?),
        u64::from_be_bytes(sequence.try_into().map_err(|_| malformed())?),
    ))
}

/// The epoch `instance` is settled to, from a `SETTLED` table: its
/// checkpoint is `[epoch:8 BE][root key_bytes]`; 0 when it has none.
fn settled_epoch_in(
    settled: &impl ReadableTable<&'static [u8], &'static [u8]>,
    instance: &StorageInstance,
) -> Result<u64, StoreError> {
    settled
        .get(instance.key().as_slice())
        .map_err(crate::error::redb)?
        .map(|value| {
            value
                .value()
                .get(..8)
                .and_then(|epoch| <[u8; 8]>::try_from(epoch).ok())
                .map(u64::from_be_bytes)
                .ok_or_else(|| StoreError::Internal("malformed settlement checkpoint".into()))
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

/// The last completion sequence of `instance`, from a
/// `PROJECTION_INSTANCES` table; 0 when it completed nothing.
fn instance_completion_in(
    instances: &impl ReadableTable<&'static [u8], &'static [u8]>,
    instance: &StorageInstance,
) -> Result<u64, StoreError> {
    instances
        .get(instance.key().as_slice())
        .map_err(crate::error::redb)?
        .map(|value| {
            <[u8; 8]>::try_from(value.value())
                .map(u64::from_be_bytes)
                .map_err(|_| StoreError::Internal("malformed instance completion".into()))
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

/// Whether `version` is of its epoch's completed attempt, and the
/// completion sequence that orders it: the epoch's completed row when it
/// has one, otherwise (compaction removed it, having purged every other
/// attempt of the epoch) whether the epoch is at or below the instance's
/// checkpoint, ordered by the instance's last completion.
pub fn visibility(
    completed: &impl ReadableTable<&'static [u8], &'static [u8]>,
    settled: &impl ReadableTable<&'static [u8], &'static [u8]>,
    instances: &impl ReadableTable<&'static [u8], &'static [u8]>,
    version: &VersionKey,
) -> Result<Option<u64>, StoreError> {
    let row = completed
        .get(epoch_key(&version.instance, version.epoch).as_slice())
        .map_err(crate::error::redb)?
        .map(|value| decode_completed(value.value()))
        .transpose()?;
    if let Some((attempt, sequence)) = row {
        return Ok((attempt == version.attempt).then_some(sequence));
    }
    if version.epoch <= settled_epoch_in(settled, &version.instance)? {
        return Ok(Some(instance_completion_in(instances, &version.instance)?));
    }
    Ok(None)
}
