//! The stored encoding of projection keys (`projection`): logical and
//! physical key framing, exact group and attempt prefixes, the one prefix
//! scan of the projection tables, and the representation bounds of a
//! version.
//!
//! A version key is `[family:1][escaped key]([00 01][escaped member])
//! [00 00][instance length:1][instance key][epoch:8 BE][attempt:4 BE]
//! [sequence:8 BE]`. Escaping turns every zero byte into `00 FF`, so no
//! escaped key contains `00 00` or `00 01`, and escaped keys compare as their
//! unescaped bytes do. An epoch's completed row and its attempts' log
//! entries are keyed by `[instance length:1][instance key][epoch:8 BE]`.

use redb::ReadableTable;

use kappa_cursor::interval::Interval;
use kappa_store::StoreError;
use kappa_store::work::{Dimension, Meter};

use super::Family;
use crate::redb_cursor::{Rows, rows};
use crate::storage_instance::{MAX_INSTANCE_KEY_BYTES, StorageInstance};

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

/// A length or cost a projection key's encoding cannot represent.
fn overflow() -> StoreError {
    StoreError::Internal("projection key length exceeds u64".into())
}

/// The checked sum of `parts`.
fn total(parts: &[u64]) -> Result<u64, StoreError> {
    parts
        .iter()
        .try_fold(0u64, |sum, part| sum.checked_add(*part))
        .ok_or_else(overflow)
}

/// Bytes [`prefixed`] over `prefix`, resumed after `after`, allocates: the
/// interval it constructs and the native copy of that interval's bounds,
/// whose bytes never exceed the interval's own.
pub fn prefixed_cost(prefix: &[u8], after: Option<&[u8]>) -> Result<u64, StoreError> {
    let interval = Interval::prefix_cost(prefix).ok_or_else(overflow)?;
    total(&[interval, after.map_or(0, Interval::position_cost)])?
        .checked_mul(2)
        .ok_or_else(overflow)
}

/// Every row of `table` whose key starts with `prefix`, in key order,
/// beginning after `after` (a scan resumed where an earlier scan of the
/// same prefix stopped), inside `unit`, an admitted unit whose bound
/// includes [`prefixed_cost`]. A resume position outside `prefix` belongs
/// to another scan and is refused before anything is built: restarting
/// would hide the stale continuation. Each row is the caller's to admit
/// before it reads it. The one prefix scan of the projection tables.
pub fn prefixed<'t>(
    table: &'t impl ReadableTable<&'static [u8], &'static [u8]>,
    prefix: &[u8],
    after: Option<&[u8]>,
    unit: &mut dyn Meter,
) -> Result<Rows<'t, &'static [u8]>, StoreError> {
    if after.is_some_and(|after| !after.starts_with(prefix)) {
        return Err(StoreError::Internal(
            "projection scan resumed from a position outside its prefix".into(),
        ));
    }
    unit.account(
        Dimension::BytesAllocated,
        Interval::prefix_cost(prefix).ok_or_else(overflow)?,
    )?;
    let mut interval = Interval::prefix(prefix);
    if let Some(after) = after {
        unit.account(Dimension::BytesAllocated, Interval::position_cost(after))?;
        interval = interval.after(after);
    }
    rows(table, &interval, unit)
}

/// Bytes `bytes` occupy escaped: one more for every zero byte.
fn escaped_len(bytes: &[u8]) -> Result<u64, StoreError> {
    let zeros = bytes.iter().filter(|byte| **byte == 0).count() as u64;
    total(&[bytes.len() as u64, zeros])
}

/// Bytes [`logical`] of `key` (and `member`) with `trailer` bytes after it
/// holds, computed without allocating: what a caller charges before
/// building it.
pub fn logical_len(key: &[u8], member: Option<&[u8]>, trailer: usize) -> Result<u64, StoreError> {
    let member = match member {
        Some(member) => total(&[MEMBER.len() as u64, escaped_len(member)?])?,
        None => 0,
    };
    total(&[1, escaped_len(key)?, member, trailer as u64])
}

/// The escaped logical key of `key` (and `member`, for a membership
/// family) followed by `trailer` (an end or member marker of a scan
/// prefix, or nothing), in a buffer requested at [`logical_len`].
pub fn logical(
    family: Family,
    key: &[u8],
    member: Option<&[u8]>,
    trailer: &[u8],
) -> Result<Vec<u8>, StoreError> {
    let mut out = exact(logical_len(key, member, trailer.len())?)?;
    out.push(family as u8);
    escape(&mut out, key);
    if let Some(member) = member {
        out.extend_from_slice(&MEMBER);
        escape(&mut out, member);
    }
    out.extend_from_slice(trailer);
    Ok(out)
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

/// The version of a logical key one attempt wrote: its stored value is a
/// tag byte (0 put, 1 tombstone) and a put's payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Version {
    Put(Vec<u8>),
    Tombstone,
}

/// A version as staging writes it, its payload borrowed from whatever owns
/// it: framed straight from that owner, never copied into a [`Version`]
/// first. The one framing of a stored version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VersionRef<'a> {
    Put(&'a [u8]),
    Tombstone,
}

impl VersionRef<'_> {
    /// Write the stored value, the tag byte (0 put, 1 tombstone) and a
    /// put's payload, into `output`, which must be exactly
    /// [`Self::encoded_len`] bytes: the one framing of a stored version.
    pub(crate) fn encode_into(self, output: &mut [u8]) -> Result<(), StoreError> {
        if Some(output.len() as u64) != self.encoded_len().ok() {
            return Err(StoreError::Internal(
                "projection version output has the wrong length".into(),
            ));
        }
        match self {
            Self::Put(payload) => {
                output[0] = 0;
                output[1..].copy_from_slice(payload);
            }
            Self::Tombstone => output[0] = 1,
        }
        Ok(())
    }

    /// Bytes [`Self::encode_into`] writes, computed without framing.
    pub(crate) fn encoded_len(self) -> Result<u64, StoreError> {
        match self {
            Self::Put(payload) => total(&[payload.len() as u64, 1]),
            Self::Tombstone => Ok(1),
        }
    }
}

impl Version {
    /// This version, borrowed for staging.
    pub(crate) fn as_ref(&self) -> VersionRef<'_> {
        match self {
            Self::Put(payload) => VersionRef::Put(payload),
            Self::Tombstone => VersionRef::Tombstone,
        }
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        match bytes.split_first() {
            Some((0, payload)) => Ok(Self::Put(payload.to_vec())),
            Some((1, [])) => Ok(Self::Tombstone),
            _ => Err(StoreError::Internal("malformed projection version".into())),
        }
    }
}

/// Bytes of a version key's coordinates: epoch, attempt and sequence.
const COORDINATES: u64 = 8 + 4 + 8;

/// Longest epoch key ([`epoch_key`]): the instance's length byte and key,
/// and the epoch.
pub const MAX_EPOCH_KEY_BYTES: u64 = 1 + MAX_INSTANCE_KEY_BYTES as u64 + 8;

/// Longest log key ([`log_key`]): the epoch key, the attempt and the
/// sequence.
pub const MAX_LOG_KEY_BYTES: u64 = MAX_EPOCH_KEY_BYTES + 4 + 8;

/// The longest version key and value the projection holds, derived from the
/// settlement record limit the projection was staged under: the key and
/// the member a staged effect names are each read from one record within
/// that limit and escaping at most doubles them, and a value is the
/// version's tag and a payload read from one record. Staging refuses a
/// version beyond them (`ProjectionStage::write`), readers refuse one
/// before copying it, and the limit is recorded in the registry so a store
/// reopened under a smaller one is refused instead of left unable to read
/// what it holds (`store_open::establish_version_bounds`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VersionBounds {
    key: u64,
    value: u64,
}

impl VersionBounds {
    /// The bounds under the record limit `record_bytes`; `None` when they
    /// do not fit in `u64`.
    pub const fn for_records(record_bytes: u64) -> Option<Self> {
        let Some(doubled) = record_bytes.checked_mul(4) else {
            return None;
        };
        let framing = 1 + MEMBER.len() as u64 + END.len() as u64 + 1;
        let Some(key) = doubled.checked_add(framing + MAX_INSTANCE_KEY_BYTES as u64 + COORDINATES)
        else {
            return None;
        };
        let Some(value) = record_bytes.checked_add(1) else {
            return None;
        };
        Some(Self { key, value })
    }

    /// Refuse a version key or value longer than the bounds, before it is
    /// copied or decoded.
    pub fn check(&self, key: &[u8], value: &[u8]) -> Result<(), StoreError> {
        self.check_lengths(key.len() as u64, value.len() as u64)
    }

    /// Refuse a version whose key or value would be longer than the bounds,
    /// from their lengths, before either is built.
    pub fn check_lengths(&self, key: u64, value: u64) -> Result<(), StoreError> {
        if key > self.key || value > self.value {
            return Err(StoreError::Internal(format!(
                "projection version of a {key} byte key and a {value} byte value exceeds the {} and {} bytes the projection admits",
                self.key, self.value
            )));
        }
        Ok(())
    }

    /// Longest encoded version key.
    pub const fn key(&self) -> u64 {
        self.key
    }

    /// Longest encoded version value.
    pub const fn value(&self) -> u64 {
        self.value
    }
}

/// Append `instance`'s framing: its length byte and its key.
fn append_instance(out: &mut Vec<u8>, instance: &StorageInstance) {
    out.push(instance.key_len());
    instance.append_key(out);
}

/// Append the framing every version of `logical` written by `instance`
/// shares: the logical key, its end marker, and the instance's framing.
fn append_group(out: &mut Vec<u8>, logical: &[u8], instance: &StorageInstance) {
    out.extend_from_slice(logical);
    out.extend_from_slice(&END);
    append_instance(out, instance);
}

/// Append the framing of `instance`'s `epoch`: the instance's framing and
/// the epoch.
fn append_epoch(out: &mut Vec<u8>, instance: &StorageInstance, epoch: u64) {
    append_instance(out, instance);
    out.extend_from_slice(&epoch.to_be_bytes());
}

/// Bytes [`key_prefix`] of `logical` for `instance` holds.
pub fn key_prefix_len(logical: &[u8], instance: &StorageInstance) -> Result<u64, StoreError> {
    group_len(logical.len() as u64, instance)
}

/// Bytes the group framing of a logical key `logical` bytes long holds for
/// `instance`: the logical key, its end marker, and the instance's framing.
fn group_len(logical: u64, instance: &StorageInstance) -> Result<u64, StoreError> {
    total(&[logical, END.len() as u64, 1, u64::from(instance.key_len())])
}

/// Bytes [`version_key`] of a logical key `logical` bytes long for
/// `instance` holds: what a writer validates and charges before building
/// either.
pub fn version_key_len(logical: u64, instance: &StorageInstance) -> Result<u64, StoreError> {
    total(&[group_len(logical, instance)?, COORDINATES])
}

/// Bytes [`epoch_key`] of `instance` holds: its length byte (at most
/// `u8::MAX` key bytes follow it) and the epoch, never near `u64::MAX`.
pub fn epoch_key_len(instance: &StorageInstance) -> u64 {
    1 + u64::from(instance.key_len()) + 8
}

/// Bytes [`log_key`] of `instance` holds.
pub fn log_key_len(instance: &StorageInstance) -> u64 {
    epoch_key_len(instance) + 4 + 8
}

/// Bytes [`attempt_prefix`] of `instance` holds.
pub fn attempt_prefix_len(instance: &StorageInstance) -> u64 {
    epoch_key_len(instance) + 4
}

/// The prefix of the `PROJECTION_LOG` keys of `instance`'s `attempt` at
/// `epoch`: the epoch key and the attempt.
pub fn attempt_prefix(
    instance: &StorageInstance,
    epoch: u64,
    attempt: u32,
) -> Result<Vec<u8>, StoreError> {
    let mut out = exact(attempt_prefix_len(instance))?;
    append_epoch(&mut out, instance, epoch);
    out.extend_from_slice(&attempt.to_be_bytes());
    Ok(out)
}

/// A buffer requested at `len` bytes, the length its key constructor's
/// length function reports, so filling it needs no growth (`Vec` grants
/// at least the capacity requested), allocated fallibly. A length this
/// platform cannot address is refused, never clamped; an allocation the
/// heap refuses is a capacity condition.
fn exact(len: u64) -> Result<Vec<u8>, StoreError> {
    let len = usize::try_from(len).map_err(|_| overflow())?;
    let mut out = Vec::new();
    out.try_reserve_exact(len).map_err(|_| {
        StoreError::CapacityExceeded(format!(
            "a projection buffer of {len} bytes could not be allocated"
        ))
    })?;
    Ok(out)
}

/// A zeroed buffer of exactly `len` bytes, allocated fallibly ([`exact`]):
/// the output a caller-buffer writer fills.
pub(crate) fn zeroed(len: u64) -> Result<Vec<u8>, StoreError> {
    let length = usize::try_from(len).map_err(|_| overflow())?;
    let mut out = exact(len)?;
    // Within the capacity reserved: no growth.
    out.resize(length, 0);
    Ok(out)
}

/// The prefix every version of `logical` written by `instance` shares: the
/// logical key, its end marker, and the instance's length byte and key.
pub fn key_prefix(logical: &[u8], instance: &StorageInstance) -> Result<Vec<u8>, StoreError> {
    let mut out = exact(key_prefix_len(logical, instance)?)?;
    append_group(&mut out, logical, instance);
    Ok(out)
}

/// The version key of `logical` written by `instance`'s `attempt` at
/// `epoch`, the `sequence`-th version the attempt staged.
pub fn version_key(
    logical: &[u8],
    instance: &StorageInstance,
    epoch: u64,
    attempt: u32,
    sequence: u64,
) -> Result<Vec<u8>, StoreError> {
    let mut out = exact(version_key_len(logical.len() as u64, instance)?)?;
    append_group(&mut out, logical, instance);
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&attempt.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    Ok(out)
}

/// The `PROJECTION_LOG` key of the `sequence`-th version `instance`'s
/// `attempt` at `epoch` staged: the epoch key, the attempt and the
/// sequence.
pub fn log_key(
    instance: &StorageInstance,
    epoch: u64,
    attempt: u32,
    sequence: u64,
) -> Result<Vec<u8>, StoreError> {
    let mut out = exact(log_key_len(instance))?;
    append_epoch(&mut out, instance, epoch);
    out.extend_from_slice(&attempt.to_be_bytes());
    out.extend_from_slice(&sequence.to_be_bytes());
    Ok(out)
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
pub fn epoch_key(instance: &StorageInstance, epoch: u64) -> Result<Vec<u8>, StoreError> {
    let mut out = exact(epoch_key_len(instance))?;
    append_epoch(&mut out, instance, epoch);
    Ok(out)
}
