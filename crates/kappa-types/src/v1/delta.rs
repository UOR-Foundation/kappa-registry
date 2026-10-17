//! Git-format binary deltas: the one encoder and decoder every consumer
//! (git packs, bundles) uses.
//!
//! Decoding is bounded before it allocates: the declared result size is
//! checked against the caller's limit and reserved against a shared
//! [`DeltaBudget`] (the bytes every concurrent decode may hold at once)
//! before the result buffer exists, and every copy and insert is checked
//! against the declared size as it lands, so a crafted delta can neither
//! allocate past its admission nor grow a buffer past it. Every refusal
//! is a typed [`DeltaError`].
//!
//! Encoding has a work budget: the fingerprint index keeps at most
//! [`HASH_LIMIT`] positions per fingerprint, each target position examines
//! at most that many candidates, and the bytes compared while extending
//! matches are capped at [`WORK_FACTOR`] times the input. When the budget
//! is exhausted the remainder of the target is emitted as literal inserts,
//! which is a valid delta, and the outcome reports it
//! ([`DeltaStats::budget_exhausted`]); a delta that is not worthwhile is
//! declined. Copy instructions are split at the wire's 24-bit size and
//! a base offset beyond 32 bits declines the delta instead of truncating.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

const BLOCK_SIZE: usize = 16;
const THRESHOLD_PERCENT: usize = 75;
/// Positions kept per fingerprint and candidates examined per target
/// position (git's `HASH_LIMIT`).
pub const HASH_LIMIT: usize = 64;
/// Bytes compared while extending matches, per input byte.
pub const WORK_FACTOR: usize = 8;
/// Largest copy one instruction can carry.
const MAX_COPY: usize = 0xff_ffff;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DeltaError {
    #[error("truncated delta: {0}")]
    Truncated(&'static str),
    #[error("varint overflow")]
    VarintOverflow,
    #[error("base size mismatch: expected {expected}, got {got}")]
    BaseSizeMismatch { expected: usize, got: usize },
    #[error("copy out of bounds: offset {offset}, size {size}, base len {base_len}")]
    CopyOutOfBounds {
        offset: usize,
        size: usize,
        base_len: usize,
    },
    #[error("reserved opcode 0x00")]
    ReservedOpcode,
    #[error("result size mismatch: expected {expected}, got {got}")]
    ResultSizeMismatch { expected: usize, got: usize },
    /// The declared result exceeds what the caller admits.
    #[error("delta result of {declared} bytes exceeds the admitted {limit}")]
    ResultTooLarge { declared: usize, limit: usize },
    /// An instruction would write past the declared result size.
    #[error("delta instructions exceed the declared result size {declared}")]
    ResultOverrun { declared: usize },
    /// The shared budget cannot hold the result alongside the decodes in
    /// flight.
    #[error("delta budget exhausted: {requested} bytes requested, {available} available")]
    BudgetExhausted { requested: usize, available: usize },
}

/// Bytes every concurrent delta decode may hold at once. Shared by every
/// decoder of a process, so admission is accounted across requests.
#[derive(Debug)]
pub struct DeltaBudget {
    limit: usize,
    used: AtomicUsize,
}

/// Bytes reserved against a [`DeltaBudget`]; released on drop. A decoded
/// result stays reserved while its holder keeps the reservation.
#[derive(Debug)]
pub struct DeltaReservation {
    budget: Arc<DeltaBudget>,
    bytes: usize,
}

impl DeltaBudget {
    pub const fn new(limit: usize) -> Self {
        Self {
            limit,
            used: AtomicUsize::new(0),
        }
    }

    pub const fn limit(&self) -> usize {
        self.limit
    }

    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    /// Reserve `bytes`, refusing when the budget cannot hold them.
    pub fn reserve(self: &Arc<Self>, bytes: usize) -> Result<DeltaReservation, DeltaError> {
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|total| *total <= self.limit)
            })
            .map_err(|used| DeltaError::BudgetExhausted {
                requested: bytes,
                available: self.limit.saturating_sub(used),
            })?;
        Ok(DeltaReservation {
            budget: Arc::clone(self),
            bytes,
        })
    }
}

impl DeltaReservation {
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Reserve `more` bytes onto this reservation.
    pub fn grow(&mut self, more: usize) -> Result<(), DeltaError> {
        let added = self.budget.reserve(more)?;
        self.bytes = self.bytes.saturating_add(added.bytes);
        // The added reservation's accounting is now carried by `self`.
        std::mem::forget(added);
        Ok(())
    }
}

impl Drop for DeltaReservation {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

pub fn encode_varint(value: usize, out: &mut Vec<u8>) {
    let mut v = value;
    loop {
        let mut byte = v.to_le_bytes()[0] & 0x7f;
        v >>= 7;
        if v > 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if v == 0 {
            break;
        }
    }
}

pub const fn decode_varint(data: &[u8], pos: &mut usize) -> Result<usize, DeltaError> {
    let mut value: usize = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= data.len() {
            return Err(DeltaError::Truncated("varint"));
        }
        let byte = data[*pos];
        *pos += 1;
        let payload = (byte & 0x7f) as usize;
        if shift >= usize::BITS || payload > (usize::MAX >> shift) {
            return Err(DeltaError::VarintOverflow);
        }
        value |= payload << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift >= usize::BITS {
            return Err(DeltaError::VarintOverflow);
        }
    }
    Ok(value)
}

/// The declared `(base_size, result_size)` of a delta and the position of
/// its first instruction.
pub fn declared_sizes(delta: &[u8]) -> Result<(usize, usize, usize), DeltaError> {
    let mut pos = 0;
    let base_size = decode_varint(delta, &mut pos)?;
    let result_size = decode_varint(delta, &mut pos)?;
    Ok((base_size, result_size, pos))
}

/// Apply `delta` to `base`, admitting a result of at most `max_result`
/// bytes reserved against `budget`. The reservation is returned with the
/// result and holds the bytes until it is dropped.
pub fn apply_delta(
    base: &[u8],
    delta: &[u8],
    max_result: usize,
    budget: &Arc<DeltaBudget>,
) -> Result<(Vec<u8>, DeltaReservation), DeltaError> {
    let (base_size, result_size, mut pos) = declared_sizes(delta)?;
    if base.len() != base_size {
        return Err(DeltaError::BaseSizeMismatch {
            expected: base_size,
            got: base.len(),
        });
    }
    if result_size > max_result {
        return Err(DeltaError::ResultTooLarge {
            declared: result_size,
            limit: max_result,
        });
    }
    let reservation = budget.reserve(result_size)?;
    let mut out = Vec::with_capacity(result_size);
    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;
        if cmd == 0 {
            return Err(DeltaError::ReservedOpcode);
        }
        if cmd & 0x80 != 0 {
            let (offset, size) = decode_copy(cmd, delta, &mut pos)?;
            let end = offset
                .checked_add(size)
                .filter(|end| *end <= base.len())
                .ok_or(DeltaError::CopyOutOfBounds {
                    offset,
                    size,
                    base_len: base.len(),
                })?;
            admit(&out, size, result_size)?;
            out.extend_from_slice(&base[offset..end]);
        } else {
            let n = cmd as usize;
            let end = pos
                .checked_add(n)
                .filter(|end| *end <= delta.len())
                .ok_or(DeltaError::Truncated("insert data"))?;
            admit(&out, n, result_size)?;
            out.extend_from_slice(&delta[pos..end]);
            pos = end;
        }
    }
    if out.len() != result_size {
        return Err(DeltaError::ResultSizeMismatch {
            expected: result_size,
            got: out.len(),
        });
    }
    Ok((out, reservation))
}

/// Refuse an instruction of `len` bytes that would write past `declared`.
const fn admit(out: &[u8], len: usize, declared: usize) -> Result<(), DeltaError> {
    match out.len().checked_add(len) {
        Some(total) if total <= declared => Ok(()),
        _ => Err(DeltaError::ResultOverrun { declared }),
    }
}

fn decode_copy(cmd: u8, delta: &[u8], pos: &mut usize) -> Result<(usize, usize), DeltaError> {
    let mut offset: usize = 0;
    for (bit, shift) in [(0x01u8, 0u32), (0x02, 8), (0x04, 16), (0x08, 24)] {
        if cmd & bit != 0 {
            let byte = *delta
                .get(*pos)
                .ok_or(DeltaError::Truncated("copy offset"))?;
            offset |= (byte as usize) << shift;
            *pos += 1;
        }
    }
    let mut size: usize = 0;
    for (bit, shift) in [(0x10u8, 0u32), (0x20, 8), (0x40, 16)] {
        if cmd & bit != 0 {
            let byte = *delta.get(*pos).ok_or(DeltaError::Truncated("copy size"))?;
            size |= (byte as usize) << shift;
            *pos += 1;
        }
    }
    if size == 0 {
        size = 0x10000;
    }
    Ok((offset, size))
}

fn fnv1a(block: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in block {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

/// What one encoding cost and achieved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DeltaStats {
    /// Bytes compared while extending candidate matches.
    pub compared_bytes: usize,
    /// Candidate positions examined.
    pub candidates_examined: usize,
    /// The work budget ran out and the rest of the target was emitted
    /// literally.
    pub budget_exhausted: bool,
    /// Bytes of the target covered by copy instructions.
    pub copied_bytes: usize,
}

/// Compute a delta from base to target. `None` when not worthwhile, when
/// the inputs are too small, or when a base offset is not representable.
pub fn compute_delta(base: &[u8], target: &[u8]) -> Option<Vec<u8>> {
    compute_delta_with_stats(base, target).map(|(delta, _)| delta)
}

/// `compute_delta` with the work and effectiveness it measured. `None`
/// carries no stats: the delta was declined.
pub fn compute_delta_with_stats(base: &[u8], target: &[u8]) -> Option<(Vec<u8>, DeltaStats)> {
    if base.is_empty() || target.is_empty() || target.len() < BLOCK_SIZE {
        return None;
    }
    let index = build_index(base);
    let work_limit = base
        .len()
        .saturating_add(target.len())
        .saturating_mul(WORK_FACTOR);
    let mut stats = DeltaStats::default();
    let mut instructions: Vec<u8> = Vec::new();
    let mut insert_buf: Vec<u8> = Vec::new();
    let mut pos = 0;
    while pos < target.len() {
        let found = if stats.budget_exhausted || pos + BLOCK_SIZE > target.len() {
            None
        } else {
            best_match(base, target, pos, &index, work_limit, &mut stats)
        };
        if let Some((best_offset, best_len)) = found {
            flush_inserts(&mut instructions, &mut insert_buf);
            emit_copy(&mut instructions, best_offset, best_len)?;
            stats.copied_bytes += best_len;
            pos += best_len;
        } else {
            insert_buf.push(target[pos]);
            if insert_buf.len() == 127 {
                flush_inserts(&mut instructions, &mut insert_buf);
            }
            pos += 1;
        }
    }
    flush_inserts(&mut instructions, &mut insert_buf);
    let mut delta = Vec::new();
    encode_varint(base.len(), &mut delta);
    encode_varint(target.len(), &mut delta);
    delta.extend_from_slice(&instructions);
    if delta.len() >= target.len() * THRESHOLD_PERCENT / 100 {
        return None;
    }
    Some((delta, stats))
}

/// Fingerprint index of `base` with at most `HASH_LIMIT` positions per
/// fingerprint, kept evenly spaced so a repetitive base still indexes its
/// whole extent.
fn build_index(base: &[u8]) -> HashMap<u64, Vec<usize>> {
    let mut index: HashMap<u64, Vec<usize>> = HashMap::new();
    if base.len() < BLOCK_SIZE {
        return index;
    }
    for i in 0..=(base.len() - BLOCK_SIZE) {
        index
            .entry(fnv1a(&base[i..i + BLOCK_SIZE]))
            .or_default()
            .push(i);
    }
    for positions in index.values_mut() {
        if positions.len() > HASH_LIMIT {
            let stride = positions.len().div_ceil(HASH_LIMIT);
            let kept: Vec<usize> = positions.iter().copied().step_by(stride).collect();
            *positions = kept;
        }
    }
    index
}

/// The longest match of `target[pos..]` in `base` among the indexed
/// candidates, within the work budget.
fn best_match(
    base: &[u8],
    target: &[u8],
    pos: usize,
    index: &HashMap<u64, Vec<usize>>,
    work_limit: usize,
    stats: &mut DeltaStats,
) -> Option<(usize, usize)> {
    let candidates = index.get(&fnv1a(&target[pos..pos + BLOCK_SIZE]))?;
    let mut best: Option<(usize, usize)> = None;
    for &base_off in candidates.iter().take(HASH_LIMIT) {
        stats.candidates_examined += 1;
        // The common prefix of the base from the candidate and the target
        // from `pos`; the zip stops at the shorter of the two.
        let len = base[base_off..]
            .iter()
            .zip(&target[pos..])
            .take_while(|(from_base, from_target)| from_base == from_target)
            .count();
        stats.compared_bytes = stats.compared_bytes.saturating_add(len.max(1));
        if len >= BLOCK_SIZE && best.is_none_or(|(_, best_len)| len > best_len) {
            best = Some((base_off, len));
        }
        if stats.compared_bytes >= work_limit {
            stats.budget_exhausted = true;
            break;
        }
    }
    best
}

fn flush_inserts(instructions: &mut Vec<u8>, buf: &mut Vec<u8>) {
    for chunk in buf.chunks(127) {
        instructions.push(chunk.len().to_le_bytes()[0]);
        instructions.extend_from_slice(chunk);
    }
    buf.clear();
}

/// Emit `size` bytes copied from `offset`, split at the wire's largest
/// copy; `None` when an offset is not representable in 32 bits.
fn emit_copy(instructions: &mut Vec<u8>, offset: usize, size: usize) -> Option<()> {
    let mut offset = u32::try_from(offset).ok()?;
    let mut remaining = size;
    while remaining != 0 {
        let size = remaining.min(MAX_COPY);
        emit_copy_chunk(instructions, offset, size);
        remaining -= size;
        if remaining != 0 {
            offset = offset.checked_add(u32::try_from(size).ok()?)?;
        }
    }
    Some(())
}

fn emit_copy_chunk(instructions: &mut Vec<u8>, offset: u32, size: usize) {
    let mut cmd: u8 = 0x80;
    let mut extra = Vec::new();
    for (bit, shift) in [(0x01u8, 0u32), (0x02, 8), (0x04, 16), (0x08, 24)] {
        let byte = ((offset >> shift) & 0xff) as u8;
        if byte != 0 {
            cmd |= bit;
            extra.push(byte);
        }
    }
    let size_bytes = if size == 0x10000 {
        [0u8; 3]
    } else {
        let bytes = size.to_le_bytes();
        [bytes[0], bytes[1], bytes[2]]
    };
    for (bit, byte) in [
        (0x10u8, size_bytes[0]),
        (0x20, size_bytes[1]),
        (0x40, size_bytes[2]),
    ] {
        if byte != 0 {
            cmd |= bit;
            extra.push(byte);
        }
    }
    instructions.push(cmd);
    instructions.extend_from_slice(&extra);
}

#[cfg(test)]
#[path = "delta_tests.rs"]
mod tests;
