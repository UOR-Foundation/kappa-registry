//! Delta codec for bundle wire format.
//!
//! Implements Git-compatible binary delta encoding: COPY (from base) and
//! INSERT (literal bytes) instructions. The format is byte-compatible with
//! Git's pack delta format (patch-delta.c / diff-delta.c).
//!
//! All multi-byte integers in the KBND bundle format are big-endian
//! (network byte order). Delta instruction offset/size bytes are
//! little-endian per the Git wire format. These are intentionally
//! different: bundle framing follows network conventions, delta
//! instructions follow Git conventions for wire compatibility.

use std::collections::HashMap;

use crate::store::StoreError;

/// Block size for fingerprint index over base object.
const BLOCK_SIZE: usize = 16;

/// Delta is only worthwhile if it saves at least 25% over the original.
const THRESHOLD_PERCENT: usize = 75;

// ---- varint codec (Git-style: MSB continuation, 7 bits per byte, LE) ----

pub fn encode_varint(value: usize, out: &mut Vec<u8>) {
    let mut v = value;
    loop {
        let mut byte = (v & 0x7f) as u8;
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

pub fn decode_varint(data: &[u8], pos: &mut usize) -> Result<usize, StoreError> {
    let mut value: usize = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= data.len() {
            return Err(StoreError::DeltaTruncated("varint"));
        }
        let byte = data[*pos];
        *pos += 1;
        value |= ((byte & 0x7f) as usize) << shift;
        if byte & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(StoreError::DeltaVarintOverflow);
        }
    }
    Ok(value)
}

// ---- FNV-1a fingerprint (search heuristic, NOT on security boundary) ----

fn fnv1a(block: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in block {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

// ---- delta computation ----

/// Compute a delta from base to target. Returns None if the delta is not
/// worth it (>= 75% of target size) or if inputs are too small.
pub fn compute_delta(base: &[u8], target: &[u8]) -> Option<Vec<u8>> {
    if base.is_empty() || target.is_empty() || target.len() < BLOCK_SIZE {
        return None;
    }

    // Build index over base: fnv1a fingerprint -> list of offsets
    let mut index: HashMap<u64, Vec<usize>> = HashMap::new();
    if base.len() >= BLOCK_SIZE {
        for i in 0..=(base.len() - BLOCK_SIZE) {
            let fp = fnv1a(&base[i..i + BLOCK_SIZE]);
            index.entry(fp).or_default().push(i);
        }
    }

    // Scan target, emit copy/insert instructions
    let mut instructions: Vec<u8> = Vec::new();
    let mut insert_buf: Vec<u8> = Vec::new();
    let mut pos = 0;

    while pos < target.len() {
        let mut best_offset = 0usize;
        let mut best_len = 0usize;

        if pos + BLOCK_SIZE <= target.len() {
            let fp = fnv1a(&target[pos..pos + BLOCK_SIZE]);
            if let Some(offsets) = index.get(&fp) {
                for &base_off in offsets {
                    if base[base_off..base_off + BLOCK_SIZE] != target[pos..pos + BLOCK_SIZE] {
                        continue;
                    }
                    let mut len = BLOCK_SIZE;
                    while base_off + len < base.len()
                        && pos + len < target.len()
                        && base[base_off + len] == target[pos + len]
                    {
                        len += 1;
                    }
                    if len > best_len {
                        best_len = len;
                        best_offset = base_off;
                    }
                }
            }
        }

        if best_len >= BLOCK_SIZE {
            flush_inserts(&mut instructions, &mut insert_buf);
            emit_copy(&mut instructions, best_offset, best_len);
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

    Some(delta)
}

fn flush_inserts(instructions: &mut Vec<u8>, buf: &mut Vec<u8>) {
    while !buf.is_empty() {
        let n = buf.len().min(127);
        instructions.push(n as u8);
        instructions.extend_from_slice(&buf[..n]);
        buf.drain(..n);
    }
}

fn emit_copy(instructions: &mut Vec<u8>, offset: usize, size: usize) {
    let mut cmd: u8 = 0x80;
    let mut extra = Vec::new();

    let off = offset as u32;
    if off & 0xff != 0 {
        cmd |= 0x01;
        extra.push((off & 0xff) as u8);
    }
    if off & 0xff00 != 0 {
        cmd |= 0x02;
        extra.push(((off >> 8) & 0xff) as u8);
    }
    if off & 0xff_0000 != 0 {
        cmd |= 0x04;
        extra.push(((off >> 16) & 0xff) as u8);
    }
    if off & 0xff00_0000 != 0 {
        cmd |= 0x08;
        extra.push(((off >> 24) & 0xff) as u8);
    }

    let sz = if size == 0x10000 { 0u32 } else { size as u32 };
    if sz & 0xff != 0 {
        cmd |= 0x10;
        extra.push((sz & 0xff) as u8);
    }
    if sz & 0xff00 != 0 {
        cmd |= 0x20;
        extra.push(((sz >> 8) & 0xff) as u8);
    }
    if sz & 0xff_0000 != 0 {
        cmd |= 0x40;
        extra.push(((sz >> 16) & 0xff) as u8);
    }

    instructions.push(cmd);
    instructions.extend_from_slice(&extra);
}

// ---- delta application ----

/// Apply a delta instruction stream to a base object, producing the result.
pub fn apply_delta(base: &[u8], delta: &[u8]) -> Result<Vec<u8>, StoreError> {
    let mut pos = 0;
    let base_size = decode_varint(delta, &mut pos)?;
    let result_size = decode_varint(delta, &mut pos)?;
    if base.len() != base_size {
        return Err(StoreError::DeltaBaseSizeMismatch {
            expected: base_size,
            got: base.len(),
        });
    }

    let mut out = Vec::with_capacity(result_size);

    while pos < delta.len() {
        let cmd = delta[pos];
        pos += 1;

        if cmd == 0 {
            return Err(StoreError::DeltaReservedOpcode);
        }

        if cmd & 0x80 != 0 {
            let mut offset: usize = 0;
            let mut size: usize = 0;
            if cmd & 0x01 != 0 {
                if pos >= delta.len() {
                    return Err(StoreError::DeltaTruncated("copy offset"));
                }
                offset |= delta[pos] as usize;
                pos += 1;
            }
            if cmd & 0x02 != 0 {
                if pos >= delta.len() {
                    return Err(StoreError::DeltaTruncated("copy offset"));
                }
                offset |= (delta[pos] as usize) << 8;
                pos += 1;
            }
            if cmd & 0x04 != 0 {
                if pos >= delta.len() {
                    return Err(StoreError::DeltaTruncated("copy offset"));
                }
                offset |= (delta[pos] as usize) << 16;
                pos += 1;
            }
            if cmd & 0x08 != 0 {
                if pos >= delta.len() {
                    return Err(StoreError::DeltaTruncated("copy offset"));
                }
                offset |= (delta[pos] as usize) << 24;
                pos += 1;
            }
            if cmd & 0x10 != 0 {
                if pos >= delta.len() {
                    return Err(StoreError::DeltaTruncated("copy size"));
                }
                size |= delta[pos] as usize;
                pos += 1;
            }
            if cmd & 0x20 != 0 {
                if pos >= delta.len() {
                    return Err(StoreError::DeltaTruncated("copy size"));
                }
                size |= (delta[pos] as usize) << 8;
                pos += 1;
            }
            if cmd & 0x40 != 0 {
                if pos >= delta.len() {
                    return Err(StoreError::DeltaTruncated("copy size"));
                }
                size |= (delta[pos] as usize) << 16;
                pos += 1;
            }
            if size == 0 {
                size = 0x10000;
            }
            if offset + size > base.len() {
                return Err(StoreError::DeltaCopyOutOfBounds {
                    offset,
                    size,
                    base_len: base.len(),
                });
            }
            out.extend_from_slice(&base[offset..offset + size]);
        } else {
            let n = cmd as usize;
            if pos + n > delta.len() {
                return Err(StoreError::DeltaTruncated("insert data"));
            }
            out.extend_from_slice(&delta[pos..pos + n]);
            pos += n;
        }
    }

    if out.len() != result_size {
        return Err(StoreError::DeltaResultSizeMismatch {
            expected: result_size,
            got: out.len(),
        });
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for &val in &[0, 1, 127, 128, 16383, 16384, 1_000_000, usize::MAX >> 1] {
            let mut buf = Vec::new();
            encode_varint(val, &mut buf);
            let mut pos = 0;
            let decoded = decode_varint(&buf, &mut pos).unwrap();
            assert_eq!(decoded, val);
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn varint_overflow_rejected() {
        let data = vec![0x80; 10];
        let mut pos = 0;
        assert!(matches!(
            decode_varint(&data, &mut pos),
            Err(StoreError::DeltaVarintOverflow)
        ));
    }

    #[test]
    fn delta_encode_decode_roundtrip() {
        let base = b"line1\nline2\nline3\nline4\nline5\nline6\nline7\nline8\n";
        let target = b"line1\nline2-modified\nline3\nline4\nline5\nline6\nline7\nline8\nline9\n";
        let delta = compute_delta(base, target);
        assert!(delta.is_some(), "similar content should produce a delta");
        let result = apply_delta(base, &delta.unwrap()).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn delta_rejected_when_dissimilar() {
        let base = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let target = b"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        assert!(compute_delta(base, target).is_none());
    }

    #[test]
    fn delta_apply_copy_only() {
        let base = b"hello world 1234567890 abcdef";
        let mut delta = Vec::new();
        encode_varint(base.len(), &mut delta);
        encode_varint(base.len(), &mut delta);
        let mut cmd: u8 = 0x80;
        let mut extra = Vec::new();
        let sz = base.len() as u32;
        if sz & 0xff != 0 {
            cmd |= 0x10;
            extra.push((sz & 0xff) as u8);
        }
        if sz & 0xff00 != 0 {
            cmd |= 0x20;
            extra.push(((sz >> 8) & 0xff) as u8);
        }
        delta.push(cmd);
        delta.extend_from_slice(&extra);

        let result = apply_delta(base, &delta).unwrap();
        assert_eq!(result, base);
    }

    #[test]
    fn delta_apply_insert_only() {
        let base = b"";
        let target = b"new content here";
        let mut delta = Vec::new();
        encode_varint(0, &mut delta);
        encode_varint(target.len(), &mut delta);
        delta.push(target.len() as u8);
        delta.extend_from_slice(target);

        let result = apply_delta(base, &delta).unwrap();
        assert_eq!(result, target);
    }

    #[test]
    fn delta_reserved_opcode_rejected() {
        let base = b"some base content here!!";
        let mut delta = Vec::new();
        encode_varint(base.len(), &mut delta);
        encode_varint(1, &mut delta);
        delta.push(0x00);
        assert!(matches!(
            apply_delta(base, &delta),
            Err(StoreError::DeltaReservedOpcode)
        ));
    }

    #[test]
    fn delta_copy_out_of_bounds_rejected() {
        let base = b"short base content!!";
        let mut delta = Vec::new();
        encode_varint(base.len(), &mut delta);
        encode_varint(100, &mut delta);
        delta.push(0x80 | 0x10);
        delta.push(100);
        assert!(matches!(
            apply_delta(base, &delta),
            Err(StoreError::DeltaCopyOutOfBounds { .. })
        ));
    }

    #[test]
    fn delta_base_size_mismatch_rejected() {
        let base = b"actual base";
        let mut delta = Vec::new();
        encode_varint(999, &mut delta);
        encode_varint(0, &mut delta);
        assert!(matches!(
            apply_delta(base, &delta),
            Err(StoreError::DeltaBaseSizeMismatch { .. })
        ));
    }
}
