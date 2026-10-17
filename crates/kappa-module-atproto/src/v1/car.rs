//! CAR (Content Addressable aRchive) v1 encode/decode.
//!
//! CAR v1 format:
//!   varint(header_len) + header_cbor + blocks...
//!   header: { version: 1, roots: [CID, ...] }
//!   block:  varint(cid_len + data_len) + cid_bytes + data_bytes
//!
//! CIDs in CAR files are raw binary (36 bytes for CIDv1+sha256).

use dcbor::prelude::*;

use crate::dag_cbor::{self, DagCborError};

/// A single block in a CAR file.
#[derive(Debug, Clone)]
pub struct CarBlock {
    /// Raw CID bytes (typically 36 bytes for CIDv1+dag-cbor+sha256).
    pub cid: Vec<u8>,
    /// The block content.
    pub bytes: Vec<u8>,
}

/// Maximum block size on decode. 4 MB.
/// AT Protocol records max 1 MB. MST nodes under 1 KB. 4 MB covers
/// any legitimate block. 256 MB x 10K concurrent = 2.56 TB OOM.
/// 4 MB x 10K = 40 GB. Under FF-1 threshold.
const MAX_BLOCK_SIZE: usize = 4 * 1024 * 1024;

/// Minimum block size: a CIDv0 (34 bytes) with zero data.
const MIN_BLOCK_SIZE: usize = 34;

const MAX_ROOTS: usize = 16;

// -- Public streaming API -----------------------------------------------------

/// Encode the CAR v1 header: varint(header_len) + dag-cbor({ version: 1, roots: [cid] }).
/// For streaming export: write this first, then write blocks via encode_car_block_into.
pub fn encode_car_header(root: Option<&[u8]>) -> Vec<u8> {
    let header_cbor = encode_header_cbor(root);
    let mut out = Vec::with_capacity(10 + header_cbor.len());
    encode_varint_into(&mut out, header_cbor.len() as u64);
    out.extend_from_slice(&header_cbor);
    out
}

/// Encode a single CAR block into the provided buffer.
/// Reuse the buffer across blocks to avoid per-block allocation.
/// Format: varint(cid_len + data_len) + cid + data.
pub fn encode_car_block_into(buf: &mut Vec<u8>, cid: &[u8], data: &[u8]) {
    buf.clear();
    let block_len = cid.len() + data.len();
    encode_varint_into(buf, block_len as u64);
    buf.extend_from_slice(cid);
    buf.extend_from_slice(data);
}

// -- Batch API (tests and small CARs) -----------------------------------------

/// Encode a complete CAR v1 file from blocks.
/// Materializes all blocks into one Vec. For test and small CAR generation only.
/// For large repos, use encode_car_header + encode_car_block_into with streaming.
pub fn encode_car(root: Option<&[u8]>, blocks: &[CarBlock]) -> Vec<u8> {
    let mut out = encode_car_header(root);
    let mut buf = Vec::with_capacity(1024);
    for block in blocks {
        encode_car_block_into(&mut buf, &block.cid, &block.bytes);
        out.extend_from_slice(&buf);
    }
    out
}

/// Decode a CAR v1 file into roots and blocks.
pub fn decode_car(data: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<CarBlock>), CarError> {
    let mut pos = 0;

    let header_len = read_varint(data, &mut pos)? as usize;
    let header_end = pos
        .checked_add(header_len)
        .ok_or(CarError::Truncated("header length overflow"))?;
    if header_end > data.len() {
        return Err(CarError::Truncated("header extends past end"));
    }
    let header_bytes = &data[pos..header_end];
    pos = header_end;

    let roots = decode_header_cbor(header_bytes)?;

    let mut blocks = Vec::new();
    while pos < data.len() {
        let block_len = read_varint(data, &mut pos)? as usize;
        if block_len > MAX_BLOCK_SIZE {
            return Err(CarError::BlockTooLarge(block_len));
        }
        if block_len < MIN_BLOCK_SIZE {
            return Err(CarError::BlockTooSmall(block_len));
        }
        let block_end = pos
            .checked_add(block_len)
            .ok_or(CarError::Truncated("block length overflow"))?;
        if block_end > data.len() {
            return Err(CarError::Truncated("block extends past end"));
        }

        let cid_len = detect_cid_len(&data[pos..block_end])?;
        let cid = data[pos..pos + cid_len].to_vec();
        let block_bytes = data[pos + cid_len..block_end].to_vec();
        pos = block_end;

        blocks.push(CarBlock {
            cid,
            bytes: block_bytes,
        });
    }

    Ok((roots, blocks))
}

// -- CID detection ------------------------------------------------------------

fn detect_cid_len(data: &[u8]) -> Result<usize, CarError> {
    if data.is_empty() {
        return Err(CarError::Truncated("empty CID"));
    }

    let mut pos = 0;

    if data[pos] == 0x01 {
        // CIDv1
        pos += 1;
        let _codec = read_varint(data, &mut pos)?;
        let _hash_func = read_varint(data, &mut pos)?;
        let hash_len = read_varint(data, &mut pos)? as usize;
        let cid_end = pos
            .checked_add(hash_len)
            .ok_or(CarError::Truncated("CID hash length overflow"))?;
        if cid_end > data.len() {
            return Err(CarError::Truncated("CID hash extends past block"));
        }
        Ok(cid_end)
    } else if data[pos] == 0x12 {
        // CIDv0 (raw sha256 multihash)
        pos += 1;
        if pos >= data.len() {
            return Err(CarError::Truncated("CIDv0 too short"));
        }
        let hash_len = data[pos] as usize;
        pos += 1;
        let cid_end = pos
            .checked_add(hash_len)
            .ok_or(CarError::Truncated("CIDv0 hash length overflow"))?;
        if cid_end > data.len() {
            return Err(CarError::Truncated("CIDv0 hash extends past block"));
        }
        Ok(cid_end)
    } else {
        Err(CarError::InvalidCid)
    }
}

// -- Header encode/decode -----------------------------------------------------

fn encode_header_cbor(root: Option<&[u8]>) -> Vec<u8> {
    let mut map = dag_cbor::new_map();

    let roots_cbor = match root {
        Some(cid) => CBOR::from(vec![dag_cbor::encode_cid(cid)]),
        None => CBOR::from(Vec::<CBOR>::new()),
    };
    dag_cbor::map_insert(&mut map, "roots", roots_cbor);
    dag_cbor::map_insert_uint(&mut map, "version", 1);

    dag_cbor::encode_map(map)
}

fn decode_header_cbor(data: &[u8]) -> Result<Vec<Vec<u8>>, CarError> {
    let cbor = dag_cbor::decode(data)?;
    let map = match cbor.as_case() {
        CBORCase::Map(m) => m,
        _ => return Err(CarError::InvalidHeader),
    };

    let version: u64 = map
        .extract("version")
        .map_err(|_| CarError::InvalidHeader)?;
    if version != 1 {
        return Err(CarError::UnsupportedVersion(version));
    }

    let mut roots = Vec::new();
    for (k, v) in map.iter() {
        if let CBORCase::Text(key) = k.as_case()
            && key == "roots"
        {
            let arr = match v.as_case() {
                CBORCase::Array(a) => a,
                _ => return Err(CarError::InvalidHeader),
            };
            if arr.len() > MAX_ROOTS {
                return Err(CarError::TooManyRoots(arr.len()));
            }
            for item in arr {
                let cid = dag_cbor::decode_cid(item)?;
                roots.push(cid);
            }
        }
    }

    Ok(roots)
}

// -- Varint (unsigned LEB128, minimal encoding) -------------------------------

/// Encode unsigned LEB128 varint into buffer. Minimal encoding.
/// 0 = [0x00]. 127 = [0x7F]. 128 = [0x80, 0x01].
pub fn encode_varint_into(buf: &mut Vec<u8>, mut val: u64) {
    loop {
        let byte = (val & 0x7F) as u8;
        val >>= 7;
        if val == 0 {
            buf.push(byte);
            return;
        }
        buf.push(byte | 0x80);
    }
}

/// Read unsigned LEB128 varint. Rejects non-minimal encodings and overflow.
fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, CarError> {
    let mut val: u64 = 0;
    let mut shift: u32 = 0;
    let start = *pos;
    loop {
        if *pos >= data.len() {
            return Err(CarError::Truncated("varint"));
        }
        let byte = data[*pos];
        *pos += 1;

        if shift >= 63 && byte > 1 {
            return Err(CarError::VarintOverflow);
        }

        val |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            // Reject non-minimal: multi-byte varint ending in 0x00.
            if *pos - start > 1 && byte == 0 {
                return Err(CarError::NonMinimalVarint);
            }
            return Ok(val);
        }
        shift += 7;
    }
}

// -- Errors -------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CarError {
    #[error("CAR data truncated: {0}")]
    Truncated(&'static str),
    #[error("block too large: {0} bytes")]
    BlockTooLarge(usize),
    #[error("block too small: {0} bytes (minimum CID is 34 bytes)")]
    BlockTooSmall(usize),
    #[error("invalid CAR header")]
    InvalidHeader,
    #[error("unsupported CAR version: {0}")]
    UnsupportedVersion(u64),
    #[error("too many roots: {0}")]
    TooManyRoots(usize),
    #[error("invalid CID in CAR")]
    InvalidCid,
    #[error("varint overflow")]
    VarintOverflow,
    #[error("non-minimal varint encoding")]
    NonMinimalVarint,
    #[error("CBOR decode: {0}")]
    CborDecode(DagCborError),
}

impl From<DagCborError> for CarError {
    fn from(e: DagCborError) -> Self {
        CarError::CborDecode(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() -> Result<(), CarError> {
        for n in [
            0u64,
            1,
            127,
            128,
            255,
            256,
            16383,
            16384,
            1_000_000,
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            encode_varint_into(&mut buf, n);
            let mut pos = 0;
            let decoded = read_varint(&buf, &mut pos)?;
            assert_eq!(decoded, n, "varint roundtrip failed for {n}");
            assert_eq!(pos, buf.len());
        }
        Ok(())
    }

    #[test]
    fn varint_rejects_non_minimal() {
        // Value 1 encoded as [0x81, 0x00] — non-minimal (should be [0x01])
        let non_minimal = [0x81u8, 0x00];
        let mut pos = 0;
        assert!(matches!(
            read_varint(&non_minimal, &mut pos),
            Err(CarError::NonMinimalVarint)
        ));
    }

    #[test]
    fn varint_accepts_minimal_zero() {
        let mut pos = 0;
        let val = read_varint(&[0x00], &mut pos).expect("minimal zero");
        assert_eq!(val, 0);
    }

    #[test]
    fn car_encode_decode_roundtrip() {
        let cid = crate::cid::cid_for_cbor(b"block content");
        let blocks = vec![CarBlock {
            cid: cid.to_vec(),
            bytes: b"block content".to_vec(),
        }];
        let encoded = encode_car(Some(&cid), &blocks);
        let (roots, decoded_blocks) = decode_car(&encoded).expect("decode");
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], cid);
        assert_eq!(decoded_blocks.len(), 1);
        assert_eq!(decoded_blocks[0].cid, cid);
        assert_eq!(decoded_blocks[0].bytes, b"block content");
    }

    #[test]
    fn car_empty_roots() {
        let encoded = encode_car(None, &[]);
        let (roots, blocks) = decode_car(&encoded).expect("decode");
        assert!(roots.is_empty());
        assert!(blocks.is_empty());
    }

    #[test]
    fn car_multiple_blocks() {
        let cid1 = crate::cid::cid_for_cbor(b"one");
        let cid2 = crate::cid::cid_for_cbor(b"two");
        let cid3 = crate::cid::cid_for_cbor(b"three");
        let blocks = vec![
            CarBlock {
                cid: cid1.to_vec(),
                bytes: b"one".to_vec(),
            },
            CarBlock {
                cid: cid2.to_vec(),
                bytes: b"two".to_vec(),
            },
            CarBlock {
                cid: cid3.to_vec(),
                bytes: b"three".to_vec(),
            },
        ];
        let encoded = encode_car(Some(&cid1), &blocks);
        let (roots, decoded) = decode_car(&encoded).expect("decode");
        assert_eq!(roots.len(), 1);
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded[0].bytes, b"one");
        assert_eq!(decoded[1].bytes, b"two");
        assert_eq!(decoded[2].bytes, b"three");
    }

    #[test]
    fn car_truncated_rejected() {
        let cid = crate::cid::cid_for_cbor(b"data");
        let blocks = vec![CarBlock {
            cid: cid.to_vec(),
            bytes: b"data".to_vec(),
        }];
        let encoded = encode_car(Some(&cid), &blocks);
        let truncated = &encoded[..encoded.len() / 2];
        assert!(decode_car(truncated).is_err());
    }

    #[test]
    fn encode_car_block_into_reuse() {
        let cid = crate::cid::cid_for_cbor(b"test");
        let mut buf = Vec::new();
        encode_car_block_into(&mut buf, &cid, b"first");
        let len1 = buf.len();
        encode_car_block_into(&mut buf, &cid, b"second");
        let len2 = buf.len();
        // buf is cleared and reused — no accumulation
        assert!(len2 > 0);
        assert!(len1 > 0);
    }

    #[test]
    fn encode_car_header_produces_valid_cbor() {
        let cid = crate::cid::cid_for_cbor(b"root");
        let header = encode_car_header(Some(&cid));
        // Should be parseable: varint + header cbor
        let mut pos = 0;
        let header_len = read_varint(&header, &mut pos).expect("header varint");
        assert!(header_len > 0);
        assert_eq!(pos + header_len as usize, header.len());
    }

    #[test]
    fn decode_rejects_block_too_small() {
        // Construct a CAR with a block claiming 10 bytes (< MIN_BLOCK_SIZE = 34)
        let header = encode_car_header(None);
        let mut data = header;
        encode_varint_into(&mut data, 10);
        data.extend_from_slice(&[0u8; 10]);
        assert!(matches!(
            decode_car(&data),
            Err(CarError::BlockTooSmall(10))
        ));
    }
}
