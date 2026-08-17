//! CAR (Content Addressable aRchive) v1 encode/decode.
//!
//! CAR v1 format:
//!   varint(header_len) + header_cbor + blocks...
//!   header: { version: 1, roots: [CID, ...] }
//!   block:  varint(cid_len + data_len) + cid_bytes + data_bytes
//!
//! CIDs in CAR files are raw binary (36 bytes for CIDv1+sha256).
//!
//! Source: bluesky-social/atproto packages/repo/src/car.ts

/// A single block in a CAR file: CID bytes + content bytes.
#[derive(Debug, Clone)]
pub struct CarBlock {
    /// Raw CID bytes (typically 36 bytes for CIDv1+dag-cbor+sha256).
    pub cid: Vec<u8>,
    /// The block content.
    pub bytes: Vec<u8>,
}

/// Maximum block size to prevent DoS from malicious CAR files (256 MiB).
const MAX_BLOCK_SIZE: usize = 256 * 1024 * 1024;

/// Maximum number of roots in a CAR header.
const MAX_ROOTS: usize = 16;

/// Encode a CAR v1 file from a root CID and a sequence of blocks.
///
/// The header contains `{ version: 1, roots: [root] }` encoded as
/// minimal CBOR. Blocks are appended with varint length prefixes.
pub fn encode_car(root: Option<&[u8]>, blocks: &[CarBlock]) -> Vec<u8> {
    let mut out = Vec::new();

    // Encode header as minimal CBOR map: { "version": 1, "roots": [...] }
    // We hand-encode to avoid a CBOR library dependency.
    let header = encode_car_header(root);
    encode_varint(header.len() as u64, &mut out);
    out.extend_from_slice(&header);

    // Encode each block
    for block in blocks {
        let block_len = block.cid.len() + block.bytes.len();
        encode_varint(block_len as u64, &mut out);
        out.extend_from_slice(&block.cid);
        out.extend_from_slice(&block.bytes);
    }

    out
}

/// Decode a CAR v1 file into roots and blocks.
///
/// Enforces per-block size limits to prevent memory exhaustion.
pub fn decode_car(data: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<CarBlock>), CarError> {
    let mut pos = 0;

    // Read header
    let header_len = read_varint(data, &mut pos)? as usize;
    if pos + header_len > data.len() {
        return Err(CarError::Truncated("header extends past end of data"));
    }
    let header_bytes = &data[pos..pos + header_len];
    pos += header_len;

    let roots = decode_car_header(header_bytes)?;

    // Read blocks
    let mut blocks = Vec::new();
    while pos < data.len() {
        let block_len = read_varint(data, &mut pos)? as usize;
        if block_len > MAX_BLOCK_SIZE {
            return Err(CarError::BlockTooLarge(block_len));
        }
        if pos + block_len > data.len() {
            return Err(CarError::Truncated("block extends past end of data"));
        }

        // CID is the first 36 bytes (CIDv1 + sha256)
        // In practice, CID length varies, but for atproto it's always 36.
        let cid_len = detect_cid_len(&data[pos..pos + block_len])?;
        let cid = data[pos..pos + cid_len].to_vec();
        let block_bytes = data[pos + cid_len..pos + block_len].to_vec();
        pos += block_len;

        blocks.push(CarBlock {
            cid,
            bytes: block_bytes,
        });
    }

    Ok((roots, blocks))
}

/// Detect the length of a CID at the start of a byte slice.
///
/// CIDv1: version(1) + codec(varint) + hash_func(varint) + hash_len(varint) + hash
/// For dag-cbor + sha256: 1 + 1 + 1 + 1 + 32 = 36 bytes
fn detect_cid_len(data: &[u8]) -> Result<usize, CarError> {
    if data.is_empty() {
        return Err(CarError::Truncated("empty CID"));
    }

    let mut pos = 0;

    // CIDv1 version byte
    if data[pos] == 0x01 {
        pos += 1;
        // codec varint
        let _codec = read_varint(data, &mut pos)?;
        // multihash: function code varint + length varint + digest
        let _hash_func = read_varint(data, &mut pos)?;
        let hash_len = read_varint(data, &mut pos)? as usize;
        pos += hash_len;
        if pos > data.len() {
            return Err(CarError::Truncated("CID hash extends past block"));
        }
        Ok(pos)
    } else if data[pos] == 0x12 {
        // CIDv0 (raw sha256 multihash): 0x12 0x20 + 32 bytes = 34
        pos += 1;
        if pos >= data.len() {
            return Err(CarError::Truncated("CIDv0 too short"));
        }
        let hash_len = data[pos] as usize;
        pos += 1 + hash_len;
        if pos > data.len() {
            return Err(CarError::Truncated("CIDv0 hash extends past block"));
        }
        Ok(pos)
    } else {
        Err(CarError::InvalidCid)
    }
}

// -- CBOR header encode/decode (minimal, hand-rolled) -------------------------

/// Encode the CAR header as CBOR: { "roots": [CID...], "version": 1 }
///
/// CBOR map with 2 entries. Keys are strings. Values are array of
/// CBOR tag 42 (CID) and unsigned integer 1.
fn encode_car_header(root: Option<&[u8]>) -> Vec<u8> {
    let mut buf = Vec::new();

    // CBOR map with 2 entries
    buf.push(0xA2);

    // Key "roots" (5 bytes)
    encode_cbor_string("roots", &mut buf);

    // Value: array of CIDs
    match root {
        Some(cid) => {
            buf.push(0x81); // array of 1
            // CBOR Tag 42 for CID
            buf.push(0xD8);
            buf.push(42);
            // CID as byte string (with 0x00 identity multibase prefix)
            let cid_with_prefix_len = 1 + cid.len();
            encode_cbor_bytes_header(cid_with_prefix_len, &mut buf);
            buf.push(0x00); // identity multibase prefix
            buf.extend_from_slice(cid);
        }
        None => {
            buf.push(0x80); // empty array
        }
    }

    // Key "version"
    encode_cbor_string("version", &mut buf);
    // Value: 1
    buf.push(0x01);

    buf
}

/// Decode the CAR header CBOR to extract root CIDs.
///
/// We parse just enough CBOR to extract the roots array.
/// The header is always a map with "roots" and "version" keys.
fn decode_car_header(data: &[u8]) -> Result<Vec<Vec<u8>>, CarError> {
    // Very minimal CBOR parsing -- we look for the roots array
    // by finding the "roots" key in the map.
    let mut pos = 0;
    if pos >= data.len() {
        return Err(CarError::InvalidHeader);
    }

    let major = data[pos] >> 5;
    let additional = data[pos] & 0x1F;
    if major != 5 {
        // not a map
        return Err(CarError::InvalidHeader);
    }
    pos += 1;

    let map_len = if additional < 24 {
        additional as usize
    } else {
        return Err(CarError::InvalidHeader);
    };

    let mut roots = Vec::new();
    let mut found_version = false;

    for _ in 0..map_len {
        // Read key (text string)
        let key = read_cbor_string(data, &mut pos)?;

        if key == "roots" {
            // Read array of CIDs
            if pos >= data.len() {
                return Err(CarError::InvalidHeader);
            }
            let arr_major = data[pos] >> 5;
            let arr_len = (data[pos] & 0x1F) as usize;
            if arr_major != 4 {
                return Err(CarError::InvalidHeader);
            }
            pos += 1;

            if arr_len > MAX_ROOTS {
                return Err(CarError::TooManyRoots(arr_len));
            }

            for _ in 0..arr_len {
                let cid = read_cbor_cid(data, &mut pos)?;
                roots.push(cid);
            }
        } else if key == "version" {
            // Read unsigned integer
            if pos >= data.len() {
                return Err(CarError::InvalidHeader);
            }
            let version = data[pos] as u64;
            pos += 1;
            if version != 1 {
                return Err(CarError::UnsupportedVersion(version));
            }
            found_version = true;
        } else {
            // Skip unknown value
            skip_cbor_value(data, &mut pos)?;
        }
    }

    if !found_version {
        return Err(CarError::InvalidHeader);
    }

    Ok(roots)
}

fn read_cbor_string<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a str, CarError> {
    if *pos >= data.len() {
        return Err(CarError::Truncated("CBOR string"));
    }
    let major = data[*pos] >> 5;
    let additional = data[*pos] & 0x1F;
    if major != 3 {
        return Err(CarError::InvalidHeader);
    }
    *pos += 1;

    let len = if additional < 24 {
        additional as usize
    } else if additional == 24 {
        if *pos >= data.len() {
            return Err(CarError::Truncated("CBOR string length"));
        }
        let l = data[*pos] as usize;
        *pos += 1;
        l
    } else {
        return Err(CarError::InvalidHeader);
    };

    if *pos + len > data.len() {
        return Err(CarError::Truncated("CBOR string data"));
    }
    let s = std::str::from_utf8(&data[*pos..*pos + len])
        .map_err(|_| CarError::InvalidHeader)?;
    *pos += len;
    Ok(s)
}

fn read_cbor_cid(data: &[u8], pos: &mut usize) -> Result<Vec<u8>, CarError> {
    if *pos + 1 >= data.len() {
        return Err(CarError::Truncated("CBOR CID tag"));
    }
    // Expect Tag 42 (0xD8 0x2A)
    if data[*pos] == 0xD8 && data[*pos + 1] == 42 {
        *pos += 2;
    } else {
        return Err(CarError::InvalidCid);
    }

    // Read byte string containing the CID
    if *pos >= data.len() {
        return Err(CarError::Truncated("CBOR CID bytes"));
    }
    let major = data[*pos] >> 5;
    let additional = data[*pos] & 0x1F;
    if major != 2 {
        return Err(CarError::InvalidCid);
    }
    *pos += 1;

    let len = if additional < 24 {
        additional as usize
    } else if additional == 24 {
        if *pos >= data.len() {
            return Err(CarError::Truncated("CBOR CID length"));
        }
        let l = data[*pos] as usize;
        *pos += 1;
        l
    } else {
        return Err(CarError::InvalidCid);
    };

    if *pos + len > data.len() {
        return Err(CarError::Truncated("CBOR CID data"));
    }
    let cid_bytes = &data[*pos..*pos + len];
    *pos += len;

    // Strip the 0x00 identity multibase prefix if present
    if !cid_bytes.is_empty() && cid_bytes[0] == 0x00 {
        Ok(cid_bytes[1..].to_vec())
    } else {
        Ok(cid_bytes.to_vec())
    }
}

fn skip_cbor_value(data: &[u8], pos: &mut usize) -> Result<(), CarError> {
    if *pos >= data.len() {
        return Err(CarError::Truncated("CBOR value"));
    }
    let major = data[*pos] >> 5;
    let additional = data[*pos] & 0x1F;
    *pos += 1;

    match major {
        0 | 1 => {
            // unsigned/negative integer
            if additional >= 24 && additional <= 27 {
                let extra = 1 << (additional - 24);
                *pos += extra;
            }
        }
        2 | 3 => {
            // byte string / text string
            let len = if additional < 24 {
                additional as usize
            } else if additional == 24 {
                let l = data.get(*pos).copied().ok_or(CarError::Truncated("skip len"))? as usize;
                *pos += 1;
                l
            } else {
                return Err(CarError::InvalidHeader);
            };
            *pos += len;
        }
        4 => {
            // array
            let len = additional as usize;
            for _ in 0..len {
                skip_cbor_value(data, pos)?;
            }
        }
        5 => {
            // map
            let len = additional as usize;
            for _ in 0..len {
                skip_cbor_value(data, pos)?; // key
                skip_cbor_value(data, pos)?; // value
            }
        }
        6 => {
            // tag
            skip_cbor_value(data, pos)?;
        }
        7 => {
            // simple values / float
        }
        _ => {}
    }
    Ok(())
}

fn encode_cbor_string(s: &str, buf: &mut Vec<u8>) {
    let len = s.len();
    if len < 24 {
        buf.push(0x60 | len as u8);
    } else {
        buf.push(0x78);
        buf.push(len as u8);
    }
    buf.extend_from_slice(s.as_bytes());
}

fn encode_cbor_bytes_header(len: usize, buf: &mut Vec<u8>) {
    if len < 24 {
        buf.push(0x40 | len as u8);
    } else if len < 256 {
        buf.push(0x58);
        buf.push(len as u8);
    } else {
        buf.push(0x59);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

// -- Varint encode/decode (unsigned LEB128) -----------------------------------

fn encode_varint(mut n: u64, buf: &mut Vec<u8>) {
    loop {
        let byte = (n & 0x7F) as u8;
        n >>= 7;
        if n == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

fn read_varint(data: &[u8], pos: &mut usize) -> Result<u64, CarError> {
    let mut n: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if *pos >= data.len() {
            return Err(CarError::Truncated("varint"));
        }
        let byte = data[*pos];
        *pos += 1;
        n |= ((byte & 0x7F) as u64) << shift;
        if byte < 0x80 {
            return Ok(n);
        }
        shift += 7;
        if shift > 63 {
            return Err(CarError::VarintOverflow);
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CarError {
    #[error("CAR data truncated: {0}")]
    Truncated(&'static str),
    #[error("block too large: {0} bytes")]
    BlockTooLarge(usize),
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        for n in [0u64, 1, 127, 128, 255, 256, 16383, 16384, 1_000_000] {
            let mut buf = Vec::new();
            encode_varint(n, &mut buf);
            let mut pos = 0;
            let decoded = read_varint(&buf, &mut pos).unwrap();
            assert_eq!(decoded, n, "varint roundtrip failed for {}", n);
            assert_eq!(pos, buf.len());
        }
    }

    #[test]
    fn car_encode_decode_roundtrip() {
        let cid = crate::cid::cid_for_cbor(b"block content");
        let blocks = vec![CarBlock {
            cid: cid.to_vec(),
            bytes: b"block content".to_vec(),
        }];
        let encoded = encode_car(Some(&cid), &blocks);
        let (roots, decoded_blocks) = decode_car(&encoded).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], cid);
        assert_eq!(decoded_blocks.len(), 1);
        assert_eq!(decoded_blocks[0].cid, cid);
        assert_eq!(decoded_blocks[0].bytes, b"block content");
    }

    #[test]
    fn car_empty_roots() {
        let encoded = encode_car(None, &[]);
        let (roots, blocks) = decode_car(&encoded).unwrap();
        assert!(roots.is_empty());
        assert!(blocks.is_empty());
    }

    #[test]
    fn car_multiple_blocks() {
        let cid1 = crate::cid::cid_for_cbor(b"one");
        let cid2 = crate::cid::cid_for_cbor(b"two");
        let cid3 = crate::cid::cid_for_cbor(b"three");
        let blocks = vec![
            CarBlock { cid: cid1.to_vec(), bytes: b"one".to_vec() },
            CarBlock { cid: cid2.to_vec(), bytes: b"two".to_vec() },
            CarBlock { cid: cid3.to_vec(), bytes: b"three".to_vec() },
        ];
        let encoded = encode_car(Some(&cid1), &blocks);
        let (roots, decoded) = decode_car(&encoded).unwrap();
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
        // Truncate the encoded data
        let truncated = &encoded[..encoded.len() / 2];
        assert!(decode_car(truncated).is_err());
    }
}
