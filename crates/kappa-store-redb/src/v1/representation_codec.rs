//! Canonical dCBOR codec for [`BlobRecord`].
//!
//! Encoding is total over validated records. Decoding is bounded and
//! strict: input longer than `MAX_RECORD_BYTES` is refused before parsing,
//! membership longer than `MAX_COMPONENTS` is refused before any vector is
//! built, every key must be known, every field present and typed, and the
//! decoded record must satisfy the structural invariants.

use dcbor::prelude::*;
use kappa_types::{Kappa, StoreError};

use crate::representation::{
    AllocationId, BlobRecord, Component, MAX_COMPONENTS, MAX_RECORD_BYTES, Representation,
};

const KEY_TOTAL: u64 = 0;
const KEY_STORED: u64 = 1;
const KEY_COMPRESSION: u64 = 2;
const KEY_REPRESENTATION: u64 = 3;
const REP_INLINE: u64 = 0;
const REP_EXTERNAL: u64 = 1;
const REP_COMPOSITE: u64 = 2;
const REP_ALIAS: u64 = 3;
const REP_MANIFEST: u64 = 4;

fn membership_items(components: &[Component], cumulative: &[u64]) -> (CBOR, CBOR) {
    let identities: Vec<CBOR> = components
        .iter()
        .map(|component| CBOR::from(&component.identity))
        .collect();
    let ends: Vec<CBOR> = cumulative.iter().map(|end| CBOR::from(*end)).collect();
    (identities.into(), ends.into())
}

pub fn encode(record: &BlobRecord) -> Vec<u8> {
    let representation: CBOR = match record.representation() {
        Representation::Inline { bytes } => {
            let items: Vec<CBOR> = vec![
                CBOR::from(REP_INLINE),
                CBOR::from(ByteString::from(bytes.as_slice())),
            ];
            items.into()
        }
        Representation::External {
            allocation,
            chunk_count,
            chunk_size,
            publication_id,
            chunk_root,
        } => {
            let items: Vec<CBOR> = vec![
                CBOR::from(REP_EXTERNAL),
                CBOR::from(ByteString::from(allocation.0)),
                CBOR::from(*chunk_count),
                CBOR::from(*chunk_size),
                CBOR::from(ByteString::from(*publication_id)),
                CBOR::from(ByteString::from(*chunk_root)),
            ];
            items.into()
        }
        Representation::Alias { target } => {
            let items: Vec<CBOR> = vec![CBOR::from(REP_ALIAS), CBOR::from(target)];
            items.into()
        }
        Representation::Composite {
            components,
            cumulative,
            leaf_children,
        } => {
            let (identities, ends) = membership_items(components, cumulative);
            let items: Vec<CBOR> = vec![
                CBOR::from(REP_COMPOSITE),
                identities,
                ends,
                CBOR::from(*leaf_children),
            ];
            items.into()
        }
        Representation::Manifest {
            components,
            cumulative,
        } => {
            let (identities, ends) = membership_items(components, cumulative);
            let items: Vec<CBOR> = vec![CBOR::from(REP_MANIFEST), identities, ends];
            items.into()
        }
    };
    encode_map(
        record.total_size(),
        record.stored_size(),
        record.compression(),
        representation,
    )
}

fn encode_map(
    total_size: u64,
    stored_size: u64,
    compression: Option<&str>,
    representation: CBOR,
) -> Vec<u8> {
    let mut map = Map::new();
    map.insert(KEY_TOTAL, total_size);
    map.insert(KEY_STORED, stored_size);
    if let Some(compression) = compression {
        map.insert(KEY_COMPRESSION, compression);
    }
    map.insert(KEY_REPRESENTATION, representation);
    CBOR::from(map).to_cbor_data()
}

/// Exact encoded length of the inline record that would hold
/// `stored_size` bytes with these sizes, computed without allocating the
/// payload: the record is encoded with an empty byte string and the
/// definite-length byte-string framing is added arithmetically.
pub fn inline_encoded_len(stored_size: u64, total_size: u64, compression: Option<&str>) -> u64 {
    let items: Vec<CBOR> = vec![
        CBOR::from(REP_INLINE),
        CBOR::from(ByteString::from(Vec::new())),
    ];
    let with_empty = encode_map(total_size, stored_size, compression, items.into());
    // The empty byte string occupies one byte; a byte string of n bytes
    // occupies 1 + argument bytes + n.
    let argument_bytes: u64 = match stored_size {
        0..=23 => 0,
        24..=0xFF => 1,
        0x100..=0xFFFF => 2,
        0x1_0000..=0xFFFF_FFFF => 4,
        _ => 8,
    };
    (with_empty.len() as u64)
        .saturating_sub(1)
        .saturating_add(1 + argument_bytes)
        .saturating_add(stored_size)
}

pub fn decode(bytes: &[u8]) -> Result<BlobRecord, StoreError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(StoreError::Internal(format!(
            "blob record of {} bytes exceeds the {MAX_RECORD_BYTES} byte format limit",
            bytes.len()
        )));
    }
    let cbor = CBOR::try_from_data(bytes)
        .map_err(|error| StoreError::Internal(format!("blob record decode: {error}")))?;
    let CBORCase::Map(map) = cbor.into_case() else {
        return Err(StoreError::Internal("blob record is not a map".into()));
    };
    for (key, _) in map.iter() {
        let key: u64 = key
            .clone()
            .try_into()
            .map_err(|_| StoreError::Internal("blob record key is not an integer".into()))?;
        if ![KEY_TOTAL, KEY_STORED, KEY_COMPRESSION, KEY_REPRESENTATION].contains(&key) {
            return Err(StoreError::Internal(format!(
                "blob record has unknown key {key}"
            )));
        }
    }
    let total_size: u64 = extract(&map, KEY_TOTAL, "total size")?;
    let stored_size: u64 = extract(&map, KEY_STORED, "stored size")?;
    let compression: Option<String> = if map.contains_key(KEY_COMPRESSION) {
        Some(extract(&map, KEY_COMPRESSION, "compression")?)
    } else {
        None
    };
    let representation: CBOR = extract(&map, KEY_REPRESENTATION, "representation")?;
    let CBORCase::Array(items) = representation.into_case() else {
        return Err(StoreError::Internal(
            "blob representation is not an array".into(),
        ));
    };
    let discriminant: u64 = items
        .first()
        .cloned()
        .ok_or_else(|| StoreError::Internal("empty blob representation".into()))?
        .try_into()
        .map_err(|_| StoreError::Internal("blob representation discriminant".into()))?;
    let representation = match (discriminant, items.len()) {
        (REP_INLINE, 2) => Representation::Inline {
            bytes: byte_string(&items[1], "inline bytes")?,
        },
        (REP_EXTERNAL, 6) => Representation::External {
            allocation: AllocationId(fixed(&items[1], "allocation identity")?),
            chunk_count: items[2]
                .clone()
                .try_into()
                .map_err(|_| StoreError::Internal("chunk count".into()))?,
            chunk_size: items[3]
                .clone()
                .try_into()
                .map_err(|_| StoreError::Internal("chunk size".into()))?,
            publication_id: fixed(&items[4], "publication identity")?,
            chunk_root: fixed(&items[5], "chunk root")?,
        },
        (REP_ALIAS, 2) => Representation::Alias {
            target: items[1]
                .clone()
                .try_into()
                .map_err(|_| StoreError::Internal("alias target identity".into()))?,
        },
        (REP_COMPOSITE, 4) => {
            let leaf_children: bool = items[3]
                .clone()
                .try_into()
                .map_err(|_| StoreError::Internal("composite child kind".into()))?;
            let (components, cumulative) = decode_membership(&items[1], &items[2])?;
            Representation::Composite {
                components,
                cumulative,
                leaf_children,
            }
        }
        (REP_MANIFEST, 3) => {
            let (components, cumulative) = decode_membership(&items[1], &items[2])?;
            Representation::Manifest {
                components,
                cumulative,
            }
        }
        _ => {
            return Err(StoreError::Internal(
                "blob representation shape is unknown".into(),
            ));
        }
    };
    BlobRecord::from_parts(total_size, stored_size, compression, representation)
}

fn decode_membership(
    identities: &CBOR,
    ends: &CBOR,
) -> Result<(Vec<Component>, Vec<u64>), StoreError> {
    let CBORCase::Array(identities) = identities.clone().into_case() else {
        return Err(StoreError::Internal(
            "composite identities are not an array".into(),
        ));
    };
    let CBORCase::Array(ends) = ends.clone().into_case() else {
        return Err(StoreError::Internal(
            "composite lengths are not an array".into(),
        ));
    };
    if identities.len() != ends.len() {
        return Err(StoreError::Internal(
            "composite identity and length counts differ".into(),
        ));
    }
    if identities.is_empty() || identities.len() > MAX_COMPONENTS {
        return Err(StoreError::Internal(format!(
            "composite of {} components is outside the format limit",
            identities.len()
        )));
    }
    let mut components = Vec::with_capacity(identities.len());
    let mut cumulative = Vec::with_capacity(ends.len());
    let mut previous: u64 = 0;
    for (identity, end) in identities.into_iter().zip(ends) {
        let identity: Kappa = identity
            .try_into()
            .map_err(|_| StoreError::Internal("composite component identity".into()))?;
        let end: u64 = end
            .try_into()
            .map_err(|_| StoreError::Internal("composite component end".into()))?;
        if end <= previous {
            return Err(StoreError::Internal(
                "composite cumulative lengths do not increase".into(),
            ));
        }
        components.push(Component {
            identity,
            length: end - previous,
        });
        cumulative.push(end);
        previous = end;
    }
    Ok((components, cumulative))
}

fn extract<T: TryFrom<CBOR>>(map: &Map, key: u64, what: &str) -> Result<T, StoreError> {
    let value: CBOR = map
        .extract(key)
        .map_err(|_| StoreError::Internal(format!("blob record {what} missing")))?;
    T::try_from(value).map_err(|_| StoreError::Internal(format!("blob record {what} type")))
}

fn byte_string(value: &CBOR, what: &str) -> Result<Vec<u8>, StoreError> {
    let bytes: ByteString = value
        .clone()
        .try_into()
        .map_err(|_| StoreError::Internal(format!("{what} is not a byte string")))?;
    Ok(bytes.into())
}

fn fixed<const N: usize>(value: &CBOR, what: &str) -> Result<[u8; N], StoreError> {
    byte_string(value, what)?
        .as_slice()
        .try_into()
        .map_err(|_| StoreError::Internal(format!("{what} width")))
}
