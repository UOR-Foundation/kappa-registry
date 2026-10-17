//! Epoch-committed evidence about content: framing commitments, digest
//! aliases, and compositions.
//!
//! A [`ContentCommitment`] binds, into authenticated history, the
//! parameters under which a store verifies a content identity chunk by
//! chunk: the identity, the chunk size the bytes were framed with, and the
//! [`crate::merkle::merkle_root`] over the SHA-256 digest of each plaintext
//! chunk in order. Given the bytes and the chunk size the root is
//! determined, so any party holding the bytes can recompute and check it;
//! no physical fact (where the bytes are allocated, how they are
//! encrypted) is part of the record, so relocating or re-encrypting them
//! never changes history.
//!
//! Decoding is strict: unknown keys, a zero chunk size, or a root that is
//! not 32 bytes are rejected at the decode boundary, so a decoded
//! commitment is always valid.

use dcbor::prelude::*;

use crate::error::StoreError;
use crate::kappa::Kappa;
use crate::wire_map::wire_map;

/// Portable correspondence between two verified digests of identical bytes.
/// Physical alias selection remains a derived projection of this evidence.
#[derive(Debug, Clone)]
pub struct ContentAlias {
    alias: Kappa,
    target: Kappa,
    length: u64,
}

struct ContentAliasWire {
    alias: Kappa,
    target: Kappa,
    length: u64,
}

wire_map!(ContentAliasWire {
    alias: value = 0,
    target: value = 1,
    length: value = 2,
});

impl ContentAlias {
    pub fn new(alias: Kappa, target: Kappa, length: u64) -> Result<Self, StoreError> {
        if alias == target || alias.axis() == target.axis() {
            return Err(StoreError::Rejected(
                "content aliases require distinct digest axes".into(),
            ));
        }
        Ok(Self {
            alias,
            target,
            length,
        })
    }

    pub const fn alias(&self) -> &Kappa {
        &self.alias
    }
    pub const fn target(&self) -> &Kappa {
        &self.target
    }
    pub const fn length(&self) -> u64 {
        self.length
    }
}

impl From<ContentAlias> for CBOR {
    fn from(value: ContentAlias) -> Self {
        ContentAliasWire {
            alias: value.alias,
            target: value.target,
            length: value.length,
        }
        .into()
    }
}

impl From<&ContentAlias> for CBOR {
    fn from(value: &ContentAlias) -> Self {
        value.clone().into()
    }
}

impl TryFrom<CBOR> for ContentAlias {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let wire = ContentAliasWire::try_from(cbor)?;
        Self::new(wire.alias, wire.target, wire.length)
            .map_err(|error| dcbor::Error::msg(error.to_string()))
    }
}

/// One component of a [`ContentComposition`]: a content identity and its
/// logical length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentComponent {
    pub identity: Kappa,
    pub length: u64,
}

wire_map!(ContentComponent {
    identity: value = 0,
    length: value = 1,
});

/// Portable evidence that the bytes of `identity` are the ordered
/// concatenation of `components`.
///
/// Recorded when a composite representation is installed. Only logical
/// facts are recorded: how the
/// store groups components physically (manifest nodes) is a function of
/// its descriptor limits and never part of history, so the same
/// composition is the same evidence on every store.
///
/// The same identity may be composed from different component lists (two
/// chunkings of the same bytes); every such record is true of the bytes.
///
/// Decoding is strict: unknown keys, an empty composition, an empty
/// component, a component naming the composite itself, or a length that
/// is not the exact sum of the component lengths are rejected at the
/// decode boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentComposition {
    identity: Kappa,
    components: Vec<ContentComponent>,
    length: u64,
}

impl ContentComposition {
    pub fn new(
        identity: Kappa,
        components: Vec<ContentComponent>,
        length: u64,
    ) -> Result<Self, StoreError> {
        if components.is_empty() {
            return Err(StoreError::Rejected(
                "content composition has no components".into(),
            ));
        }
        let mut total = 0u64;
        for component in &components {
            if component.length == 0 {
                return Err(StoreError::Rejected(
                    "content composition has an empty component".into(),
                ));
            }
            if component.identity == identity {
                return Err(StoreError::Rejected(
                    "content composition names itself as a component".into(),
                ));
            }
            total = total.checked_add(component.length).ok_or_else(|| {
                StoreError::CapacityExceeded("content composition length overflows".into())
            })?;
        }
        if total != length {
            return Err(StoreError::Rejected(
                "content composition length is not the sum of its components".into(),
            ));
        }
        Ok(Self {
            identity,
            components,
            length,
        })
    }

    pub const fn identity(&self) -> &Kappa {
        &self.identity
    }
    pub fn components(&self) -> &[ContentComponent] {
        &self.components
    }
    pub const fn length(&self) -> u64 {
        self.length
    }
}

/// Keys (PERMANENT): 0 identity, 1 components, 2 length.
impl From<ContentComposition> for CBOR {
    fn from(value: ContentComposition) -> Self {
        let components: Vec<Self> = value.components.into_iter().map(Self::from).collect();
        let mut map = Map::new();
        map.insert(0u64, value.identity);
        map.insert(1u64, Self::from(components));
        map.insert(2u64, value.length);
        map.into()
    }
}

impl From<&ContentComposition> for CBOR {
    fn from(value: &ContentComposition) -> Self {
        value.clone().into()
    }
}

impl TryFrom<CBOR> for ContentComposition {
    type Error = dcbor::Error;
    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = crate::resource::strict_map(cbor, &[0, 1, 2])?;
        Self::new(
            map.extract(0u64)?,
            crate::resource::array_of(map.extract(1u64)?)?,
            map.extract(2u64)?,
        )
        .map_err(|error| dcbor::Error::msg(error.to_string()))
    }
}

/// Wire shape. Keys (PERMANENT): 0 identity key bytes, 1 chunk size,
/// 2 chunk root.
struct ContentCommitmentWire {
    identity: Vec<u8>,
    chunk_size: u64,
    chunk_root: Vec<u8>,
}

wire_map!(ContentCommitmentWire {
    identity: bytes = 0,
    chunk_size: value = 1,
    chunk_root: bytes = 2,
});

/// Canonical evidence for `MutationOp::ContentPublish`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentCommitment {
    identity: Kappa,
    chunk_size: u32,
    chunk_root: [u8; 32],
}

impl ContentCommitment {
    pub fn new(identity: Kappa, chunk_size: u32, chunk_root: [u8; 32]) -> Result<Self, StoreError> {
        if chunk_size == 0 {
            return Err(StoreError::Rejected(
                "content commitment chunk size is zero".into(),
            ));
        }
        Ok(Self {
            identity,
            chunk_size,
            chunk_root,
        })
    }

    pub const fn identity(&self) -> &Kappa {
        &self.identity
    }

    pub const fn chunk_size(&self) -> u32 {
        self.chunk_size
    }

    pub const fn chunk_root(&self) -> &[u8; 32] {
        &self.chunk_root
    }
}

impl From<ContentCommitment> for CBOR {
    fn from(value: ContentCommitment) -> Self {
        ContentCommitmentWire {
            identity: value.identity.key_bytes(),
            chunk_size: u64::from(value.chunk_size),
            chunk_root: value.chunk_root.to_vec(),
        }
        .into()
    }
}

impl From<&ContentCommitment> for CBOR {
    fn from(value: &ContentCommitment) -> Self {
        value.clone().into()
    }
}

impl TryFrom<CBOR> for ContentCommitment {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let wire = ContentCommitmentWire::try_from(cbor)?;
        let identity = Kappa::from_key_bytes(&wire.identity)
            .map_err(|error| dcbor::Error::msg(format!("content commitment identity: {error}")))?;
        let chunk_size = u32::try_from(wire.chunk_size)
            .map_err(|_| dcbor::Error::msg("content commitment chunk size exceeds u32"))?;
        let chunk_root: [u8; 32] = wire
            .chunk_root
            .as_slice()
            .try_into()
            .map_err(|_| dcbor::Error::msg("content commitment root is not 32 bytes"))?;
        Self::new(identity, chunk_size, chunk_root)
            .map_err(|error| dcbor::Error::msg(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    #[test]
    fn roundtrips() -> Result<(), StoreError> {
        let commitment = ContentCommitment::new(Kappa::sha256(b"content"), 65536, [7; 32])?;
        let decoded: ContentCommitment = from_canonical(&canonical_bytes(&commitment))?;
        assert_eq!(decoded, commitment);
        assert_eq!(decoded.chunk_root(), &[7; 32]);
        assert_eq!(decoded.chunk_size(), 65536);
        Ok(())
    }

    #[test]
    fn malformed_canonical_input_is_rejected_at_decode() {
        assert!(ContentCommitment::new(Kappa::sha256(b"content"), 0, [7; 32]).is_err());
        let identity = Kappa::sha256(b"content").key_bytes();
        let encode = |chunk_size: u64, root: Vec<u8>, extra: bool| {
            let mut map = Map::new();
            map.insert(0u64, ByteString::from(identity.clone()));
            map.insert(1u64, chunk_size);
            map.insert(2u64, ByteString::from(root));
            if extra {
                map.insert(3u64, 1u64);
            }
            CBOR::from(map).to_cbor_data()
        };
        assert!(from_canonical::<ContentCommitment>(&encode(0, vec![7; 32], false)).is_err());
        assert!(from_canonical::<ContentCommitment>(&encode(1, vec![7; 31], false)).is_err());
        assert!(from_canonical::<ContentCommitment>(&encode(1, vec![7; 32], true)).is_err());
        assert!(
            from_canonical::<ContentCommitment>(&encode(
                u64::from(u32::MAX) + 1,
                vec![7; 32],
                false
            ))
            .is_err()
        );
        assert!(from_canonical::<ContentCommitment>(&encode(1, vec![7; 32], false)).is_ok());
    }

    fn component(bytes: &[u8]) -> ContentComponent {
        ContentComponent {
            identity: Kappa::sha256(bytes),
            length: bytes.len() as u64,
        }
    }

    #[test]
    fn composition_roundtrips_and_rejects_inconsistent_records() -> Result<(), StoreError> {
        let whole = Kappa::sha256(b"hello world");
        let parts = vec![component(b"hello "), component(b"world")];
        let composition = ContentComposition::new(whole.clone(), parts.clone(), 11)?;
        let decoded: ContentComposition = from_canonical(&canonical_bytes(&composition))?;
        assert_eq!(decoded, composition);
        assert_eq!(decoded.components(), parts.as_slice());

        assert!(ContentComposition::new(whole.clone(), Vec::new(), 0).is_err());
        assert!(ContentComposition::new(whole.clone(), parts.clone(), 12).is_err());
        assert!(
            ContentComposition::new(
                whole.clone(),
                vec![ContentComponent {
                    identity: Kappa::sha256(b""),
                    length: 0,
                }],
                0
            )
            .is_err()
        );
        assert!(
            ContentComposition::new(
                whole.clone(),
                vec![ContentComponent {
                    identity: whole.clone(),
                    length: 11,
                }],
                11
            )
            .is_err()
        );

        // The decode boundary enforces the same rules and admits no
        // unknown key.
        let encode = |length: u64, extra: bool| {
            let items: Vec<CBOR> = parts.iter().cloned().map(CBOR::from).collect();
            let mut map = Map::new();
            map.insert(0u64, whole.clone());
            map.insert(1u64, CBOR::from(items));
            map.insert(2u64, length);
            if extra {
                map.insert(3u64, 1u64);
            }
            CBOR::from(map).to_cbor_data()
        };
        assert!(from_canonical::<ContentComposition>(&encode(11, false)).is_ok());
        assert!(from_canonical::<ContentComposition>(&encode(10, false)).is_err());
        assert!(from_canonical::<ContentComposition>(&encode(11, true)).is_err());
        // Composition evidence is not commitment or alias evidence.
        let bytes = canonical_bytes(&composition);
        assert!(from_canonical::<ContentCommitment>(&bytes).is_err());
        assert!(from_canonical::<ContentAlias>(&bytes).is_err());
        Ok(())
    }
}
