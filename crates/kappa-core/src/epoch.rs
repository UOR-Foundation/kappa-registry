//! Epoch roots as Merkle trees of dCBOR fields.
//!
//! Epoch leaf ordering (PERMANENT):
//!   leaf 0: namespace (text)
//!   leaf 1: epoch_number (unsigned)
//!   leaf 2: prev_root_kappa (text or null)
//!   leaf 3: state_root (bytes, 32-byte Merkle root over all tags)
//!   leaf 4: mutations_root (bytes, 32-byte Merkle root over mutations)
//!   leaf 5: timestamp_ms (unsigned, milliseconds since Unix epoch)
//!   leaf 6: signer_anchor (text)

use dcbor::prelude::*;

use crate::canonical::{canonical_bytes, from_canonical};
use crate::kappa::kappa_from_bytes;
use crate::merkle;
use crate::types::EpochMutation;

const EPOCH_LEAF_COUNT: usize = 7;

/// Named fields for EpochRoot construction. Eliminates positional
/// argument bugs (swapping state_root and mutations_root is visible
/// at the call site).
pub struct EpochRootFields {
    pub namespace: String,
    pub epoch_number: u64,
    pub prev_root_kappa: Option<String>,
    pub state_root: [u8; 32],
    pub mutations_root: [u8; 32],
    pub timestamp_ms: u64,
    pub signer_anchor: String,
}

#[derive(Debug, Clone)]
pub struct EpochRoot {
    pub namespace: String,
    pub epoch_number: u64,
    pub prev_root_kappa: Option<String>,
    pub state_root: [u8; 32],
    pub mutations_root: [u8; 32],
    pub timestamp_ms: u64,
    pub signer_anchor: String,
    pub root_hash: [u8; 32],
    pub signature: Vec<u8>,
    /// The 7 dCBOR-encoded Merkle leaves, stored for serialization
    /// and selective disclosure proofs.
    pub leaves: Vec<Vec<u8>>,
}

#[derive(Debug, thiserror::Error)]
pub enum EpochError {
    #[error("malformed epoch leaf data: {0}")]
    MalformedLeafData(String),
}

impl EpochRoot {
    pub fn build(fields: EpochRootFields) -> Self {
        let leaves = encode_leaves(
            &fields.namespace,
            fields.epoch_number,
            &fields.prev_root_kappa,
            &fields.state_root,
            &fields.mutations_root,
            fields.timestamp_ms,
            &fields.signer_anchor,
        );
        let leaf_refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
        let root_hash = merkle::merkle_root(&leaf_refs)
            .expect("epoch root always has EPOCH_LEAF_COUNT > 0 leaves");

        EpochRoot {
            namespace: fields.namespace,
            epoch_number: fields.epoch_number,
            prev_root_kappa: fields.prev_root_kappa,
            state_root: fields.state_root,
            mutations_root: fields.mutations_root,
            timestamp_ms: fields.timestamp_ms,
            signer_anchor: fields.signer_anchor,
            root_hash,
            signature: Vec::new(),
            leaves,
        }
    }

    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    /// Storage address of this epoch root: hash(serialized_leaf_bytes).
    ///
    /// The Merkle root is a FIELD inside the epoch (self.root_hash),
    /// not the storage address. The invariant hash(bytes_on_disk) ==
    /// storage_address requires the kappa to be hash(to_leaf_bytes()).
    /// The Merkle root is verifiable by recomputing from the leaves.
    pub fn kappa(&self) -> String {
        kappa_from_bytes(&self.to_leaf_bytes())
    }

    /// Serialize the epoch root into a recoverable byte format.
    /// Entries 0-6: the 7 dCBOR-encoded Merkle leaves.
    /// Entry 7: the signature bytes (omitted if empty/unsigned).
    /// Each entry: 4-byte big-endian length prefix followed by data.
    /// The Merkle root is computed from entries 0-6 only.
    pub fn to_leaf_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for leaf in &self.leaves {
            out.extend_from_slice(&(leaf.len() as u32).to_be_bytes());
            out.extend_from_slice(leaf);
        }
        // Append signature as 8th entry if present
        if !self.signature.is_empty() {
            out.extend_from_slice(&(self.signature.len() as u32).to_be_bytes());
            out.extend_from_slice(&self.signature);
        }
        out
    }

    /// Reconstruct an EpochRoot from serialized leaf bytes.
    /// Parses length-prefixed leaves, recomputes the Merkle root,
    /// and decodes the 7 dCBOR fields.
    pub fn from_leaf_bytes(data: &[u8]) -> Result<Self, EpochError> {
        let mut leaves = Vec::new();
        let mut cursor = 0;
        while cursor < data.len() {
            if cursor + 4 > data.len() {
                return Err(EpochError::MalformedLeafData(
                    "truncated length prefix".into(),
                ));
            }
            let len = u32::from_be_bytes([
                data[cursor],
                data[cursor + 1],
                data[cursor + 2],
                data[cursor + 3],
            ]) as usize;
            cursor += 4;
            if cursor + len > data.len() {
                return Err(EpochError::MalformedLeafData("truncated leaf data".into()));
            }
            leaves.push(data[cursor..cursor + len].to_vec());
            cursor += len;
        }
        // 7 entries = unsigned epoch, 8 entries = signed (entry 7 is signature)
        let signature = if leaves.len() == EPOCH_LEAF_COUNT + 1 {
            leaves.pop().unwrap()
        } else if leaves.len() == EPOCH_LEAF_COUNT {
            Vec::new()
        } else {
            return Err(EpochError::MalformedLeafData(format!(
                "expected {} or {} entries, got {}",
                EPOCH_LEAF_COUNT,
                EPOCH_LEAF_COUNT + 1,
                leaves.len()
            )));
        };

        // Recompute Merkle root from the 7 Merkle leaves only
        let leaf_refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
        let root_hash = merkle::merkle_root(&leaf_refs)
            .ok_or_else(|| EpochError::MalformedLeafData("empty leaves".into()))?;

        // Decode fields from dCBOR leaves
        let namespace: String =
            from_canonical(&leaves[0]).map_err(|e| EpochError::MalformedLeafData(e.to_string()))?;
        let epoch_number: u64 =
            from_canonical(&leaves[1]).map_err(|e| EpochError::MalformedLeafData(e.to_string()))?;

        // Leaf 2: prev_root_kappa is either a text string or CBOR null
        let prev_root_kappa: Option<String> = {
            let cbor = CBOR::try_from_data(&leaves[2])
                .map_err(|e| EpochError::MalformedLeafData(e.to_string()))?;
            match cbor.as_case() {
                CBORCase::Simple(dcbor::Simple::Null) => None,
                _ => Some(
                    from_canonical::<String>(&leaves[2])
                        .map_err(|e| EpochError::MalformedLeafData(e.to_string()))?,
                ),
            }
        };

        // Leaves 3 and 4 are ByteString-encoded [u8; 32]
        let state_root_cbor = CBOR::try_from_data(&leaves[3])
            .map_err(|e| EpochError::MalformedLeafData(e.to_string()))?;
        let state_root_bytes = state_root_cbor
            .as_byte_string()
            .ok_or_else(|| EpochError::MalformedLeafData("state_root not a byte string".into()))?;
        let mutations_root_cbor = CBOR::try_from_data(&leaves[4])
            .map_err(|e| EpochError::MalformedLeafData(e.to_string()))?;
        let mutations_root_bytes = mutations_root_cbor.as_byte_string().ok_or_else(|| {
            EpochError::MalformedLeafData("mutations_root not a byte string".into())
        })?;

        let timestamp_ms: u64 =
            from_canonical(&leaves[5]).map_err(|e| EpochError::MalformedLeafData(e.to_string()))?;
        let signer_anchor: String =
            from_canonical(&leaves[6]).map_err(|e| EpochError::MalformedLeafData(e.to_string()))?;

        let mut sr = [0u8; 32];
        let mut mr = [0u8; 32];
        let sr_len = 32.min(state_root_bytes.len());
        let mr_len = 32.min(mutations_root_bytes.len());
        sr[..sr_len].copy_from_slice(&state_root_bytes[..sr_len]);
        mr[..mr_len].copy_from_slice(&mutations_root_bytes[..mr_len]);

        Ok(Self {
            namespace,
            epoch_number,
            prev_root_kappa,
            state_root: sr,
            mutations_root: mr,
            timestamp_ms,
            signer_anchor,
            root_hash,
            signature,
            leaves,
        })
    }

    /// Generate a Merkle proof for a specific leaf index (0-6).
    pub fn proof_for_leaf(&self, leaf_index: usize) -> Option<Vec<([u8; 32], bool)>> {
        if leaf_index >= EPOCH_LEAF_COUNT {
            return None;
        }
        let leaf_refs: Vec<&[u8]> = self.leaves.iter().map(|l| l.as_slice()).collect();
        merkle::merkle_proof(&leaf_refs, leaf_index)
    }

    pub fn verify_leaf(&self, leaf_data: &[u8], proof: &[([u8; 32], bool)]) -> bool {
        merkle::merkle_verify(&self.root_hash, leaf_data, proof)
    }
}

fn encode_leaves(
    namespace: &str,
    epoch_number: u64,
    prev_root_kappa: &Option<String>,
    state_root: &[u8; 32],
    mutations_root: &[u8; 32],
    timestamp_ms: u64,
    signer_anchor: &str,
) -> Vec<Vec<u8>> {
    let mut leaves = Vec::with_capacity(EPOCH_LEAF_COUNT);
    leaves.push(canonical_bytes(&namespace.to_string()));
    leaves.push(canonical_bytes(&epoch_number));
    match prev_root_kappa {
        Some(k) => leaves.push(canonical_bytes(k)),
        None => {
            let null_cbor: CBOR = CBORCase::Simple(dcbor::Simple::Null).into();
            leaves.push(null_cbor.to_cbor_data());
        }
    }
    let sr: CBOR = dcbor::ByteString::from(state_root.to_vec()).into();
    leaves.push(sr.to_cbor_data());
    let mr: CBOR = dcbor::ByteString::from(mutations_root.to_vec()).into();
    leaves.push(mr.to_cbor_data());
    leaves.push(canonical_bytes(&timestamp_ms));
    leaves.push(canonical_bytes(&signer_anchor.to_string()));
    assert_eq!(leaves.len(), EPOCH_LEAF_COUNT);
    leaves
}

pub fn mutations_merkle_root(mutations: &[EpochMutation]) -> [u8; 32] {
    if mutations.is_empty() {
        return [0u8; 32];
    }
    let encoded: Vec<Vec<u8>> = mutations.iter().map(canonical_bytes).collect();
    let leaf_refs: Vec<&[u8]> = encoded.iter().map(|e| e.as_slice()).collect();
    merkle::merkle_root(&leaf_refs).unwrap_or([0u8; 32])
}

pub fn state_merkle_root(sorted_tags: &[crate::types::TagEntry]) -> [u8; 32] {
    if sorted_tags.is_empty() {
        return [0u8; 32];
    }
    let encoded: Vec<Vec<u8>> = sorted_tags.iter().map(canonical_bytes).collect();
    let leaf_refs: Vec<&[u8]> = encoded.iter().map(|e| e.as_slice()).collect();
    merkle::merkle_root(&leaf_refs).unwrap_or([0u8; 32])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MutationOp;

    fn test_fields() -> EpochRootFields {
        EpochRootFields {
            namespace: "test/ns".into(),
            epoch_number: 1,
            prev_root_kappa: None,
            state_root: [0xaa; 32],
            mutations_root: [0xbb; 32],
            timestamp_ms: 1000,
            signer_anchor: "anchor-1".into(),
        }
    }

    #[test]
    fn deterministic() {
        let r1 = EpochRoot::build(test_fields());
        let r2 = EpochRoot::build(test_fields());
        assert_eq!(r1.kappa(), r2.kappa());
    }

    #[test]
    fn changes_with_any_field() {
        let base = EpochRoot::build(test_fields());
        let different = EpochRoot::build(EpochRootFields {
            epoch_number: 2,
            ..test_fields()
        });
        assert_ne!(base.root_hash, different.root_hash);

        let different_ns = EpochRoot::build(EpochRootFields {
            namespace: "other/ns".into(),
            ..test_fields()
        });
        assert_ne!(base.root_hash, different_ns.root_hash);
    }

    #[test]
    fn kappa_format() {
        let r = EpochRoot::build(test_fields());
        assert!(r.kappa().starts_with("sha256:"));
    }

    #[test]
    fn selective_disclosure_verifies() {
        let r = EpochRoot::build(EpochRootFields {
            namespace: "ns".into(),
            epoch_number: 5,
            prev_root_kappa: None,
            state_root: [0x11; 32],
            mutations_root: [0x22; 32],
            timestamp_ms: 9999,
            signer_anchor: "signer".into(),
        });
        let proof = r.proof_for_leaf(0).unwrap();
        let ns_leaf = canonical_bytes(&"ns".to_string());
        assert!(r.verify_leaf(&ns_leaf, &proof));
    }

    #[test]
    fn selective_disclosure_rejects_wrong() {
        let r = EpochRoot::build(EpochRootFields {
            namespace: "ns".into(),
            epoch_number: 5,
            prev_root_kappa: None,
            state_root: [0x11; 32],
            mutations_root: [0x22; 32],
            timestamp_ms: 9999,
            signer_anchor: "signer".into(),
        });
        let proof = r.proof_for_leaf(0).unwrap();
        assert!(!r.verify_leaf(&canonical_bytes(&"wrong".to_string()), &proof));
    }

    #[test]
    fn mutations_merkle_root_empty() {
        assert_eq!(mutations_merkle_root(&[]), [0u8; 32]);
    }

    #[test]
    fn mutations_merkle_root_deterministic() {
        let mutations = vec![EpochMutation {
            op: MutationOp::TagSet,
            namespace: "ns".into(),
            tag_name: "tag1".into(),
            old_kappa: None,
            new_kappa: Some("sha256:aaa".into()),
        }];
        assert_eq!(
            mutations_merkle_root(&mutations),
            mutations_merkle_root(&mutations)
        );
        assert_ne!(mutations_merkle_root(&mutations), [0u8; 32]);
    }

    #[test]
    fn proof_out_of_bounds() {
        let r = EpochRoot::build(test_fields());
        assert!(r.proof_for_leaf(99).is_none());
    }

    #[test]
    fn with_signature_attaches() {
        let r = EpochRoot::build(test_fields()).with_signature(vec![1, 2, 3]);
        assert_eq!(r.signature, vec![1, 2, 3]);
    }

    #[test]
    fn leaf_bytes_roundtrip() {
        let fields = EpochRootFields {
            namespace: "test".into(),
            epoch_number: 42,
            prev_root_kappa: Some("sha256:abc".into()),
            state_root: [1u8; 32],
            mutations_root: [2u8; 32],
            timestamp_ms: 1000,
            signer_anchor: "sha256:anchor".into(),
        };
        let original = EpochRoot::build(fields);
        let bytes = original.to_leaf_bytes();
        let recovered = EpochRoot::from_leaf_bytes(&bytes).unwrap();
        assert_eq!(original.kappa(), recovered.kappa());
        assert_eq!(original.epoch_number, recovered.epoch_number);
        assert_eq!(original.namespace, recovered.namespace);
        assert_eq!(original.prev_root_kappa, recovered.prev_root_kappa);
        assert_eq!(original.state_root, recovered.state_root);
        assert_eq!(original.mutations_root, recovered.mutations_root);
        assert_eq!(original.timestamp_ms, recovered.timestamp_ms);
        assert_eq!(original.signer_anchor, recovered.signer_anchor);
    }

    #[test]
    fn leaf_bytes_roundtrip_none_prev() {
        let fields = EpochRootFields {
            namespace: "genesis".into(),
            epoch_number: 1,
            prev_root_kappa: None,
            state_root: [0u8; 32],
            mutations_root: [0u8; 32],
            timestamp_ms: 0,
            signer_anchor: "".into(),
        };
        let original = EpochRoot::build(fields);
        let bytes = original.to_leaf_bytes();
        let recovered = EpochRoot::from_leaf_bytes(&bytes).unwrap();
        assert_eq!(original.kappa(), recovered.kappa());
        assert_eq!(recovered.prev_root_kappa, None);
    }

    #[test]
    fn from_leaf_bytes_rejects_truncated() {
        assert!(EpochRoot::from_leaf_bytes(&[0, 0, 0, 5, 1, 2]).is_err());
    }

    #[test]
    fn from_leaf_bytes_rejects_wrong_leaf_count() {
        let mut data = Vec::new();
        for _ in 0..3 {
            data.extend_from_slice(&1u32.to_be_bytes());
            data.push(0);
        }
        assert!(EpochRoot::from_leaf_bytes(&data).is_err());
    }
}
