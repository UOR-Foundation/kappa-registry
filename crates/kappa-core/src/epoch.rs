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

use crate::canonical::canonical_bytes;
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
        }
    }

    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    pub fn kappa(&self) -> String {
        kappa_from_bytes(&self.root_hash)
    }

    /// Generate a Merkle proof for a specific leaf index (0-6).
    pub fn proof_for_leaf(&self, leaf_index: usize) -> Option<Vec<([u8; 32], bool)>> {
        if leaf_index >= EPOCH_LEAF_COUNT {
            return None;
        }
        let leaves = encode_leaves(
            &self.namespace,
            self.epoch_number,
            &self.prev_root_kappa,
            &self.state_root,
            &self.mutations_root,
            self.timestamp_ms,
            &self.signer_anchor,
        );
        let leaf_refs: Vec<&[u8]> = leaves.iter().map(|l| l.as_slice()).collect();
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
    let encoded: Vec<Vec<u8>> = mutations.iter().map(|m| canonical_bytes(m)).collect();
    let leaf_refs: Vec<&[u8]> = encoded.iter().map(|e| e.as_slice()).collect();
    merkle::merkle_root(&leaf_refs).unwrap_or([0u8; 32])
}

pub fn state_merkle_root(sorted_tags: &[crate::types::TagEntry]) -> [u8; 32] {
    if sorted_tags.is_empty() {
        return [0u8; 32];
    }
    let encoded: Vec<Vec<u8>> = sorted_tags.iter().map(|t| canonical_bytes(t)).collect();
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
        assert_eq!(mutations_merkle_root(&mutations), mutations_merkle_root(&mutations));
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
}
