//! Construction of history proofs from the current state.

use dcbor::prelude::*;

use kappa_types::merkle_index;

use crate::error::DirectoryError;
use crate::proof::{EpochBinding, HistoryProof, HistoryState, LeafProof, path_bytes};
use crate::state::{DirectoryState, Position};

/// The inclusion proof of leaf `index` of `leaves`.
fn leaf_proof(
    state: &DirectoryState,
    leaves: &[&[u8]],
    index: usize,
) -> Result<LeafProof, DirectoryError> {
    let entry = state
        .entry_at(index)
        .ok_or_else(|| DirectoryError::Verification(format!("map has no leaf {index}")))?;
    let path = merkle_index::inclusion_proof(leaves, index)
        .ok_or_else(|| DirectoryError::Verification(format!("no inclusion proof for {index}")))?;
    Ok(LeafProof {
        entry: entry.clone(),
        index: index as u64,
        path: path_bytes(&path),
    })
}

/// The history proof of `label` under `binding`, from `state`.
pub(crate) fn build(
    state: &DirectoryState,
    binding: EpochBinding,
    label: &[u8],
) -> Result<HistoryProof, DirectoryError> {
    let map = state.map_leaves();
    let leaves: Vec<&[u8]> = map.iter().map(Vec::as_slice).collect();
    let mut proof = HistoryProof {
        label: ByteString::from(label),
        binding,
        state: HistoryState::NeverAsserted,
        leaf: None,
        left: None,
        right: None,
    };
    match state.position(label) {
        Position::At(index) => {
            let leaf = leaf_proof(state, &leaves, index)?;
            proof.state = if leaf.entry.is_active() {
                HistoryState::Active
            } else {
                HistoryState::Retracted
            };
            proof.leaf = Some(leaf);
        }
        Position::Between { left, right } => {
            proof.left = left
                .map(|index| leaf_proof(state, &leaves, index))
                .transpose()?;
            proof.right = right
                .map(|index| leaf_proof(state, &leaves, index))
                .transpose()?;
        }
    }
    Ok(proof)
}
