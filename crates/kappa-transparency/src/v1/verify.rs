//! Proof verification, from bytes and the node's signing key alone.
//!
//! `*_structure` functions check everything except the epoch signature
//! and return the admitted root, so a verifier that establishes the
//! root's authority another way (the node itself, against its own
//! admitted epoch) reuses the same checks; the plain functions add the
//! signature check under `public_key`.

use kappa_types::canonical::canonical_bytes;
use kappa_types::epoch::MutationOp;
use kappa_types::epoch_root::EpochRoot;
use kappa_types::kappa::Kappa;
use kappa_types::merkle::EMPTY_ROOT;
use kappa_types::merkle_index;

use crate::directory::COMMITMENT_TAG;
use crate::error::DirectoryError;
use crate::proof::{AuditProof, EpochBinding, HistoryProof, HistoryState, LeafProof, path_nodes};
use crate::record::Commitment;

fn refuse(reason: impl Into<String>) -> DirectoryError {
    DirectoryError::Verification(reason.into())
}

/// Check a binding's structure and return its root.
///
/// The root parses and belongs to `namespace_id`, the mutation is a
/// `TagSet` of the commitment tag
/// included under the root's `mutations_root` at the claimed index, the
/// mutation names the commitment bytes, and the commitment's epoch is
/// the root's.
pub fn binding_structure(
    binding: &EpochBinding,
    namespace_id: &[u8; 16],
) -> Result<EpochRoot, DirectoryError> {
    let root = EpochRoot::from_bytes(binding.epoch_root.as_ref())
        .map_err(|error| refuse(format!("epoch root: {error}")))?;
    if root.namespace_id() != namespace_id.as_slice() {
        return Err(refuse("epoch root belongs to another namespace"));
    }
    if root.epoch_number() != binding.commitment.epoch {
        return Err(refuse("commitment epoch differs from the epoch root"));
    }
    if binding.mutation.op != MutationOp::TagSet
        || binding.mutation.context.as_deref() != Some(COMMITMENT_TAG)
    {
        return Err(refuse("binding mutation is not the commitment tag"));
    }
    let commitment_kappa = Kappa::sha256(&canonical_bytes(&binding.commitment));
    if binding.mutation.kappa != commitment_kappa {
        return Err(refuse("binding mutation does not name the commitment"));
    }
    let mutations_root: [u8; 32] = root
        .mutations_root()
        .try_into()
        .map_err(|_| refuse("mutations root is not 32 bytes"))?;
    let path = path_nodes(&binding.mutation_path)?;
    // `mutation_index` and `mutation_count` are the prover's; the root does
    // not commit a mutation count. The binding claims membership only, and
    // a path from the domain-separated leaf hash to `mutations_root` proves
    // the mutation is a leaf of that tree under any size the path verifies
    // under (`merkle_index`). No position is relied on here; the positional
    // checks (map adjacency, log pages) take their sizes from the signed
    // commitment.
    if !merkle_index::inclusion_verify(
        &mutations_root,
        &canonical_bytes(&binding.mutation),
        binding.mutation_index,
        binding.mutation_count,
        &path,
    ) {
        return Err(refuse(
            "binding mutation is not included under the epoch's mutations root",
        ));
    }
    Ok(root)
}

/// `binding_structure` plus the root's signature under `public_key`.
pub fn binding(
    binding: &EpochBinding,
    namespace_id: &[u8; 16],
    public_key: &[u8],
) -> Result<EpochRoot, DirectoryError> {
    let root = binding_structure(binding, namespace_id)?;
    kappa_crypto::signed_types::verify_epoch(&root, public_key)
        .map_err(|error| refuse(format!("epoch signature: {error}")))?;
    Ok(root)
}

fn leaf_included(leaf: &LeafProof, commitment: &Commitment) -> Result<(), DirectoryError> {
    let path = path_nodes(&leaf.path)?;
    if !merkle_index::inclusion_verify(
        &commitment.map_root_bytes()?,
        &canonical_bytes(&leaf.entry),
        leaf.index,
        commitment.leaf_count,
        &path,
    ) {
        return Err(refuse(format!(
            "map leaf {} is not included under the committed map root",
            leaf.index
        )));
    }
    Ok(())
}

/// Check a history proof's structure against its binding; returns the
/// label's state and the root.
pub fn history_structure(
    proof: &HistoryProof,
    namespace_id: &[u8; 16],
) -> Result<(HistoryState, EpochRoot), DirectoryError> {
    let root = binding_structure(&proof.binding, namespace_id)?;
    let commitment = &proof.binding.commitment;
    let label = proof.label.as_ref();
    match proof.state {
        HistoryState::Active | HistoryState::Retracted => {
            if proof.left.is_some() || proof.right.is_some() {
                return Err(refuse("a membership proof carries neighbour leaves"));
            }
            let leaf = proof
                .leaf
                .as_ref()
                .ok_or_else(|| refuse("membership proof without its leaf"))?;
            if leaf.entry.label.as_ref() != label {
                return Err(refuse("membership leaf carries another label"));
            }
            leaf_included(leaf, commitment)?;
            let retracted = leaf.entry.retracted_at.is_some();
            if retracted != matches!(proof.state, HistoryState::Retracted) {
                return Err(refuse("leaf retraction disagrees with the claimed state"));
            }
        }
        HistoryState::NeverAsserted => {
            if proof.leaf.is_some() {
                return Err(refuse("an absence proof carries a leaf for the label"));
            }
            match (&proof.left, &proof.right) {
                (None, None) => {
                    if commitment.leaf_count != 0 || commitment.map_root_bytes()? != EMPTY_ROOT {
                        return Err(refuse("absence without neighbours in a non-empty map"));
                    }
                }
                (left, right) => {
                    let expected_right = match left {
                        Some(left) => {
                            if left.entry.label.as_ref() >= label {
                                return Err(refuse("left neighbour is not below the label"));
                            }
                            leaf_included(left, commitment)?;
                            left.index
                                .checked_add(1)
                                .ok_or_else(|| refuse("left neighbour index has no successor"))?
                        }
                        None => 0,
                    };
                    match right {
                        Some(right) => {
                            if right.entry.label.as_ref() <= label {
                                return Err(refuse("right neighbour is not above the label"));
                            }
                            if right.index != expected_right {
                                return Err(refuse("neighbours are not adjacent"));
                            }
                            leaf_included(right, commitment)?;
                        }
                        None => {
                            if expected_right != commitment.leaf_count {
                                return Err(refuse("left neighbour is not the last leaf"));
                            }
                        }
                    }
                }
            }
        }
    }
    Ok((proof.state, root))
}

/// `history_structure` plus the epoch signature.
pub fn history(
    proof: &HistoryProof,
    namespace_id: &[u8; 16],
    public_key: &[u8],
) -> Result<(HistoryState, EpochRoot), DirectoryError> {
    let (state, root) = history_structure(proof, namespace_id)?;
    kappa_crypto::signed_types::verify_epoch(&root, public_key)
        .map_err(|error| refuse(format!("epoch signature: {error}")))?;
    Ok((state, root))
}

/// Check an audit proof's structure.
///
/// Both bindings, `from` no later than `to`, the log consistency, and
/// every transition on the page included
/// in the log at `to` at consecutive indexes from `offset`, each
/// published by an epoch in `(from, to]`.
pub fn audit_structure(
    proof: &AuditProof,
    namespace_id: &[u8; 16],
) -> Result<(EpochRoot, EpochRoot), DirectoryError> {
    let from_root = binding_structure(&proof.from, namespace_id)?;
    let to_root = binding_structure(&proof.to, namespace_id)?;
    let from = &proof.from.commitment;
    let to = &proof.to.commitment;
    if from.epoch > to.epoch {
        return Err(refuse("audit range is reversed"));
    }
    let consistency = path_nodes(&proof.consistency)?;
    if !merkle_index::consistency_verify(
        from.log_size,
        to.log_size,
        &from.log_root_bytes()?,
        &to.log_root_bytes()?,
        &consistency,
    ) {
        return Err(refuse("the earlier log is not a prefix of the later log"));
    }
    if proof.offset < from.log_size {
        return Err(refuse("audit page starts before the earlier log's end"));
    }
    let to_log_root = to.log_root_bytes()?;
    // The offset and page length are the prover's; their sum is checked,
    // so a crafted offset is refused rather than wrapping to an index the
    // later log holds.
    let overflow = || refuse("audit page extends past the largest log position");
    for (position, step) in proof.transitions.iter().enumerate() {
        let expected = proof
            .offset
            .checked_add(position as u64)
            .ok_or_else(overflow)?;
        if step.index != expected {
            return Err(refuse("audit transitions are not consecutive"));
        }
        if step.transition.epoch <= from.epoch || step.transition.epoch > to.epoch {
            return Err(refuse("audit transition was published outside the range"));
        }
        let path = path_nodes(&step.path)?;
        if !merkle_index::inclusion_verify(
            &to_log_root,
            &canonical_bytes(&step.transition),
            step.index,
            to.log_size,
            &path,
        ) {
            return Err(refuse(format!(
                "log transition {} is not included under the later log root",
                step.index
            )));
        }
    }
    let end = proof
        .offset
        .checked_add(proof.transitions.len() as u64)
        .ok_or_else(overflow)?;
    match proof.next {
        Some(next) if next != end || end >= to.log_size => {
            return Err(refuse("audit continuation does not follow the page"));
        }
        None if end != to.log_size => {
            return Err(refuse(
                "audit page ends before the later log's end without a continuation",
            ));
        }
        _ => {}
    }
    Ok((from_root, to_root))
}

/// `audit_structure` plus both epoch signatures.
pub fn audit(
    proof: &AuditProof,
    namespace_id: &[u8; 16],
    public_key: &[u8],
) -> Result<(EpochRoot, EpochRoot), DirectoryError> {
    let (from_root, to_root) = audit_structure(proof, namespace_id)?;
    for root in [&from_root, &to_root] {
        kappa_crypto::signed_types::verify_epoch(root, public_key)
            .map_err(|error| refuse(format!("epoch signature: {error}")))?;
    }
    Ok((from_root, to_root))
}
