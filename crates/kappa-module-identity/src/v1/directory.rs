//! The authenticated directory behind identity proofs.
//!
//! Every admitted assertion sets the directory label of its (subject,
//! facet) to the assertion's content identity, and every revocation of
//! the assertion a label currently names retracts it, so a client can
//! obtain a proof bound to this node's signed epoch that an assertion
//! exists for the pair, that it was retracted at an epoch, or that none
//! ever existed. The proofs are `kappa_transparency` records; this module
//! serves them as canonical bytes beside a readable summary.

use std::sync::Arc;

use kappa_handler::HandlerError;
use kappa_store::canonical::canonical_bytes;
use kappa_transparency::{AuditProof, Directory, DirectoryError, HistoryProof, HistoryState};
use topcoat::context::Cx;
use topcoat::router::StatusCode;

pub use kappa_transparency::label;

/// The directory the server registers alongside the identity routes. A
/// missing registration is a bootstrap defect, not a request-time error.
pub fn directory(cx: &Cx) -> Arc<Directory> {
    kappa_handler::service::<Arc<Directory>>(cx).clone()
}

/// HTTP form of a directory failure.
pub fn directory_error(error: DirectoryError) -> HandlerError {
    match error {
        DirectoryError::Unavailable => HandlerError::protocol(
            StatusCode::SERVICE_UNAVAILABLE,
            "DirectoryRecovering",
            error.to_string(),
        ),
        DirectoryError::Rejected(reason) => HandlerError::bad_request(reason),
        DirectoryError::Store(error) => HandlerError::Store(error),
        other => HandlerError::internal(other.to_string()),
    }
}

/// Recover the directory in the background after a publication left it
/// unavailable, so the next request finds the committed state.
pub fn recover_in_background(directory: Arc<Directory>) {
    tokio::task::spawn_blocking(move || {
        if let Err(error) = directory.recover() {
            tracing::error!(%error, "identity directory recovery failed");
        }
    });
}

/// The node's signing anchor and key, so a client can verify the proof's
/// epoch signature and check the key against the anchor it names.
fn signer_json(cx: &Cx) -> Result<serde_json::Value, HandlerError> {
    let node = kappa_handler::try_service::<Arc<kappa_crypto::NodeIdentity>>(cx)
        .ok_or_else(|| HandlerError::internal("node identity not bootstrapped"))?;
    node.with_authority(|authority| {
        serde_json::json!({
            "anchor": authority.anchor().to_string(),
            "algorithm": authority.signer().algorithm(),
            "public_key": hex::encode(authority.signer().public_key()),
        })
    })
    .map_err(|error| HandlerError::internal(format!("node identity: {error}")))
}

/// JSON form of a history proof: the readable state beside the canonical
/// proof bytes a client verifies.
pub fn history_json(cx: &Cx, proof: &HistoryProof) -> Result<serde_json::Value, HandlerError> {
    let leaf = proof.leaf.as_ref();
    Ok(serde_json::json!({
        "namespace": hex::encode(directory(cx).namespace().id()),
        "state": proof.state.as_str(),
        "exists": matches!(proof.state, HistoryState::Active),
        "epoch": proof.binding.commitment.epoch,
        "value": leaf.map(|leaf| leaf.entry.value.to_string()),
        "version": leaf.map(|leaf| leaf.entry.version),
        "first_epoch": leaf.map(|leaf| leaf.entry.first_epoch),
        "retracted_at": leaf.and_then(|leaf| leaf.entry.retracted_at),
        "signer": signer_json(cx)?,
        "proof": hex::encode(canonical_bytes(proof)),
    }))
}

/// JSON form of an audit proof.
pub fn audit_json(cx: &Cx, proof: &AuditProof) -> Result<serde_json::Value, HandlerError> {
    let transitions: Vec<serde_json::Value> = proof
        .transitions
        .iter()
        .map(|step| {
            serde_json::json!({
                "index": step.index,
                "label": hex::encode(step.transition.label.as_ref()),
                "value": step.transition.value.as_ref().map(ToString::to_string),
                "version": step.transition.version,
                "epoch": step.transition.epoch,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "namespace": hex::encode(directory(cx).namespace().id()),
        "from_epoch": proof.from.commitment.epoch,
        "to_epoch": proof.to.commitment.epoch,
        "offset": proof.offset,
        "next": proof.next,
        "transitions": transitions,
        "signer": signer_json(cx)?,
        "proof": hex::encode(canonical_bytes(proof)),
    }))
}
