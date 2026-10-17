//! Authenticated epoch-chain admission. A signature alone is not authority.
//!
//! An epoch whose signer differs from its predecessor's carries, by
//! `rotation_kappa`, the content identity of the succession path that
//! leads from the predecessor's signer to its own: one or more contiguous
//! dual-signed successions, encoded canonically as an array. A namespace
//! that stayed idle across several rotations therefore publishes its next
//! epoch with the whole path, and no retired key is ever asked to sign.

use kappa_types::{EpochRoot, Kappa, NamespaceRef, Succession, canonical_bytes};

use crate::{
    CryptoError,
    signed_types::{verify_epoch, verify_succession},
};

#[derive(Debug, thiserror::Error)]
pub enum EpochVerificationError {
    #[error("epoch cryptography: {0}")]
    Crypto(#[from] CryptoError),
    #[error("genesis must be epoch 1 without predecessor or rotation evidence")]
    InvalidGenesis,
    #[error("genesis signer does not match the trusted anchor")]
    UntrustedGenesis,
    #[error("epoch namespace differs from the expected namespace")]
    NamespaceMismatch,
    #[error("epoch does not immediately follow the admitted predecessor")]
    Discontinuous,
    #[error("epoch timestamp regressed")]
    TimeRegression,
    #[error("signer change requires the referenced succession path")]
    MissingSuccession,
    #[error("succession path content address, endpoints or links do not match the transition")]
    SuccessionMismatch,
    #[error("succession path link key does not derive the link's outgoing anchor")]
    SuccessionKeyMismatch,
    #[error("succession is not effective at this epoch")]
    SuccessionNotEffective,
    #[error("unchanged signer must not publish rotation evidence")]
    UnexpectedSuccession,
}

/// Evidence for a signer change: the contiguous succession path from the
/// predecessor's signer to the new signer, and for each link the
/// `(algorithm, public key)` of its outgoing anchor. The incoming key of the
/// last link is the new signer's own key.
#[derive(Clone, Copy)]
pub struct SuccessionPath<'a> {
    pub links: &'a [Succession],
    pub outgoing: &'a [(&'a str, &'a [u8])],
}

/// Canonical content of a succession path: the array of its links.
pub fn succession_path_bytes(links: &[Succession]) -> Vec<u8> {
    canonical_bytes(&links.to_vec())
}

/// Content identity an epoch names in `rotation_kappa` for `links`.
pub fn succession_path_identity(links: &[Succession]) -> Kappa {
    Kappa::sha256(&succession_path_bytes(links))
}

/// An epoch admitted from a pinned genesis or an already admitted predecessor.
/// Private construction prevents callers from substituting an unsigned root
/// as the authority for a subsequent signer transition.
#[derive(Debug, Clone)]
pub struct VerifiedEpoch {
    root: EpochRoot,
}

impl VerifiedEpoch {
    pub fn root(&self) -> &EpochRoot {
        &self.root
    }

    pub fn admit_genesis(
        root: EpochRoot,
        namespace: &NamespaceRef,
        trusted_anchor: &Kappa,
        public_key: &[u8],
    ) -> Result<Self, EpochVerificationError> {
        if root.namespace_id() != namespace.id() {
            return Err(EpochVerificationError::NamespaceMismatch);
        }
        if root.epoch_number() != 1
            || root.prev_identifier().is_some()
            || root.rotation_kappa().is_some()
        {
            return Err(EpochVerificationError::InvalidGenesis);
        }
        if root.signer_anchor() != trusted_anchor {
            return Err(EpochVerificationError::UntrustedGenesis);
        }
        verify_epoch(&root, public_key)?;
        Ok(Self { root })
    }

    pub fn admit_successor(
        &self,
        root: EpochRoot,
        public_key: &[u8],
        path: Option<SuccessionPath<'_>>,
    ) -> Result<Self, EpochVerificationError> {
        check_successor(&self.root, &root, public_key, path)?;
        Ok(Self { root })
    }
}

/// The one rule admitting `root` as the immediate successor of `previous`:
/// same namespace, the next number linked to `previous`, no time regression,
/// and either the same signer without rotation evidence or a signer change
/// carried by the referenced succession path. The path must start at the
/// previous signer, end at `root`'s signer, be contiguous with
/// non-decreasing effective times, be fully effective by `root`'s timestamp,
/// and every link must verify under keys that derive its anchors. `root`
/// must verify under `public_key`.
///
/// Replay admits history through this rule, and publication checks every
/// epoch it signs against it, so the two cannot diverge.
pub fn check_successor(
    previous: &EpochRoot,
    root: &EpochRoot,
    public_key: &[u8],
    path: Option<SuccessionPath<'_>>,
) -> Result<(), EpochVerificationError> {
    if root.namespace_id() != previous.namespace_id() {
        return Err(EpochVerificationError::NamespaceMismatch);
    }
    if previous.epoch_number().checked_add(1) != Some(root.epoch_number())
        || root.prev_identifier() != Some(previous.kappa())
    {
        return Err(EpochVerificationError::Discontinuous);
    }
    if root.timestamp_ms() < previous.timestamp_ms() {
        return Err(EpochVerificationError::TimeRegression);
    }
    if root.signer_anchor() == previous.signer_anchor() {
        if root.rotation_kappa().is_some() || path.is_some() {
            return Err(EpochVerificationError::UnexpectedSuccession);
        }
    } else {
        let reference = root
            .rotation_kappa()
            .ok_or(EpochVerificationError::MissingSuccession)?;
        let path = path.ok_or(EpochVerificationError::MissingSuccession)?;
        check_path(previous.signer_anchor(), root, reference, public_key, path)?;
    }
    verify_epoch(root, public_key)?;
    Ok(())
}

fn check_path(
    from: &Kappa,
    root: &EpochRoot,
    reference: &Kappa,
    public_key: &[u8],
    path: SuccessionPath<'_>,
) -> Result<(), EpochVerificationError> {
    let (Some(first), Some(last)) = (path.links.first(), path.links.last()) else {
        return Err(EpochVerificationError::SuccessionMismatch);
    };
    if path.outgoing.len() != path.links.len()
        || &succession_path_identity(path.links) != reference
        || &first.old_anchor != from
        || &last.new_anchor != root.signer_anchor()
    {
        return Err(EpochVerificationError::SuccessionMismatch);
    }
    for pair in path.links.windows(2) {
        if pair[0].new_anchor != pair[1].old_anchor
            || pair[1].effective_at_ms < pair[0].effective_at_ms
        {
            return Err(EpochVerificationError::SuccessionMismatch);
        }
    }
    if last.effective_at_ms > root.timestamp_ms() {
        return Err(EpochVerificationError::SuccessionNotEffective);
    }
    for (index, (link, (algorithm, outgoing))) in
        path.links.iter().zip(path.outgoing.iter()).enumerate()
    {
        if Kappa::from_key(algorithm, outgoing).map_err(CryptoError::from)? != link.old_anchor {
            return Err(EpochVerificationError::SuccessionKeyMismatch);
        }
        let incoming = path
            .outgoing
            .get(index + 1)
            .map_or(public_key, |(_, key)| *key);
        verify_succession(link, outgoing, incoming)?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "epoch_verification_tests.rs"]
mod tests;
