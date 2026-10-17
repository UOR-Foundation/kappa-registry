use super::*;
use crate::{
    Signer,
    ed25519::Ed25519Signer,
    signed_types::{sign_epoch, sign_succession},
};
use kappa_types::{ClockMs, EpochRootInput, NamespaceRef, SignedPayload, SuccessionReason};

fn epoch(
    signer: &Ed25519Signer,
    number: u64,
    previous: Option<&EpochRoot>,
    rotation: Option<&Kappa>,
) -> Result<EpochRoot, Box<dyn std::error::Error>> {
    let anchor = Kappa::from_key(signer.algorithm(), signer.public_key())?;
    let ledger = Kappa::sha256(b"ledger");
    Ok(sign_epoch(
        EpochRoot::build(EpochRootInput {
            namespace: &NamespaceRef::deterministic("namespace"),
            epoch_number: number,
            prev_identifier: previous.map(EpochRoot::kappa),
            state_digest: [0; 32],
            mutations_root: [0; 32],
            timestamp: ClockMs::from_raw(i64::try_from(number)?),
            signer_anchor: &anchor,
            tag_count: 0,
            rotation_kappa: rotation,
            ledger_root: &ledger,
        }),
        signer,
    )?)
}

#[test]
fn valid_signature_from_unpinned_genesis_is_not_authority() -> Result<(), Box<dyn std::error::Error>>
{
    let signer = Ed25519Signer::from_bytes(&[1; 32])?;
    let other = Ed25519Signer::from_bytes(&[2; 32])?;
    let trusted = Kappa::from_key(other.algorithm(), other.public_key())?;
    assert!(matches!(
        VerifiedEpoch::admit_genesis(
            epoch(&signer, 1, None, None)?,
            &NamespaceRef::deterministic("namespace"),
            &trusted,
            signer.public_key()
        ),
        Err(EpochVerificationError::UntrustedGenesis)
    ));
    Ok(())
}

#[test]
fn history_requires_exact_predecessor_and_immediate_epoch_number()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::from_bytes(&[1; 32])?;
    let root = epoch(&signer, 1, None, None)?;
    let verified = VerifiedEpoch::admit_genesis(
        root.clone(),
        &NamespaceRef::deterministic("namespace"),
        root.signer_anchor(),
        signer.public_key(),
    )?;
    verified.admit_successor(
        epoch(&signer, 2, Some(&root), None)?,
        signer.public_key(),
        None,
    )?;
    assert!(matches!(
        verified.admit_successor(
            epoch(&signer, 3, Some(&root), None)?,
            signer.public_key(),
            None
        ),
        Err(EpochVerificationError::Discontinuous)
    ));
    assert!(matches!(
        verified.admit_successor(epoch(&signer, 2, None, None)?, signer.public_key(), None),
        Err(EpochVerificationError::Discontinuous)
    ));
    Ok(())
}

#[test]
fn trusted_signer_cannot_substitute_a_different_namespace() -> Result<(), Box<dyn std::error::Error>>
{
    let signer = Ed25519Signer::from_bytes(&[1; 32])?;
    let root = epoch(&signer, 1, None, None)?;
    let anchor = root.signer_anchor().clone();
    assert!(matches!(
        VerifiedEpoch::admit_genesis(
            root,
            &NamespaceRef::deterministic("other"),
            &anchor,
            signer.public_key()
        ),
        Err(EpochVerificationError::NamespaceMismatch)
    ));
    Ok(())
}

fn rotation(
    old: &Ed25519Signer,
    new: &Ed25519Signer,
    effective_at_ms: i64,
) -> Result<Succession, Box<dyn std::error::Error>> {
    Ok(sign_succession(
        Succession {
            old_anchor: Kappa::from_key(old.algorithm(), old.public_key())?,
            new_anchor: Kappa::from_key(new.algorithm(), new.public_key())?,
            reason: SuccessionReason::Rotation,
            effective_at_ms,
            chain_anchor: None,
            prev_identifier: None,
            old_cose_signature: SignedPayload::empty(),
            new_cose_signature: SignedPayload::empty(),
        },
        old,
        new,
    )?)
}

fn genesis(
    signer: &Ed25519Signer,
) -> Result<(EpochRoot, VerifiedEpoch), Box<dyn std::error::Error>> {
    let root = epoch(signer, 1, None, None)?;
    let verified = VerifiedEpoch::admit_genesis(
        root.clone(),
        &NamespaceRef::deterministic("namespace"),
        root.signer_anchor(),
        signer.public_key(),
    )?;
    Ok((root, verified))
}

#[test]
fn new_key_requires_content_addressed_dual_signed_authority_transition()
-> Result<(), Box<dyn std::error::Error>> {
    let old = Ed25519Signer::from_bytes(&[1; 32])?;
    let new = Ed25519Signer::from_bytes(&[2; 32])?;
    let (root, verified) = genesis(&old)?;
    assert!(matches!(
        verified.admit_successor(epoch(&new, 2, Some(&root), None)?, new.public_key(), None),
        Err(EpochVerificationError::MissingSuccession)
    ));
    let succession = rotation(&old, &new, 2)?;
    let links = [succession.clone()];
    let outgoing = [(old.algorithm(), old.public_key())];
    let path = SuccessionPath {
        links: &links,
        outgoing: &outgoing,
    };
    let reference = succession_path_identity(&links);
    let next = epoch(&new, 2, Some(&root), Some(&reference))?;
    let admitted = verified.admit_successor(next.clone(), new.public_key(), Some(path))?;
    admitted.admit_successor(epoch(&new, 3, Some(&next), None)?, new.public_key(), None)?;

    let mut altered = succession.clone();
    altered.effective_at_ms = 3;
    let altered_links = [altered];
    assert!(matches!(
        verified.admit_successor(
            next,
            new.public_key(),
            Some(SuccessionPath {
                links: &altered_links,
                outgoing: &outgoing
            })
        ),
        Err(EpochVerificationError::SuccessionMismatch)
    ));

    let mut forged = succession;
    forged.old_cose_signature = forged.new_cose_signature.clone();
    let forged_links = [forged];
    let reference = succession_path_identity(&forged_links);
    assert!(matches!(
        verified.admit_successor(
            epoch(&new, 2, Some(&root), Some(&reference))?,
            new.public_key(),
            Some(SuccessionPath {
                links: &forged_links,
                outgoing: &outgoing
            })
        ),
        Err(EpochVerificationError::Crypto(_))
    ));
    Ok(())
}

/// A namespace idle across A -> B -> C publishes its next epoch under C
/// with the whole path; no link may be skipped, reordered, or carry a key
/// that does not derive its outgoing anchor.
#[test]
fn idle_namespace_crosses_several_rotations_with_the_complete_path()
-> Result<(), Box<dyn std::error::Error>> {
    let a = Ed25519Signer::from_bytes(&[1; 32])?;
    let b = Ed25519Signer::from_bytes(&[2; 32])?;
    let c = Ed25519Signer::from_bytes(&[3; 32])?;
    let (root, verified) = genesis(&a)?;
    let links = [rotation(&a, &b, 2)?, rotation(&b, &c, 2)?];
    let outgoing = [
        (a.algorithm(), a.public_key()),
        (b.algorithm(), b.public_key()),
    ];
    let reference = succession_path_identity(&links);
    let next = epoch(&c, 2, Some(&root), Some(&reference))?;
    verified.admit_successor(
        next.clone(),
        c.public_key(),
        Some(SuccessionPath {
            links: &links,
            outgoing: &outgoing,
        }),
    )?;

    // Only the last link: does not start at the predecessor's signer.
    let tail = [links[1].clone()];
    let tail_reference = succession_path_identity(&tail);
    assert!(matches!(
        verified.admit_successor(
            epoch(&c, 2, Some(&root), Some(&tail_reference))?,
            c.public_key(),
            Some(SuccessionPath {
                links: &tail,
                outgoing: &outgoing[1..]
            })
        ),
        Err(EpochVerificationError::SuccessionMismatch)
    ));

    // Links out of order are not contiguous.
    let reversed = [links[1].clone(), links[0].clone()];
    let reversed_outgoing = [outgoing[1], outgoing[0]];
    assert!(matches!(
        verified.admit_successor(
            epoch(
                &c,
                2,
                Some(&root),
                Some(&succession_path_identity(&reversed))
            )?,
            c.public_key(),
            Some(SuccessionPath {
                links: &reversed,
                outgoing: &reversed_outgoing
            })
        ),
        Err(EpochVerificationError::SuccessionMismatch)
    ));

    // A key that does not derive the first link's outgoing anchor.
    let wrong_first = [(c.algorithm(), c.public_key()), outgoing[1]];
    assert!(matches!(
        verified.admit_successor(
            next,
            c.public_key(),
            Some(SuccessionPath {
                links: &links,
                outgoing: &wrong_first
            })
        ),
        Err(EpochVerificationError::SuccessionKeyMismatch)
    ));

    // The path must be effective by the epoch's timestamp.
    let late = [rotation(&a, &b, 2)?, rotation(&b, &c, 5)?];
    assert!(matches!(
        verified.admit_successor(
            epoch(&c, 2, Some(&root), Some(&succession_path_identity(&late)))?,
            c.public_key(),
            Some(SuccessionPath {
                links: &late,
                outgoing: &outgoing
            })
        ),
        Err(EpochVerificationError::SuccessionNotEffective)
    ));
    Ok(())
}
