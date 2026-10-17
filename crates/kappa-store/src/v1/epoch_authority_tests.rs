use std::sync::Arc;

use kappa_crypto::SigningAuthority;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_types::{SignedPayload, SuccessionReason};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;
type RotatedResult = Result<
    (
        EpochAuthority,
        [SigningAuthority; 3],
        Vec<AuthorityTransition>,
    ),
    Box<dyn std::error::Error>,
>;

const DOMAIN: ActivationDomain = ActivationDomain {
    control: [7; 16],
    incarnation: [8; 16],
};

fn authority(seed: u8) -> Result<SigningAuthority, Box<dyn std::error::Error>> {
    Ok(SigningAuthority::new(Arc::new(Ed25519Signer::from_bytes(
        &[seed; 32],
    )?))?)
}

fn succession(
    old: &SigningAuthority,
    new: &SigningAuthority,
    effective_at_ms: i64,
) -> Result<VerifiedSuccession, Box<dyn std::error::Error>> {
    let record = kappa_crypto::signed_types::sign_succession(
        Succession {
            old_anchor: old.anchor().clone(),
            new_anchor: new.anchor().clone(),
            reason: SuccessionReason::Rotation,
            effective_at_ms,
            chain_anchor: None,
            prev_identifier: None,
            old_cose_signature: SignedPayload::empty(),
            new_cose_signature: SignedPayload::empty(),
        },
        old.signer(),
        new.signer(),
    )?;
    Ok(VerifiedSuccession::verify(
        record,
        old.signer().algorithm(),
        old.signer().public_key(),
        new.signer().algorithm(),
        new.signer().public_key(),
    )?)
}

/// The activation of `succession` in `store`'s lineage, witnessed by the
/// signer of seed `witness`.
fn witnessed(
    store: &EpochAuthority,
    succession: &VerifiedSuccession,
    witness: u8,
) -> Result<Activation, Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::from_bytes(&[witness; 32])?;
    Ok(Activation {
        domain: DOMAIN,
        witnesses: vec![sign_witness(
            &signer,
            succession.inner(),
            store.origin().anchor(),
            DOMAIN,
            i64::MIN,
            None,
        )?],
    })
}

/// Rotate `store` to `next` through `succession`, witnessed.
fn rotate(
    store: &EpochAuthority,
    next: &SigningAuthority,
    succession: VerifiedSuccession,
    now: i64,
) -> Result<(EpochAuthority, AuthorityTransition), Box<dyn std::error::Error>> {
    let activation = witnessed(store, &succession, 42)?;
    Ok(store.rotate(next.clone(), succession, activation, ClockMs::from_raw(now))?)
}

/// A -> B effective at 100, B -> C effective at 200.
fn rotated() -> RotatedResult {
    let (a, b, c) = (authority(1)?, authority(2)?, authority(3)?);
    let start = EpochAuthority::new(a.clone())?;
    let (middle, first) = rotate(&start, &b, succession(&a, &b, 100)?, 150)?;
    let (end, second) = rotate(&middle, &c, succession(&b, &c, 200)?, 250)?;
    Ok((end, [a, b, c], vec![first, second]))
}

#[test]
fn rotation_hands_signing_to_the_next_authority_only() -> TestResult {
    let (store, [a, b, c], _) = rotated()?;
    assert_eq!(store.anchor(), c.anchor());
    assert_eq!(
        store.current().signer().public_key(),
        c.signer().public_key()
    );
    assert_eq!(store.origin().anchor(), a.anchor());
    assert_eq!(store.transitions().len(), 2);
    assert_eq!(
        store.resolve(b.anchor()).map(|(_, key)| key),
        Some(b.signer().public_key().to_vec())
    );
    Ok(())
}

#[test]
fn historical_keys_verify_only_inside_their_authority_windows() -> TestResult {
    let (store, [a, b, c], _) = rotated()?;
    assert!(store.verification_key(a.anchor(), i64::MIN).is_some());
    assert!(store.verification_key(a.anchor(), 99).is_some());
    assert!(
        store.verification_key(a.anchor(), 100).is_none(),
        "retired at its successor's effective time"
    );
    assert!(
        store.verification_key(b.anchor(), 99).is_none(),
        "not yet effective"
    );
    assert!(store.verification_key(b.anchor(), 100).is_some());
    assert!(store.verification_key(b.anchor(), 199).is_some());
    assert!(store.verification_key(b.anchor(), 200).is_none());
    assert!(store.verification_key(c.anchor(), 199).is_none());
    assert!(store.verification_key(c.anchor(), 200).is_some());
    assert!(store.verification_key(c.anchor(), i64::MAX).is_some());
    let stranger = authority(9)?;
    assert!(store.verification_key(stranger.anchor(), 150).is_none());
    Ok(())
}

#[test]
fn every_historical_signer_has_a_path_to_the_current_authority() -> TestResult {
    let (store, [a, b, c], _) = rotated()?;
    let from_a = store.path_from(a.anchor()).ok_or("no path from origin")?;
    assert_eq!(from_a.len(), 2);
    assert_eq!(&from_a[0].succession().old_anchor, a.anchor());
    assert_eq!(&from_a[1].succession().new_anchor, c.anchor());
    let from_b = store.path_from(b.anchor()).ok_or("no path from middle")?;
    assert_eq!(from_b.len(), 1);
    assert!(
        store
            .path_from(c.anchor())
            .ok_or("no path from current")?
            .is_empty()
    );
    assert!(store.path_from(authority(9)?.anchor()).is_none());
    Ok(())
}

#[test]
fn rotation_rejects_foreign_premature_regressing_and_reused_transitions() -> TestResult {
    let (a, b, c) = (authority(1)?, authority(2)?, authority(3)?);
    let start = EpochAuthority::new(a.clone())?;
    let refused = |store: &EpochAuthority, next: &SigningAuthority, succession, now| {
        rotate(store, next, succession, now)
            .err()
            .and_then(|error| error.downcast::<StoreError>().ok())
            .map(|error| *error)
    };
    // Leads from an authority this store does not hold.
    assert!(matches!(
        refused(&start, &c, succession(&b, &c, 10)?, 20),
        Some(StoreError::Conflict(_))
    ));
    // Leads somewhere other than the authority handed over.
    assert!(matches!(
        refused(&start, &c, succession(&a, &b, 10)?, 20),
        Some(StoreError::Conflict(_))
    ));
    // Not yet effective at the rotation boundary.
    assert!(matches!(
        refused(&start, &b, succession(&a, &b, 30)?, 20),
        Some(StoreError::Rejected(_))
    ));
    let (middle, _) = rotate(&start, &b, succession(&a, &b, 10)?, 20)?;
    // Effective before the transition it follows.
    assert!(matches!(
        refused(&middle, &c, succession(&b, &c, 5)?, 20),
        Some(StoreError::Rejected(_))
    ));
    // Returns to an authority that already served.
    assert!(matches!(
        refused(&middle, &a, succession(&b, &a, 15)?, 20),
        Some(StoreError::Rejected(_))
    ));
    Ok(())
}

#[test]
fn activation_requires_a_qualifying_non_self_witness() -> TestResult {
    let (a, b, c) = (authority(1)?, authority(2)?, authority(3)?);
    let start = EpochAuthority::new(a.clone())?;
    let at = ClockMs::from_raw(20);
    let refuses = |activation: Activation| -> Result<bool, Box<dyn std::error::Error>> {
        Ok(matches!(
            start.rotate(b.clone(), succession(&a, &b, 10)?, activation, at),
            Err(StoreError::Rejected(_))
        ))
    };
    let transition = succession(&a, &b, 10)?;
    assert!(
        refuses(Activation {
            domain: DOMAIN,
            witnesses: Vec::new()
        })?,
        "no witness"
    );
    // Seed 1 is the outgoing authority, seed 2 the incoming one.
    assert!(
        refuses(witnessed(&start, &transition, 1)?)?,
        "the outgoing authority witnessed"
    );
    assert!(
        refuses(witnessed(&start, &transition, 2)?)?,
        "the incoming authority witnessed"
    );
    // A witness of another succession.
    let other = succession(&a, &c, 10)?;
    assert!(
        refuses(witnessed(&start, &other, 42)?)?,
        "another succession"
    );
    // A witness for another domain.
    let mut foreign = witnessed(&start, &transition, 42)?;
    foreign.domain.incarnation = [9; 16];
    assert!(refuses(foreign)?, "another control incarnation");
    // A witness not yet valid at the effective time.
    let signer = Ed25519Signer::from_bytes(&[42; 32])?;
    let late = sign_witness(
        &signer,
        transition.inner(),
        start.origin().anchor(),
        DOMAIN,
        11,
        None,
    )?;
    assert!(
        refuses(Activation {
            domain: DOMAIN,
            witnesses: vec![late]
        })?,
        "a witness valid only after activation"
    );
    // The qualifying witness admits it.
    start.rotate(
        b.clone(),
        succession(&a, &b, 10)?,
        witnessed(&start, &transition, 42)?,
        at,
    )?;
    Ok(())
}

#[test]
fn persisted_history_is_readmitted_and_bound_to_its_origin() -> TestResult {
    let (store, [a, b, c], transitions) = rotated()?;
    let origin = AuthorityKey::from_bytes(&store.origin().to_bytes()?)?;
    let restored_transitions = transitions
        .iter()
        .map(|transition| AuthorityTransition::from_bytes(&transition.to_bytes()?, origin.anchor()))
        .collect::<Result<Vec<_>, _>>()?;
    let restored =
        EpochAuthority::restore(origin.clone(), restored_transitions.clone(), c.clone())?;
    assert_eq!(restored.anchor(), c.anchor());
    assert_eq!(restored.transitions().len(), 2);
    assert_eq!(
        restored.transitions()[0].activation(),
        transitions[0].activation()
    );

    // An omitted prefix no longer starts at the origin.
    assert!(
        EpochAuthority::restore(
            origin.clone(),
            restored_transitions[1..].to_vec(),
            c.clone()
        )
        .is_err()
    );
    // The configured authority must be the history's head.
    assert!(EpochAuthority::restore(origin.clone(), restored_transitions, b).is_err());
    // An empty history admits only the origin itself.
    assert!(EpochAuthority::restore(origin.clone(), Vec::new(), c).is_err());
    EpochAuthority::restore(origin.clone(), Vec::new(), a)?;

    // A transition's witnesses are bound to its lineage's origin.
    let stranger = authority(9)?;
    assert!(
        AuthorityTransition::from_bytes(&transitions[0].to_bytes()?, stranger.anchor()).is_err()
    );

    // Tampering with a persisted record fails re-admission.
    let mut bytes = transitions[0].to_bytes()?;
    let last = bytes.len() - 1;
    bytes[last] ^= 0x01;
    assert!(AuthorityTransition::from_bytes(&bytes, origin.anchor()).is_err());
    let mut trailing = transitions[0].to_bytes()?;
    trailing.push(0);
    assert!(AuthorityTransition::from_bytes(&trailing, origin.anchor()).is_err());
    assert!(
        AuthorityTransition::from_bytes(&transitions[0].to_bytes()?[..8], origin.anchor()).is_err()
    );
    Ok(())
}
