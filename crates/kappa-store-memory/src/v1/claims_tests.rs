use super::*;

const A: Holder = Holder {
    namespace: [1; 16],
    incarnation: 1,
};
const B: Holder = Holder {
    namespace: [2; 16],
    incarnation: 1,
};

fn key() -> ClaimKey {
    ClaimKey::Handle("atproto:alice".into())
}

fn alias(protocol: &str) -> ClaimKey {
    ClaimKey::Alias {
        name: "repo".into(),
        protocol: protocol.into(),
    }
}

#[test]
fn alias_admission_follows_the_shared_rule_under_one_lock() -> Result<(), StoreError> {
    let claims = Claims::default();
    claims.reserve_alias("repo", "oci", A, 1)?;
    // Another protocol may scope the same name.
    claims.reserve_alias("repo", "git", B, 2)?;
    // The global name conflicts with any scoped alias of it.
    assert!(claims.reserve_alias("repo", "", B, 3).is_err());
    // The exact alias is held.
    assert!(claims.reserve_alias("repo", "oci", B, 4).is_err());
    claims.settle(&[alias("oci")], A, 1, false);
    claims.settle(&[alias("git")], B, 2, false);
    claims.reserve_alias("repo", "", A, 5)?;
    // A scoped alias conflicts with the global name.
    assert!(claims.reserve_alias("repo", "oci", B, 6).is_err());
    assert!(claims.reserve_alias("", "", A, 7).is_err());
    Ok(())
}

#[test]
fn a_rename_back_within_one_attempt_keeps_the_alias() -> Result<(), StoreError> {
    let claims = Claims::default();
    claims.reserve_alias("repo", "", A, 1)?;
    claims.settle(&[alias("")], A, 1, true);
    assert!(claims.release(&alias(""), A, 2));
    claims.reserve_alias("repo", "", A, 2)?;
    claims.settle(&[alias("")], A, 2, true);
    assert_eq!(claims.observe(&alias("")).holder, Some(A));
    Ok(())
}

#[test]
fn a_reservation_excludes_every_other_holder_until_it_is_aborted() -> Result<(), StoreError> {
    let claims = Claims::default();
    assert!(claims.reserve(&key(), A, 1)?);
    assert!(claims.reserve(&key(), B, 7).is_err());
    claims.settle(&[key()], A, 1, false);
    assert!(claims.reserve(&key(), B, 7)?);
    Ok(())
}

#[test]
fn a_reservation_is_a_candidate_so_a_stored_view_is_found_before_its_claim_commits()
-> Result<(), StoreError> {
    let claims = Claims::default();
    claims.reserve(&key(), A, 1)?;
    // Between the view store and the claim settlement the row is
    // published; the reader still finds the namespace to confirm it in.
    assert_eq!(claims.observe(&key()).holder, Some(A));
    claims.settle(&[key()], A, 1, true);
    assert_eq!(claims.observe(&key()).holder, Some(A));
    // The committed name stays owned: another namespace cannot take it.
    assert!(claims.reserve(&key(), B, 2).is_err());
    // A later execution of the owner writes it without a new reservation.
    assert!(!claims.reserve(&key(), A, 3)?);
    Ok(())
}

#[test]
fn a_release_holds_the_claim_until_its_publication() -> Result<(), StoreError> {
    let claims = Claims::default();
    claims.reserve(&key(), A, 1)?;
    claims.settle(&[key()], A, 1, true);
    assert!(claims.release(&key(), A, 2));
    assert_eq!(claims.observe(&key()).holder, Some(A));
    assert!(claims.reserve(&key(), B, 9).is_err());
    claims.settle(&[key()], A, 2, false);
    assert_eq!(
        claims.observe(&key()).holder,
        Some(A),
        "an aborted release keeps the claim"
    );
    assert!(claims.release(&key(), A, 3));
    claims.settle(&[key()], A, 3, true);
    assert_eq!(claims.observe(&key()).holder, None);
    assert!(claims.reserve(&key(), B, 9)?);
    Ok(())
}

#[test]
fn another_incarnation_of_the_namespace_is_another_holder() -> Result<(), StoreError> {
    let claims = Claims::default();
    claims.reserve(&key(), A, 1)?;
    claims.settle(&[key()], A, 1, true);
    let recreated = Holder {
        namespace: A.namespace,
        incarnation: 2,
    };
    assert!(claims.reserve(&key(), recreated, 1).is_err());
    assert!(!claims.release(&key(), recreated, 1));
    Ok(())
}

#[test]
fn an_unowned_observation_fails_once_the_key_is_reserved() -> Result<(), StoreError> {
    let claims = Claims::default();
    let observed = claims.observe(&key());
    assert_eq!(observed.holder, None);
    assert!(claims.unchanged(observed.at));
    claims.reserve(&key(), B, 1)?;
    claims.settle(&[key()], B, 1, false);
    assert_eq!(claims.observe(&key()).holder, None);
    assert!(
        !claims.unchanged(observed.at),
        "reserved and aborted is still a change"
    );
    Ok(())
}

#[test]
fn another_attempt_of_the_same_namespace_cannot_take_a_reservation_in_flight()
-> Result<(), StoreError> {
    let claims = Claims::default();
    claims.reserve(&key(), A, 1)?;
    assert!(claims.reserve(&key(), A, 2).is_err());
    assert!(claims.reserve(&key(), B, 3).is_err());
    assert_eq!(claims.observe(&key()).holder, Some(A));
    Ok(())
}
