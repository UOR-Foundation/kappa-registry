use std::sync::Arc;
use std::sync::atomic::Ordering;

use kappa_crypto::SigningAuthority;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_fixture::FixtureRoot;
use kappa_handler::clock_at;
use kappa_store::{
    AuthorityRotationError, ClockMs, EpochStore, ExecutionStore, Kappa, NamespaceRef,
    SignedPayload, StoreError, Succession, SuccessionReason, TagStore, TagUpdate,
    VerifiedSuccession, replay_authenticated, replay_to,
};

use crate::PersistentStore;
use crate::test_support::PersistentSpec;

#[path = "authority_fault_tests.rs"]
mod faults;

#[path = "authority_standing_tests.rs"]
mod standing;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn authority(seed: u8) -> Result<SigningAuthority, Box<dyn std::error::Error>> {
    Ok(SigningAuthority::new(Arc::new(Ed25519Signer::from_bytes(
        &[seed; 32],
    )?))?)
}

/// The store in `root`, signing with the authority from `seed`.
fn open(root: &FixtureRoot, seed: u8) -> Result<PersistentStore, Box<dyn std::error::Error>> {
    Ok(PersistentSpec::new()
        .in_root(root)
        .authority(authority(seed)?)
        .acquire()?
        .into_store())
}

/// The `StoreError` a failed acquisition carries. A successful acquisition
/// or any other failure is returned as the test's error.
fn acquisition_error<T, E: Into<Box<dyn std::error::Error>>>(
    result: Result<T, E>,
) -> Result<StoreError, Box<dyn std::error::Error>> {
    match result {
        Ok(_) => Err("acquisition succeeded".into()),
        Err(error) => error.into().downcast::<StoreError>().map(|error| *error),
    }
}

fn mismatch(error: &StoreError, offered: &SigningAuthority, current: &SigningAuthority) -> bool {
    matches!(
        error,
        StoreError::AuthorityMismatch { offered: o, current: c }
            if o.as_ref() == offered.anchor() && c.as_ref() == current.anchor()
    )
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

/// A control namespace for activations, created at `at`.
fn control(store: &PersistentStore, at: i64) -> Result<NamespaceRef, Box<dyn std::error::Error>> {
    let ns = NamespaceRef::generate("control", ClockMs::from_raw(at))?;
    publish_tag(store, &ns, at, true, "control")?;
    Ok(ns)
}

/// Rotate `store` to `next` through `succession`, witnessed in `control`,
/// at `at`. The outer result is the test's setup; the inner one the
/// rotation's typed outcome.
fn rotation(
    store: &PersistentStore,
    control: &NamespaceRef,
    next: &SigningAuthority,
    succession: VerifiedSuccession,
    at: i64,
) -> Result<Result<(), AuthorityRotationError>, Box<dyn std::error::Error>> {
    let witness = Ed25519Signer::from_bytes(&[77; 32])?;
    let origin = store.authority.load().origin().anchor().clone();
    let witnesses = match store.activation_domain(control) {
        Ok(domain) => vec![kappa_store::sign_witness(
            &witness,
            succession.inner(),
            &origin,
            domain,
            i64::MIN,
            None,
        )?],
        // A domain that cannot be read is the rotation's to refuse.
        Err(_) => Vec::new(),
    };
    Ok(store.rotate_authority(
        next.clone(),
        succession,
        witnesses,
        control,
        &clock_at(ClockMs::from_raw(at))?,
    ))
}

fn publish_tag(
    store: &PersistentStore,
    ns: &NamespaceRef,
    at: i64,
    create: bool,
    name: &str,
) -> Result<Kappa, Box<dyn std::error::Error>> {
    let mut execution = store.begin_execution(ns, &clock_at(ClockMs::from_raw(at))?)?;
    if create {
        execution.namespace_create(None, None)?;
    }
    execution.tag_put(
        name,
        &TagUpdate::Set {
            kappa: Kappa::sha256(name.as_bytes()),
        },
    )?;
    Ok(execution.publish()?.root)
}

/// Replay of `ns` admitted from the store's origin, with keys from the
/// store's own history, equals structural replay, and every tag it
/// reconstructs reads back live.
fn authenticated_replay_matches(store: &PersistentStore, ns: &NamespaceRef) -> TestResult {
    let history = store.authority.load_full();
    let (head, _) = store.epoch_current(ns)?;
    let admitted = replay_authenticated(store, ns, head, history.origin().anchor(), &|anchor| {
        history.resolve(anchor)
    })?;
    assert_eq!(admitted, replay_to(store, ns, head)?);
    for (name, kappa) in &admitted.tags {
        assert_eq!(&store.tag_get(ns, name)?.kappa, kappa);
    }
    Ok(())
}

#[test]
fn rotations_persist_and_idle_namespaces_cross_the_whole_path() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let (a, b, c) = (authority(1)?, authority(2)?, authority(3)?);
    let store = open(&root, 1)?;
    assert_eq!(
        store.persisted_authority_rows()?,
        1,
        "origin recorded at first open"
    );
    let idle = NamespaceRef::generate("idle", ClockMs::from_raw(1000))?;
    let busy = NamespaceRef::generate("busy", ClockMs::from_raw(1000))?;
    publish_tag(&store, &idle, 1000, true, "first")?;
    publish_tag(&store, &busy, 1000, true, "first")?;
    let control = control(&store, 1000)?;

    // Effective before, or exactly at, a published epoch: the outgoing
    // window would no longer contain it. Rejected; nothing persisted; the
    // current authority and every published epoch are unchanged.
    for effective in [900, 1000] {
        assert!(matches!(
            rotation(&store, &control, &b, succession(&a, &b, effective)?, 2000)?,
            Err(AuthorityRotationError::NotCommitted(StoreError::Rejected(
                _
            )))
        ));
    }
    // Without a witness the rotation does not activate.
    assert!(matches!(
        store.rotate_authority(
            b.clone(),
            succession(&a, &b, 2000)?,
            Vec::new(),
            &control,
            &clock_at(ClockMs::from_raw(2000))?
        ),
        Err(AuthorityRotationError::NotCommitted(StoreError::Rejected(
            _
        )))
    ));
    assert_eq!(store.persisted_authority_rows()?, 1);
    assert_eq!(&store.node_anchor(), a.anchor());
    assert!(store.retired_authorities().is_empty());
    assert!(!store.authority_unresolved());
    authenticated_replay_matches(&store, &idle)?;
    authenticated_replay_matches(&store, &busy)?;

    rotation(&store, &control, &b, succession(&a, &b, 2000)?, 2000)??;
    // The committed transition is published in the control namespace under
    // the incoming authority, as its first epoch there.
    let (_, activation_root) = store.epoch_current(&control)?;
    let activation_epoch = store.epoch_get(&activation_root)?;
    assert_eq!(activation_epoch.signer_anchor(), b.anchor());
    assert!(activation_epoch.rotation_kappa().is_some());
    assert!(
        store
            .tag_get_raw(
                &control,
                &format!("{}{:020}", crate::authority::AUTHORITY_TAG_PREFIX, 1)
            )
            .is_ok()
    );
    let busy_b = publish_tag(&store, &busy, 2500, false, "second")?;
    assert_eq!(store.epoch_get(&busy_b)?.signer_anchor(), b.anchor());
    rotation(&store, &control, &c, succession(&b, &c, 3000)?, 3000)??;
    assert_eq!(store.persisted_authority_rows()?, 3);
    assert_eq!(&store.node_anchor(), c.anchor());
    assert_eq!(
        store.retired_authorities(),
        vec![a.anchor().clone(), b.anchor().clone()],
        "retired anchors in history order"
    );

    let busy_c = store.epoch_get(&publish_tag(&store, &busy, 3500, false, "third")?)?;
    assert_eq!(busy_c.signer_anchor(), c.anchor());
    assert!(busy_c.rotation_kappa().is_some(), "B -> C evidence");
    authenticated_replay_matches(&store, &busy)?;
    drop(store);

    // Reopening under a retired authority is refused, naming the current.
    for retired in [&a, &b] {
        let refused = acquisition_error(
            PersistentSpec::new()
                .in_root(&root)
                .authority(retired.clone())
                .acquire(),
        )?;
        assert!(mismatch(&refused, retired, &c), "{refused:?}");
    }

    let reopened = open(&root, 3)?;
    assert_eq!(
        reopened.retired_authorities(),
        vec![a.anchor().clone(), b.anchor().clone()],
        "retired anchors are restored from persisted history"
    );
    let idle_c = reopened.epoch_get(&publish_tag(&reopened, &idle, 4000, false, "second")?)?;
    assert_eq!(idle_c.signer_anchor(), c.anchor());
    let path = idle_c
        .rotation_kappa()
        .ok_or("idle namespace crossed rotations without evidence")?;
    let links: Vec<Succession> = kappa_store::canonical::from_canonical(
        &kappa_store::BlobStore::blob_get(&reopened, path)?,
    )?;
    assert_eq!(links.len(), 2, "A -> B -> C");
    authenticated_replay_matches(&reopened, &idle)?;
    authenticated_replay_matches(&reopened, &busy)?;
    Ok(())
}

/// The node holds several keys and the store's history decides which one
/// signs: whichever candidate is offered as configured or alternate, the
/// one holding the chain's last key is selected; a set of candidates none of
/// which holds it is refused; and a store without history refuses to let an
/// unordered candidate set choose its origin.
#[test]
fn persisted_history_selects_the_signing_key_among_candidates() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let (a, b, c) = (authority(1)?, authority(2)?, authority(3)?);

    let fresh = FixtureRoot::temporary()?;
    let refused = acquisition_error(
        PersistentSpec::new()
            .in_root(&fresh)
            .authority(a.clone())
            .alternates(vec![b.clone()])
            .requiring_history()
            .acquire(),
    )?;
    assert!(
        matches!(refused, StoreError::AuthorityHistoryAbsent { offered: 2 }),
        "{refused:?}"
    );

    let store = open(&root, 1)?;
    let ns = NamespaceRef::generate("selected", ClockMs::from_raw(1000))?;
    publish_tag(&store, &ns, 1000, true, "first")?;
    let control = control(&store, 1000)?;
    rotation(&store, &control, &b, succession(&a, &b, 2000)?, 2000)??;
    drop(store);

    // A crash between the store's commit and the key store's settlement:
    // the node still names A current and holds B staged. History picks B
    // in either offering order, and requiring history changes nothing.
    for (configured, alternates) in [(a.clone(), vec![b.clone()]), (b.clone(), vec![a.clone()])] {
        let reopened = PersistentSpec::new()
            .in_root(&root)
            .authority(configured)
            .alternates(alternates)
            .requiring_history()
            .acquire()?
            .into_store();
        assert_eq!(&reopened.node_anchor(), b.anchor());
        authenticated_replay_matches(&reopened, &ns)?;
    }
    let refused = acquisition_error(
        PersistentSpec::new()
            .in_root(&root)
            .authority(a.clone())
            .alternates(vec![c.clone()])
            .acquire(),
    )?;
    assert!(
        mismatch(&refused, &a, &b),
        "candidates without the committed key: {refused:?}"
    );
    let expected = b.anchor().clone();
    let reopened = PersistentSpec::new()
        .in_root(&root)
        .authority(c)
        .alternates(vec![a, b])
        .acquire()?
        .into_store();
    assert_eq!(reopened.node_anchor(), expected);
    Ok(())
}

/// The unresolved gate is checked by the seal itself, not only by redb's
/// refusal of writes after a failed commit: a handle marked unresolved
/// refuses to seal through execution publication even when the database
/// accepts the write transaction, with the typed refusal naming the
/// outgoing authority, and the refusal publishes nothing.
#[test]
fn unresolved_authority_refuses_execution_publication() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let store = open(&root, 1)?;
    let a = authority(1)?;
    let ns = NamespaceRef::generate("gated", ClockMs::from_raw(1000))?;
    let first = publish_tag(&store, &ns, 1000, true, "first")?;
    store.authority_unresolved.store(true, Ordering::SeqCst);
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2000))?)?;
    execution.tag_put(
        "second",
        &TagUpdate::Set {
            kappa: Kappa::sha256(b"second"),
        },
    )?;
    let refused = execution.publish();
    assert!(
        matches!(
            &refused,
            Err(StoreError::AuthorityUnresolved { outgoing }) if outgoing.as_ref() == a.anchor()
        ),
        "sealed under an unresolved authority: {refused:?}"
    );
    assert_eq!(store.epoch_current(&ns)?, (1, first));
    assert!(matches!(
        store.tag_get(&ns, "second"),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}
