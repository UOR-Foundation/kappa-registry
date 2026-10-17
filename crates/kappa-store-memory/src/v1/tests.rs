use kappa_crypto::Signer;
use kappa_handler::clock_at;
use kappa_store::traits::blob::BlobStore;
use kappa_store::traits::edge::EdgeStore;
use kappa_store::traits::epoch::EpochStore;
use kappa_store::traits::namespace::NamespaceStore;
use kappa_store::traits::tag::TagStore;
use kappa_store::{Execution, ExecutionStore, Published};
use kappa_types::StoreError;
use kappa_types::axis::Axis;
use kappa_types::canonical::from_canonical;
use kappa_types::clock::ClockMs;
use kappa_types::edge::{BuiltinRelation, Direction, EdgeQuery, EdgeRelation};
use kappa_types::epoch::{EpochMutation, MutationOp};
use kappa_types::epoch_root::mutations_merkle_root;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::page::PageRequest;
use kappa_types::tag::TagUpdate;

use super::InMemoryStore;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn test_store() -> Result<InMemoryStore, Box<dyn std::error::Error>> {
    Ok(super::test_support::test_store()?.into_store())
}

fn now() -> ClockMs {
    ClockMs::from_raw(1_700_000_000_000i64 << 16)
}

fn now2() -> ClockMs {
    ClockMs::from_raw(1_700_000_001_000i64 << 16)
}

fn now3() -> ClockMs {
    ClockMs::from_raw(1_700_000_002_000i64 << 16)
}

fn set(content: &[u8]) -> TagUpdate {
    TagUpdate::Set {
        kappa: Kappa::sha256(content),
    }
}

/// Run `write` in one execution against `ns` and publish it.
fn publish(
    store: &InMemoryStore,
    ns: &NamespaceRef,
    at: ClockMs,
    write: impl FnOnce(&mut dyn Execution) -> Result<(), StoreError>,
) -> Result<Published, StoreError> {
    let mut execution = store.begin_execution(ns, &clock_at(at)?)?;
    write(&mut *execution)?;
    execution.publish()
}

/// A namespace created by the execution that also applies `tags`, so its
/// first epoch carries the namespace record followed by the tag mutations.
fn create_with_tags(
    store: &InMemoryStore,
    name: &str,
    tags: &[(&str, &[u8])],
) -> Result<(NamespaceRef, Published), StoreError> {
    let ns = NamespaceRef::generate(name, now())?;
    let published = publish(store, &ns, now(), |execution| {
        execution.namespace_create(None, None)?;
        for (tag, content) in tags {
            execution.tag_put(tag, &set(content))?;
        }
        Ok(())
    })?;
    Ok((ns, published))
}

fn ledger(store: &InMemoryStore, root: &Kappa) -> Result<Vec<EpochMutation>, StoreError> {
    let root = store.epoch_get(root)?;
    Ok(from_canonical(
        &store.blob_get_verified(root.ledger_root())?,
    )?)
}

// =========================================================================
// Published state commitment across executions
// =========================================================================

#[test]
fn empty_namespace_commits_zero_state() -> TestResult {
    let s = test_store()?;
    let (ns, _) = create_with_tags(&s, "digest-empty", &[])?;
    assert_eq!(s.epoch_state(&ns)?, ([0u8; 32], 0));
    Ok(())
}

#[test]
fn state_commitment_tracks_each_published_tag_change() -> TestResult {
    let s = test_store()?;
    let (ns, _) = create_with_tags(&s, "digest", &[("x", b"one")])?;
    let one = s.epoch_state(&ns)?;
    assert_ne!(one.0, [0u8; 32]);
    assert_eq!(one.1, 1);

    publish(&s, &ns, now2(), |e| e.tag_put("y", &set(b"two")))?;
    let two = s.epoch_state(&ns)?;
    assert_ne!(one.0, two.0, "a second tag changes the commitment");
    assert_eq!(two.1, 2);

    publish(&s, &ns, now3(), |e| e.tag_delete("x"))?;
    let after_delete = s.epoch_state(&ns)?;
    assert_ne!(two.0, after_delete.0, "deletion changes the commitment");
    assert_eq!(after_delete.1, 1);

    publish(&s, &ns, now3(), |e| e.tag_put("x", &set(b"one")))?;
    assert_eq!(
        s.epoch_state(&ns)?,
        two,
        "removal and reinsertion restore the same logical tag set"
    );
    Ok(())
}

#[test]
fn unpublished_execution_changes_no_commitment() -> TestResult {
    let s = test_store()?;
    let (ns, _) = create_with_tags(&s, "private", &[("x", b"one")])?;
    let before = s.epoch_state(&ns)?;
    let mut execution = s.begin_execution(&ns, &clock_at(now2())?)?;
    execution.tag_put("y", &set(b"two"))?;
    assert_eq!(s.epoch_state(&ns)?, before, "private writes stay private");
    drop(execution);
    assert_eq!(s.epoch_state(&ns)?, before, "dropping discards the writes");
    assert!(matches!(s.tag_get(&ns, "y"), Err(StoreError::NotFound(_))));
    Ok(())
}

// =========================================================================
// Epoch publication
// =========================================================================

#[test]
fn first_epoch_commits_namespace_record_then_tags() -> TestResult {
    let s = test_store()?;
    let (ns, published) = create_with_tags(&s, "epoch-rt", &[("a", b"hello"), ("b", b"world")])?;
    let (state_root, tag_count) = s.epoch_state(&ns)?;
    assert_eq!(published.epoch_number, 1);
    assert_eq!(published.root.axis(), Axis::Sha256);

    let root = s.epoch_get(&published.root)?;
    assert_eq!(root.epoch_number(), 1);
    assert!(root.prev_identifier().is_none(), "first epoch has no prev");
    assert_eq!(root.state_digest(), state_root.as_slice());
    assert_eq!(root.tag_count(), tag_count);
    assert_eq!(tag_count, 2);

    let fixture = kappa_crypto::testing::fixture_authority(1)?;
    assert_eq!(&s.node_anchor(), fixture.anchor());
    assert_eq!(root.signer_anchor(), fixture.anchor());
    assert_ne!(root.mutations_root(), &[0u8; 32]);

    // The root links its ledger and the namespace record it retains. Edge
    // pages are ordered by edge identity, so each is selected by target.
    let edges = s.edge_query(
        &ns,
        &EdgeQuery {
            anchor: published.root.clone(),
            direction: Direction::Outbound,
            relation: Some(EdgeRelation::Builtin(BuiltinRelation::EpochRoot)),
            asserter: None,
        },
        &PageRequest::first(16),
    )?;
    assert!(edges.next_after.is_none());
    assert_eq!(
        edges.items.len(),
        2,
        "ledger edge and namespace record link"
    );

    let mutations = ledger(&s, &published.root)?;
    assert_eq!(mutations.len(), 3, "namespace record and two tag mutations");
    assert_eq!(mutations[0].op, MutationOp::NamespaceUpdate);
    assert!(mutations[0].context.is_none());
    for target in [root.ledger_root(), &mutations[0].kappa] {
        assert_eq!(
            edges
                .items
                .iter()
                .filter(|edge| edge.target() == target)
                .count(),
            1
        );
    }
    let record: kappa_store::traits::namespace::NamespaceInfo =
        from_canonical(&s.blob_get_verified(&mutations[0].kappa)?)?;
    assert_eq!(record.ns.id(), ns.id());
    assert_eq!(mutations[1].op, MutationOp::TagSet);
    assert_eq!(mutations[1].context.as_deref(), Some("a"));
    assert_eq!(mutations[1].kappa, Kappa::sha256(b"hello"));
    assert_eq!(mutations[2].op, MutationOp::TagSet);
    assert_eq!(mutations[2].context.as_deref(), Some("b"));
    assert_eq!(mutations[2].kappa, Kappa::sha256(b"world"));
    assert_eq!(mutations_merkle_root(&mutations), root.mutations_root());

    assert_eq!(s.epoch_current(&ns)?, (1, published.root));
    Ok(())
}

#[test]
fn each_publication_links_its_predecessor_and_its_own_ledger() -> TestResult {
    let s = test_store()?;
    let (ns, first) = create_with_tags(&s, "epoch-chain", &[("a", b"hello"), ("b", b"world")])?;
    let first_root = s.epoch_get(&first.root)?;

    let second = publish(&s, &ns, now2(), |e| e.tag_put("c", &set(b"third")))?;
    assert_eq!(second.epoch_number, 2);
    assert_ne!(second.root, first.root);
    let root2 = s.epoch_get(&second.root)?;
    assert_eq!(root2.prev_identifier(), Some(&first.root));
    assert_eq!(root2.tag_count(), 3);
    assert_ne!(root2.state_digest(), first_root.state_digest());
    assert_eq!(ledger(&s, &second.root)?.len(), 1, "only the new tag");

    let third = publish(&s, &ns, now3(), |_| Ok(()))?;
    assert_eq!(third.epoch_number, 3);
    assert_eq!(
        s.epoch_get(&third.root)?.prev_identifier(),
        Some(&second.root)
    );
    assert!(
        ledger(&s, &third.root)?.is_empty(),
        "no mutations since last epoch"
    );
    Ok(())
}

// =========================================================================
// Replay
// =========================================================================

#[test]
fn replay_reconstructs_each_published_state() -> TestResult {
    let s = test_store()?;
    let (ns, _) = create_with_tags(
        &s,
        "replay-ns",
        &[("a", b"alpha"), ("b", b"bravo"), ("c", b"charlie")],
    )?;
    publish(&s, &ns, now2(), |e| {
        e.tag_delete("b")?;
        e.tag_put("d", &set(b"delta"))
    })?;
    publish(&s, &ns, now3(), |e| e.tag_put("e", &set(b"echo")))?;

    let names = |state: &kappa_store::NamespaceState| -> Vec<String> {
        state.tags.keys().cloned().collect()
    };
    assert_eq!(
        names(&kappa_store::replay::replay_to(&s, &ns, 1)?),
        ["a", "b", "c"]
    );
    assert_eq!(
        names(&kappa_store::replay::replay_to(&s, &ns, 2)?),
        ["a", "c", "d"]
    );
    let state3 = kappa_store::replay::replay_to(&s, &ns, 3)?;
    assert_eq!(names(&state3), ["a", "c", "d", "e"]);

    let mut live = std::collections::BTreeMap::new();
    let mut request = PageRequest::first(2);
    loop {
        let page = s.tag_list(&ns, None, &request)?;
        live.extend(page.items.into_iter().map(|tag| (tag.name, tag.kappa)));
        match page.next_after {
            Some(next) => {
                assert_ne!(request.after.as_ref(), Some(&next));
                request.after = Some(next);
            }
            None => break,
        }
    }
    assert_eq!(
        state3.tags, live,
        "replay at current epoch matches live tags"
    );
    Ok(())
}

#[test]
fn replay_target_beyond_current_returns_not_found() -> TestResult {
    let s = test_store()?;
    let (ns, _) = create_with_tags(&s, "replay-nf", &[("x", b"x")])?;
    assert!(matches!(
        kappa_store::replay::replay_to(&s, &ns, 99),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

// =========================================================================
// Signer authority
// =========================================================================

/// The succession from `old` to `new` taking effect at `at`, signed by both.
fn rotation(
    old: &kappa_crypto::SigningAuthority,
    new: &kappa_crypto::SigningAuthority,
    at: ClockMs,
) -> Result<kappa_store::VerifiedSuccession, Box<dyn std::error::Error>> {
    let record = kappa_crypto::signed_types::sign_succession(
        kappa_types::identity::Succession {
            old_anchor: old.anchor().clone(),
            new_anchor: new.anchor().clone(),
            reason: kappa_types::identity::SuccessionReason::Rotation,
            effective_at_ms: at.as_i64(),
            chain_anchor: None,
            prev_identifier: None,
            old_cose_signature: kappa_types::SignedPayload::empty(),
            new_cose_signature: kappa_types::SignedPayload::empty(),
        },
        old.signer(),
        new.signer(),
    )?;
    Ok(kappa_store::VerifiedSuccession::verify(
        record,
        old.signer().algorithm(),
        old.signer().public_key(),
        new.signer().algorithm(),
        new.signer().public_key(),
    )?)
}

/// One witness's evidence for `succession`, bound to the activation domain
/// of `control` and to `origin`, the history's first anchor.
fn witnessed(
    store: &InMemoryStore,
    succession: &kappa_store::VerifiedSuccession,
    origin: &Kappa,
    control: &NamespaceRef,
) -> Result<Vec<kappa_store::WitnessEvidence>, Box<dyn std::error::Error>> {
    let witness = kappa_crypto::ed25519::Ed25519Signer::from_bytes(&[77; 32])?;
    Ok(vec![kappa_store::sign_witness(
        &witness,
        succession.inner(),
        origin,
        store.activation_domain(control)?,
        i64::MIN,
        None,
    )?])
}

/// Rotate `store`'s authority from `old` to `new` at `at`, witnessed and
/// activated in `control`.
fn rotate(
    store: &InMemoryStore,
    old: &kappa_crypto::SigningAuthority,
    new: &kappa_crypto::SigningAuthority,
    origin: &Kappa,
    control: &NamespaceRef,
    at: ClockMs,
) -> TestResult {
    let succession = rotation(old, new, at)?;
    let witnesses = witnessed(store, &succession, origin, control)?;
    store.rotate_authority(new.clone(), succession, witnesses, control, &clock_at(at)?)?;
    Ok(())
}

/// After A -> B -> C an idle namespace's next epoch carries the whole path,
/// a namespace published under B carries only B -> C, retired authorities
/// sign nothing, and authenticated replay from the origin admits both.
#[test]
fn rotation_composes_for_idle_and_active_namespaces() -> TestResult {
    let s = test_store()?;
    let (a, b, c) = (
        kappa_crypto::testing::fixture_authority(1)?,
        kappa_crypto::testing::fixture_authority(2)?,
        kappa_crypto::testing::fixture_authority(3)?,
    );
    let (idle, _) = create_with_tags(&s, "idle", &[("x", b"one")])?;
    let (active, _) = create_with_tags(&s, "active", &[("x", b"one")])?;
    let (control, _) = create_with_tags(&s, "control", &[])?;
    // Taking effect at a published epoch's own time would retire its signer
    // beneath it.
    let early = rotation(&a, &b, now())?;
    let early_witnesses = witnessed(&s, &early, a.anchor(), &control)?;
    assert!(matches!(
        s.rotate_authority(
            b.clone(),
            early,
            early_witnesses,
            &control,
            &clock_at(now2())?
        ),
        Err(kappa_store::AuthorityRotationError::NotCommitted(
            StoreError::Rejected(_)
        ))
    ));
    // No witness, no activation.
    assert!(matches!(
        s.rotate_authority(
            b.clone(),
            rotation(&a, &b, now2())?,
            Vec::new(),
            &control,
            &clock_at(now2())?
        ),
        Err(kappa_store::AuthorityRotationError::NotCommitted(
            StoreError::Rejected(_)
        ))
    ));
    assert_eq!(&s.node_anchor(), a.anchor());
    rotate(&s, &a, &b, a.anchor(), &control, now2())?;
    // The activation is the incoming authority's first epoch of the control
    // namespace, carrying the transition record.
    let (_, activation_root) = s.epoch_current(&control)?;
    let activation_epoch = s.epoch_get(&activation_root)?;
    assert_eq!(activation_epoch.signer_anchor(), b.anchor());
    assert!(activation_epoch.rotation_kappa().is_some());
    assert!(
        s.tag_get_raw(
            &control,
            &format!("{}{:020}", super::epoch::AUTHORITY_TAG_PREFIX, 1)
        )
        .is_ok()
    );
    let at_b = publish(&s, &active, now2(), |e| e.tag_put("y", &set(b"two")))?;
    assert_eq!(s.epoch_get(&at_b.root)?.signer_anchor(), b.anchor());
    rotate(&s, &b, &c, a.anchor(), &control, now3())?;

    let active_c =
        s.epoch_get(&publish(&s, &active, now3(), |e| e.tag_put("z", &set(b"three")))?.root)?;
    let idle_c =
        s.epoch_get(&publish(&s, &idle, now3(), |e| e.tag_put("z", &set(b"three")))?.root)?;
    for (root, hops) in [(&active_c, 1), (&idle_c, 2)] {
        assert_eq!(root.signer_anchor(), c.anchor());
        let path = root
            .rotation_kappa()
            .ok_or("signer change without evidence")?;
        let links: Vec<kappa_types::identity::Succession> =
            from_canonical(&s.blob_get_verified(path)?)?;
        assert_eq!(links.len(), hops);
    }

    let history = s.authority.load_full();
    for ns in [&idle, &active] {
        let (head, _) = s.epoch_current(ns)?;
        assert_eq!(
            kappa_store::replay_authenticated(&s, ns, head, a.anchor(), &|anchor| history
                .resolve(anchor))?,
            kappa_store::replay::replay_to(&s, ns, head)?
        );
    }
    Ok(())
}

/// Executions seal with the node anchor; the override parameter of `seal`
/// is reached here directly, through the execution's own writer. A seal
/// under an anchor the node cannot sign for must publish nothing.
#[test]
fn unrelated_signer_override_publishes_nothing() -> TestResult {
    let s = test_store()?;
    let ns = NamespaceRef::generate("epoch-signer", now())?;
    let override_signer = kappa_crypto::ed25519::Ed25519Signer::from_bytes(&[99u8; 32])?;
    let override_anchor = Kappa::from_key("ed25519", override_signer.public_key())?;

    // The execution's candidate is dropped whatever the seal decides, so
    // nothing can publish.
    let rejected = {
        let mut execution = s.open_execution(&ns, &clock_at(now())?)?;
        execution.write(|cx| {
            cx.namespace_create(None, None)?;
            cx.tag_put("d", &set(b"four"))?;
            cx.seal(Some(&override_anchor))
        })
    };
    assert!(
        matches!(rejected, Err(StoreError::Conflict(_))),
        "a seal under a foreign anchor must be rejected as an authority conflict: {rejected:?}"
    );
    assert!(matches!(s.epoch_current(&ns), Err(StoreError::NotFound(_))));
    assert!(matches!(s.tag_get(&ns, "d"), Err(StoreError::NotFound(_))));
    assert!(matches!(
        s.namespace_resolve("epoch-signer", None),
        Err(StoreError::NotFound(_))
    ));

    let published = publish(&s, &ns, now(), |e| {
        e.namespace_create(None, None)?;
        e.tag_put("d", &set(b"four"))
    })?;
    let mutations = ledger(&s, &published.root)?;
    assert_eq!(mutations.len(), 2);
    assert_eq!(mutations[0].op, MutationOp::NamespaceUpdate);
    assert_eq!(mutations[1].op, MutationOp::TagSet);
    assert_eq!(mutations[1].context.as_deref(), Some("d"));
    assert_eq!(mutations[1].kappa, Kappa::sha256(b"four"));
    Ok(())
}
