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

    // The root links its ledger, the state and authority records it
    // commits, and every transition evidence record its ledger names.
    // Edge pages are ordered by edge identity, so each is selected by
    // target.
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

    let mutations = ledger(&s, &published.root)?;
    assert_eq!(mutations.len(), 3, "namespace record and two tag mutations");
    assert_eq!(mutations[0].op, MutationOp::NamespaceUpdate);
    assert!(mutations[0].context.is_none());
    let state: kappa_types::NamespaceState = from_canonical(&s.blob_get_verified(root.state())?)?;
    let authority: kappa_types::AuthorityState =
        from_canonical(&s.blob_get_verified(state.authority())?)?;
    assert!(state.names(&authority));
    assert_eq!(authority.namespace(), ns.id());
    let targets = [
        root.ledger_root(),
        root.state(),
        state.authority(),
        &mutations[0].kappa,
        &mutations[1].kappa,
        &mutations[2].kappa,
    ];
    assert_eq!(edges.items.len(), targets.len());
    for target in targets {
        assert_eq!(
            edges
                .items
                .iter()
                .filter(|edge| edge.target() == target)
                .count(),
            1,
            "one edge retains {target}"
        );
    }
    let record: kappa_store::traits::namespace::NamespaceInfo =
        from_canonical(&s.blob_get_verified(&mutations[0].kappa)?)?;
    assert_eq!(record.ns.id(), ns.id());
    // Each tag mutation names its complete canonical entry, whose target is
    // the tagged content.
    for (mutation, (name, content)) in mutations[1..]
        .iter()
        .zip([("a", b"hello".as_slice()), ("b", b"world".as_slice())])
    {
        assert_eq!(mutation.op, MutationOp::TagSet);
        assert_eq!(mutation.context.as_deref(), Some(name));
        let entry: kappa_types::tag::TagEntry =
            from_canonical(&s.blob_get_verified(&mutation.kappa)?)?;
        assert_eq!(entry.name, name);
        assert_eq!(entry.kappa, Kappa::sha256(content));
        assert_ne!(mutation.kappa, entry.kappa, "the ledger names evidence");
    }
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

    let names = |state: &kappa_store::ReplayedNamespaceState| -> Vec<String> {
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

/// Executions seal with the node anchor; the override parameter of
/// `prepare_seal` is reached here directly, through the execution's own
/// writer. A seal under an anchor the node cannot sign for must publish
/// nothing and consume no coordinate.
#[test]
fn unrelated_signer_override_publishes_nothing() -> TestResult {
    let s = test_store()?;
    let ns = NamespaceRef::generate("epoch-signer", now())?;
    let override_signer = kappa_crypto::ed25519::Ed25519Signer::from_bytes(&[99u8; 32])?;
    let override_anchor = Kappa::from_key("ed25519", override_signer.public_key())?;

    // The execution's candidate is dropped whatever the seal decides, so
    // nothing can publish.
    let authority = s.authority.load_full();
    let slot = s.slot(ns.id())?;
    let rejected = {
        let mut execution = s.open_execution(&ns, &clock_at(now())?)?;
        execution.write(|cx| {
            cx.namespace_create(None, None)?;
            cx.tag_put("d", &set(b"four"))?;
            cx.prepare_seal(&authority, Some(&override_anchor))
                .map(drop)
        })
    };
    assert!(
        matches!(rejected, Err(StoreError::Conflict(_))),
        "a seal under a foreign anchor must be rejected as an authority conflict: {rejected:?}"
    );
    assert_eq!(
        slot.signed.load(std::sync::atomic::Ordering::Acquire),
        0,
        "a refusal before signing consumes no coordinate"
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
    assert_eq!(published.epoch_number, 1);
    let mutations = ledger(&s, &published.root)?;
    assert_eq!(mutations.len(), 2);
    assert_eq!(mutations[0].op, MutationOp::NamespaceUpdate);
    assert_eq!(mutations[1].op, MutationOp::TagSet);
    assert_eq!(mutations[1].context.as_deref(), Some("d"));
    let entry: kappa_types::tag::TagEntry =
        from_canonical(&s.blob_get_verified(&mutations[1].kappa)?)?;
    assert_eq!(entry.kappa, Kappa::sha256(b"four"));
    Ok(())
}

/// A coordinate consumed by a seal that did not publish is never signed
/// again: every later publication of the namespace is refused before it
/// signs, and nothing it wrote becomes visible.
#[test]
fn a_consumed_coordinate_fences_its_namespace() -> TestResult {
    let s = test_store()?;
    let (ns, first) = create_with_tags(&s, "fenced", &[("x", b"one")])?;
    let slot = s.slot(ns.id())?;
    assert_eq!(slot.signed.load(std::sync::atomic::Ordering::Acquire), 1);
    // Epoch 2's coordinate consumed by a seal whose publication never
    // happened.
    slot.signed.store(2, std::sync::atomic::Ordering::Release);
    let refused = publish(&s, &ns, now2(), |e| e.tag_put("y", &set(b"two")));
    assert!(
        matches!(refused, Err(StoreError::Conflict(_))),
        "a consumed coordinate must refuse the next seal: {refused:?}"
    );
    assert_eq!(s.epoch_current(&ns)?, (1, first.root));
    assert!(matches!(s.tag_get(&ns, "y"), Err(StoreError::NotFound(_))));
    assert_eq!(slot.signed.load(std::sync::atomic::Ordering::Acquire), 2);
    Ok(())
}

// =========================================================================
// Publication custody
// =========================================================================

const SIGNS: u8 = 0;
const REFUSES: u8 = 1;
const CORRUPTS: u8 = 2;
const SLOW: u8 = 3;

/// How long a `SLOW` signer takes: longer than the deadline the resumable
/// custody test gives its execution.
const SLOW_SIGNATURE: std::time::Duration = std::time::Duration::from_millis(300);

/// The fixture key, counting its invocations and returning a signature, a
/// refusal, wrong signature bytes, or a signature only after
/// [`SLOW_SIGNATURE`], as `mode` selects.
struct Counted {
    inner: kappa_crypto::ed25519::Ed25519Signer,
    calls: std::sync::atomic::AtomicUsize,
    mode: std::sync::atomic::AtomicU8,
    advance: std::sync::Mutex<Option<std::sync::Arc<kappa_handler::clock::ControlledSource>>>,
}

impl Signer for Counted {
    fn algorithm(&self) -> &'static str {
        self.inner.algorithm()
    }
    fn public_key(&self) -> &[u8] {
        self.inner.public_key()
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, kappa_crypto::CryptoError> {
        use std::sync::atomic::Ordering::SeqCst;
        self.calls.fetch_add(1, SeqCst);
        if let Some(source) = self
            .advance
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            source.set(kappa_types::clock::UnixTimeMs::from_millis(
                1_700_000_003_000,
            ));
        }
        match self.mode.load(SeqCst) {
            REFUSES => Err(kappa_crypto::CryptoError::SigningFailed {
                algorithm: "ed25519".into(),
                reason: "refused by the test signer".into(),
            }),
            CORRUPTS => Ok(vec![0; 64]),
            SLOW => {
                std::thread::sleep(SLOW_SIGNATURE);
                self.inner.sign(message)
            }
            _ => self.inner.sign(message),
        }
    }
}

/// A store whose authority signs through a `Counted` signer.
fn counted_store()
-> Result<(super::test_support::TestStore, std::sync::Arc<Counted>), Box<dyn std::error::Error>> {
    let signer = std::sync::Arc::new(Counted {
        inner: kappa_crypto::ed25519::Ed25519Signer::from_bytes(&[41; 32])?,
        calls: std::sync::atomic::AtomicUsize::new(0),
        mode: std::sync::atomic::AtomicU8::new(SIGNS),
        advance: std::sync::Mutex::new(None),
    });
    let authority = kappa_crypto::SigningAuthority::new(
        std::sync::Arc::clone(&signer) as std::sync::Arc<dyn Signer>
    )?;
    Ok((
        super::test_support::test_store_with_authority(authority)?,
        signer,
    ))
}

fn set_mode(signer: &Counted, mode: u8) {
    signer.mode.store(mode, std::sync::atomic::Ordering::SeqCst);
}

fn calls(signer: &Counted) -> usize {
    signer.calls.load(std::sync::atomic::Ordering::SeqCst)
}

fn resolve(
    store: &InMemoryStore,
    ns: &NamespaceRef,
) -> Result<kappa_store::PublicationResolution, StoreError> {
    let limit = kappa_types::work::Dimension::ALL.into_iter().fold(
        kappa_types::work::WorkLimit::unbounded(),
        |limit, dimension| limit.with(dimension, 1_000_000),
    );
    store.resolve_publication(
        ns,
        &clock_at(now3())?,
        &mut kappa_types::work::WorkMeter::new(limit),
    )
}

/// A signer that refuses after the coordinate is consumed leaves the
/// publication retained in its slot: the head is unchanged, the claims it
/// reserved stay owned (another namespace cannot take its name), the
/// namespace is fenced, unrelated namespaces still publish, and resolution
/// never invokes the signer a second time.
#[test]
fn a_refused_signature_is_retained_in_custody() -> TestResult {
    let (s, signer) = counted_store()?;
    let (unrelated, _) = create_with_tags(&s, "unrelated", &[])?;
    let ns = NamespaceRef::generate("custody", now())?;
    set_mode(&signer, REFUSES);
    let before = calls(&signer);
    let refused = publish(&s, &ns, now(), |e| {
        e.namespace_create(None, None)?;
        e.tag_put("held", &set(b"retained"))
    });
    assert!(
        matches!(refused, Err(StoreError::PublicationRetained(_))),
        "a post-reservation failure is reported as retained: {refused:?}"
    );
    assert_eq!(calls(&signer), before + 1);
    let slot = s.slot(ns.id())?;
    assert!(
        slot.pending
            .lock()
            .map_err(|_| "custody poisoned")?
            .is_some(),
        "the publication is in the slot's custody"
    );
    assert!(matches!(s.epoch_current(&ns), Err(StoreError::NotFound(_))));

    // The name the retained publication reserved stays owned by it.
    let rival = NamespaceRef::generate("custody", now())?;
    assert!(
        publish(&s, &rival, now2(), |e| e.namespace_create(None, None)).is_err(),
        "a retained publication's claims are not released"
    );
    // The fenced namespace refuses; an unrelated one publishes.
    set_mode(&signer, SIGNS);
    assert!(publish(&s, &ns, now2(), |e| e.tag_put("next", &set(b"two"))).is_err());
    publish(&s, &unrelated, now2(), |e| {
        e.tag_put("free", &set(b"three"))
    })?;

    let invoked = calls(&signer);
    assert!(matches!(
        resolve(&s, &ns)?,
        kappa_store::PublicationResolution::Retained(_)
    ));
    assert_eq!(calls(&signer), invoked, "resolution never re-signs");
    assert!(
        slot.pending
            .lock()
            .map_err(|_| "custody poisoned")?
            .is_some()
    );
    Ok(())
}

/// A returned signature that fails verification is kept in custody as
/// returned; resolution continues from it without signing again.
#[test]
fn a_returned_signature_is_retained_as_returned() -> TestResult {
    let (s, signer) = counted_store()?;
    let ns = NamespaceRef::generate("returned", now())?;
    set_mode(&signer, CORRUPTS);
    let refused = publish(&s, &ns, now(), |e| e.namespace_create(None, None));
    let Err(StoreError::PublicationRetained(outcome)) = refused else {
        return Err(format!("expected a retained publication, got {refused:?}").into());
    };
    let slot = s.slot(ns.id())?;
    {
        let custody = slot.pending.lock().map_err(|_| "custody poisoned")?;
        let pending = custody.as_ref().ok_or("the publication is in custody")?;
        assert_eq!(
            pending.signed_root(),
            outcome.signed_root,
            "the returned root is kept"
        );
        assert_eq!(
            pending.epoch().and_then(|epoch| epoch.returned_signature()),
            Some([0u8; 64].as_slice()),
            "the exact bytes the signer returned survive the failure"
        );
        assert_eq!(
            outcome.phase,
            kappa_types::PublicationPhase::SignatureInvalid
        );
        assert_eq!(
            outcome.disposition,
            kappa_types::RecoveryDisposition::Terminal
        );
    }
    set_mode(&signer, SIGNS);
    let invoked = calls(&signer);
    assert!(matches!(
        resolve(&s, &ns)?,
        kappa_store::PublicationResolution::Retained(_)
    ));
    assert_eq!(calls(&signer), invoked);
    Ok(())
}

/// A publication stopped by its deadline after the signer returned is
/// retained resumable with the returned bytes and its retention charged.
/// A resolution whose allowance cannot admit its first unit does no work
/// and changes nothing; an admitted resolution forms the root from the
/// retained bytes and publishes it without invoking the signer again.
#[test]
fn a_returned_signature_resumes_within_admitted_work() -> TestResult {
    let (s, signer) = counted_store()?;
    let ns = NamespaceRef::generate("resumed", now())?;
    set_mode(&signer, SLOW);
    let invoked = calls(&signer);
    let mut execution = s.begin_execution(&ns, &clock_at(now())?)?;
    execution.namespace_create(None, None)?;
    execution.tag_put("held", &set(b"resumed"))?;
    execution.set_deadline(std::time::Instant::now() + SLOW_SIGNATURE / 3);
    let Err(StoreError::PublicationRetained(outcome)) = execution.publish() else {
        return Err("a deadline crossed while signing must retain the publication".into());
    };
    assert_eq!(
        outcome.phase,
        kappa_types::PublicationPhase::SignatureReturned
    );
    assert_eq!(
        outcome.disposition,
        kappa_types::RecoveryDisposition::Resumable
    );
    assert!(outcome.signed_root.is_none(), "no root is formed yet");
    assert_eq!(calls(&signer), invoked + 1);

    let slot = s.slot(ns.id())?;
    let returned = {
        let custody = slot.pending.lock().map_err(|_| "custody poisoned")?;
        let pending = custody.as_ref().ok_or("the publication is in custody")?;
        let held = pending.retention();
        assert!(held > 0, "the generated records' retention is reserved");
        assert!(
            s.publication_retention.used() >= held,
            "the pool counts the retention custody holds"
        );
        assert!(
            pending.work().get(kappa_types::work::Dimension::Signatures) > 0,
            "the signer invocation is recorded as spent work"
        );
        pending
            .epoch()
            .and_then(|epoch| epoch.returned_signature())
            .map(<[u8]>::to_vec)
            .ok_or("the returned bytes are retained")?
    };

    // An allowance that cannot admit the first unit does nothing.
    let mut short = kappa_types::work::WorkMeter::new(
        kappa_types::work::WorkLimit::unbounded().with(kappa_types::work::Dimension::Entries, 1),
    );
    let kappa_store::PublicationResolution::Retained(stopped) =
        s.resolve_publication(&ns, &clock_at(now2())?, &mut short)?
    else {
        return Err("an unadmitted resolution must leave the publication retained".into());
    };
    assert_eq!(
        stopped.phase,
        kappa_types::PublicationPhase::SignatureReturned
    );
    assert_eq!(
        stopped.disposition,
        kappa_types::RecoveryDisposition::Resumable
    );
    assert_eq!(
        short.used().get(kappa_types::work::Dimension::Entries),
        0,
        "a refused unit spends nothing"
    );
    assert!(matches!(s.epoch_current(&ns), Err(StoreError::NotFound(_))));

    // An admitted resolution publishes the root formed from the retained
    // bytes: the signer was invoked once in all, so the published, verified
    // root carries the bytes it returned.
    let kappa_store::PublicationResolution::Published(published) = resolve(&s, &ns)? else {
        return Err("an admitted resolution of a resumable publication must publish".into());
    };
    assert_eq!(calls(&signer), invoked + 1, "resolution never re-signs");
    assert!(!returned.is_empty());
    assert_eq!(published.epoch_number, 1);
    assert_eq!(s.epoch_current(&ns)?, (1, published.root.clone()));
    assert_eq!(s.epoch_get(&published.root)?.kappa(), &published.root);
    assert!(
        slot.pending
            .lock()
            .map_err(|_| "custody poisoned")?
            .is_none(),
        "a published retention leaves custody"
    );
    assert_eq!(
        s.tag_get(&ns, "held")?.kappa,
        Kappa::sha256(b"resumed"),
        "the retained candidate is what publishes"
    );
    Ok(())
}

/// Resolving a namespace without a retained publication publishes nothing.
#[test]
fn resolving_without_custody_is_a_no_op() -> TestResult {
    let s = test_store()?;
    let (ns, first) = create_with_tags(&s, "settled", &[("x", b"one")])?;
    assert!(matches!(
        resolve(&s, &ns)?,
        kappa_store::PublicationResolution::Clear
    ));
    assert_eq!(s.epoch_current(&ns)?, (1, first.root));
    Ok(())
}

#[test]
fn authorization_expiring_during_signing_retains_the_signed_candidate_without_publication()
-> TestResult {
    use kappa_handler::clock::{ControlledSource, WallClock};
    use kappa_types::clock::{CausalTime, UnixTimeMs};
    use std::sync::Arc;
    let (store, signer) = counted_store()?;
    let (ns, _) = create_with_tags(&store, "expires-during-signing", &[])?;
    publish(&store, &ns, now2(), |execution| {
        execution.session_put(
            "session",
            &Kappa::sha256(b"owner"),
            now3().as_i64(),
            b"metadata",
        )
    })?;
    let before = store.epoch_current(&ns)?;
    let source = Arc::new(ControlledSource::new(UnixTimeMs::from_millis(
        1_700_000_001_500,
    )));
    let clock = WallClock::recovered(source.clone(), CausalTime::from_encoded(now2()));
    let mut execution = store.begin_execution(&ns, &clock)?;
    assert!(execution.session_get("session")?.is_some());
    execution.tag_put("private", &set(b"expired"))?;
    *signer.advance.lock().map_err(|_| "signer hook poisoned")? = Some(source);
    let invoked = calls(&signer);
    let Err(StoreError::PublicationRetained(retained)) = execution.publish() else {
        return Err("expired signed publication must remain in custody".into());
    };
    assert_eq!(
        retained.disposition,
        kappa_types::RecoveryDisposition::Terminal
    );
    assert!(retained.signed_root.is_some());
    assert_eq!(calls(&signer), invoked + 1);
    assert_eq!(store.epoch_current(&ns)?, before);
    assert!(matches!(
        store.tag_get(&ns, "private"),
        Err(StoreError::NotFound(_))
    ));
    let kappa_store::PublicationResolution::Retained(resolved) = resolve(&store, &ns)? else {
        return Err("terminal custody must not publish on resolution".into());
    };
    assert_eq!(resolved.signed_root, retained.signed_root);
    assert_eq!(
        resolved.disposition,
        kappa_types::RecoveryDisposition::Terminal
    );
    assert_eq!(
        calls(&signer),
        invoked + 1,
        "resolution must not sign again"
    );
    assert_eq!(store.epoch_current(&ns)?, before);
    Ok(())
}
