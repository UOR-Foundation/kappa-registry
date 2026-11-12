//! PERF-EPO-009: authenticated replay. C-10: a genesis that does not match
//! the pinned authority aborts replay.
//!
//! Structural replay (`replay_to`) verifies content identities, ledger
//! commitments, chain continuity and state commitments; it does not
//! establish who signed the history. `replay_authenticated` additionally
//! admits every epoch from an externally pinned genesis anchor, with signer
//! keys supplied by a resolver and bound to their anchors. These tests
//! show both halves: honest history replays identically through both on
//! both backends and matches live state; a chain rebuilt end to end around
//! genuine ledgers passes structure and fails authentication; history from
//! another authority, missing or substituted key material, a transplanted
//! signature, a tampered ledger and a substituted epoch are each rejected
//! by the replay responsible for detecting them.

use kappa_crypto::SigningAuthority;
use kappa_crypto::testing::fixture_authority_from_seed;
use kappa_handler::clock_at;
use kappa_store::epoch_publication::{EpochPublication, EpochPublicationInput};
use kappa_store::epoch_root::EpochRootInput;
use kappa_store::namespace_commitment::StateInput;
use kappa_store::{
    AuthorityState, BlobStore, ClockMs, EpochRoot, EpochStore, ExecutionStore, Kappa, NamespaceRef,
    StoreError, TagStore, TagUpdate, replay_authenticated, replay_to,
};
use kappa_store_memory::InMemoryStore;
use kappa_store_memory::test_support::StoreSpec;
use kappa_types::canonical::canonical_bytes;
use kappa_types::merkle::StreamingTree;
use kappa_types::state_index::{self, Node, NodeSource};
use kappa_types::state_key;
use kappa_types::work::WorkMeter;

use crate::adversary::Adversary;
use crate::common::{TestResult, create_ns, memory_store, redb_store};

/// Seed of the fixtures' default epoch signer.
const NODE_SEED: [u8; 32] = [1; 32];
const ATTACKER_SEED: [u8; 32] = [2; 32];

/// The two authorities these tests sign with and their public material,
/// acquired once per test.
struct Keys {
    node: SigningAuthority,
    attacker: SigningAuthority,
}

impl Keys {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            node: fixture_authority_from_seed(&NODE_SEED)?,
            attacker: fixture_authority_from_seed(&ATTACKER_SEED)?,
        })
    }

    /// Public key material of a known anchor, as a key directory serves it.
    fn lookup(&self, anchor: &Kappa) -> Option<(String, Vec<u8>)> {
        [&self.node, &self.attacker]
            .into_iter()
            .find(|authority| authority.anchor() == anchor)
            .map(|authority| {
                let signer = authority.signer();
                (signer.algorithm().to_owned(), signer.public_key().to_vec())
            })
    }

    /// Authenticated replay with every known signer's key resolvable;
    /// whether history is admitted then depends only on the pin and the
    /// evidence.
    fn authenticated<S: EpochStore + BlobStore + ?Sized>(
        &self,
        store: &S,
        ns: &NamespaceRef,
        target: u64,
        trusted: &Kappa,
    ) -> Result<kappa_store::ReplayedNamespaceState, StoreError> {
        replay_authenticated(store, ns, target, trusted, &|anchor: &Kappa| {
            self.lookup(anchor)
        })
    }
}

/// Five publications after creation: sets, an overwrite and a delete, so
/// every replayed epoch has a distinct state.
fn build_history<S: ExecutionStore + ?Sized>(store: &S, ns: &NamespaceRef) -> TestResult {
    for batch in 0..5u32 {
        let mut execution =
            store.begin_execution(ns, &clock_at(ClockMs::from_raw(2000 + i64::from(batch)))?)?;
        for i in 0..20u32 {
            let idx = batch * 20 + i;
            execution.tag_put(
                &format!("tag-{idx}"),
                &TagUpdate::Set {
                    kappa: Kappa::sha256(&idx.to_le_bytes()),
                },
            )?;
        }
        if batch == 3 {
            execution.tag_put(
                "tag-0",
                &TagUpdate::Set {
                    kappa: Kappa::sha256(b"overwritten"),
                },
            )?;
            execution.tag_delete("tag-1")?;
        }
        execution.publish()?;
    }
    Ok(())
}

fn honest_history_replays_identically<S>(store: &S) -> TestResult
where
    S: ExecutionStore + EpochStore + BlobStore + TagStore,
{
    let keys = Keys::new()?;
    let ns = create_ns(store, "authenticated")?;
    build_history(store, &ns)?;
    let trusted = keys.node.anchor();
    let (head, _) = store.epoch_current(&ns)?;
    assert_eq!(head, 6, "creation plus five publications");

    let mut previous_len = None;
    for target in 0..=head {
        let structural = replay_to(store, &ns, target)?;
        let authenticated = keys.authenticated(store, &ns, target, trusted)?;
        assert_eq!(
            structural, authenticated,
            "replays diverge at epoch {target}"
        );
        if let Some(previous) = previous_len {
            assert!(
                authenticated.tags.len() + 1 >= previous,
                "epoch {target} lost tags"
            );
        }
        previous_len = Some(authenticated.tags.len());
    }

    let live = keys.authenticated(store, &ns, head, trusted)?;
    assert_eq!(live.tags.len(), 99, "100 set, one deleted");
    assert!(!live.tags.contains_key("tag-1"));
    assert_eq!(live.tags["tag-0"], Kappa::sha256(b"overwritten"));
    for (name, kappa) in &live.tags {
        assert_eq!(
            &store.tag_get(&ns, name)?.kappa,
            kappa,
            "replay differs from live {name}"
        );
    }

    assert!(matches!(
        keys.authenticated(store, &ns, head + 1, trusted),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

#[test]
fn honest_history_replays_identically_on_memory() -> TestResult {
    honest_history_replays_identically(&memory_store()?)
}

#[test]
fn honest_history_replays_identically_on_redb() -> TestResult {
    honest_history_replays_identically(&redb_store()?)
}

fn untrusted_genesis_aborts<S>(store: &S) -> TestResult
where
    S: ExecutionStore + EpochStore + BlobStore,
{
    let keys = Keys::new()?;
    let ns = create_ns(store, "c10")?;
    build_history(store, &ns)?;
    let (head, _) = store.epoch_current(&ns)?;
    for target in [0, 1, head] {
        match keys.authenticated(store, &ns, target, keys.attacker.anchor()) {
            Err(StoreError::Rejected(message)) => {
                assert!(
                    message.contains("trusted anchor"),
                    "epoch {target}: {message}"
                );
            }
            other => {
                return Err(format!("epoch {target}: expected rejection, got {other:?}").into());
            }
        }
    }
    Ok(())
}

#[test]
fn untrusted_genesis_aborts_on_memory() -> TestResult {
    untrusted_genesis_aborts(&memory_store()?)
}

#[test]
fn untrusted_genesis_aborts_on_redb() -> TestResult {
    untrusted_genesis_aborts(&redb_store()?)
}

#[test]
fn history_of_another_authority_is_structurally_valid_but_not_admitted() -> TestResult {
    let keys = Keys::new()?;
    let store = StoreSpec::new()
        .authority(keys.attacker.clone())
        .acquire()?
        .into_store();
    let ns = create_ns(&store, "foreign")?;
    build_history(&store, &ns)?;
    let (head, _) = store.epoch_current(&ns)?;

    let structural = replay_to(&store, &ns, head)?;
    assert_eq!(structural.tags.len(), 99);
    assert!(matches!(
        keys.authenticated(&store, &ns, head, keys.node.anchor()),
        Err(StoreError::Rejected(_))
    ));
    // The pin decides: the same history admits under its own authority.
    assert_eq!(
        keys.authenticated(&store, &ns, head, keys.attacker.anchor())?,
        structural
    );
    Ok(())
}

#[test]
fn key_resolution_can_withhold_but_never_substitute_authority() -> TestResult {
    let keys = Keys::new()?;
    let store = memory_store()?;
    let ns = create_ns(&store, "resolver")?;
    build_history(&store, &ns)?;
    let trusted = keys.node.anchor();

    // No key for the pinned genesis: nothing is admitted.
    match replay_authenticated(&store, &ns, 6, trusted, &|_: &Kappa| None) {
        Err(StoreError::Rejected(message)) => {
            assert!(message.contains("no key material"), "{message}");
        }
        other => return Err(format!("history admitted without key material: {other:?}").into()),
    }
    // A resolver answering the node anchor with the attacker's key is
    // caught before any signature is checked.
    let attacker = keys.attacker.anchor();
    let lying = |anchor: &Kappa| {
        if anchor == trusted {
            keys.lookup(attacker)
        } else {
            keys.lookup(anchor)
        }
    };
    match replay_authenticated(&store, &ns, 6, trusted, &lying) {
        Err(StoreError::Rejected(message)) => {
            assert!(message.contains("does not match"), "{message}");
        }
        other => return Err(format!("substituted key admitted: {other:?}").into()),
    }
    // Only the genesis key is needed while the signer never changes.
    let genesis_only = |anchor: &Kappa| (anchor == trusted).then(|| keys.lookup(anchor)).flatten();
    assert_eq!(
        replay_authenticated(&store, &ns, 6, trusted, &genesis_only)?,
        replay_to(&store, &ns, 6)?
    );
    Ok(())
}

/// A node source holding created index nodes.
struct ReplayTestNodes(std::collections::BTreeMap<[u8; 32], Node>);

impl ReplayTestNodes {
    fn new() -> Self {
        Self(std::collections::BTreeMap::new())
    }

    fn absorb(&mut self, update: &state_index::Update) {
        for node in &update.created {
            self.0.insert(node.hash(), *node);
        }
    }
}

impl NodeSource for ReplayTestNodes {
    fn node(&self, hash: &[u8; 32]) -> Result<Node, StoreError> {
        self.0
            .get(hash)
            .copied()
            .ok_or_else(|| StoreError::NotFound(hex::encode(hash)))
    }
}

/// A signer cannot publish under an anchor it does not derive. Authority
/// is coherent by construction, so the attacker's key yields only the
/// attacker's anchor; and the shared publication policy, which every backend
/// seals through, refuses an epoch required under the node's anchor when the
/// authority in force is the attacker's.
#[test]
fn signer_that_does_not_match_the_anchor_cannot_publish() -> TestResult {
    let keys = Keys::new()?;
    let node_anchor = keys.node.anchor();
    assert_ne!(keys.attacker.anchor(), node_anchor);

    let ns = NamespaceRef::generate("impersonated", ClockMs::from_raw(1000))?;
    let incarnation = [1; 16];
    let attacker_authority = AuthorityState::new(
        *ns.id(),
        incarnation,
        Some(keys.attacker.anchor().clone()),
        ns.display_name().to_owned(),
        None,
        false,
    )?;
    let auth_bytes = canonical_bytes(&attacker_authority);
    let (path, value) = state_key::authority_entry(&auth_bytes);
    let mut nodes = ReplayTestNodes::new();
    let mut meter = WorkMeter::unbounded();
    let update = state_index::apply(
        &nodes,
        state_index::EMPTY,
        &[(path, Some(value))],
        &mut meter,
    )?;
    nodes.absorb(&update);
    let history = StreamingTree::default();
    let state_input = StateInput {
        authority: &attacker_authority,
        index_root: update.root,
        index: &nodes,
        predecessor: None,
        history: &history,
    };

    let mutations = Vec::new();
    let refused = EpochPublication::prepare(
        EpochPublicationInput {
            namespace: &ns,
            predecessor: None,
            state_root: [0; 32],
            tag_count: 0,
            mutations: &mutations,
            now: ClockMs::from_raw(1000),
            signer_override: Some(node_anchor),
            state: state_input,
        },
        &kappa_store::EpochAuthority::new(keys.attacker)?,
        &mut meter,
    );
    assert!(
        matches!(refused, Err(StoreError::Conflict(_))),
        "an epoch required under the node's anchor was sealed by another key"
    );
    Ok(())
}

/// Honest store with a namespace at head 6 and the root of `epoch`.
fn honest_with_root(
    epoch: u64,
) -> Result<(InMemoryStore, NamespaceRef, EpochRoot), Box<dyn std::error::Error>> {
    let store = memory_store()?;
    let ns = create_ns(&store, "adversarial")?;
    build_history(&store, &ns)?;
    let root = store.epoch_get(&store.epoch_get_by_number(&ns, epoch)?)?;
    Ok((store, ns, root))
}

#[test]
fn adversary_without_substitution_is_transparent() -> TestResult {
    let keys = Keys::new()?;
    let (store, ns, _) = honest_with_root(1)?;
    let adversary = Adversary::honest(&store);
    assert_eq!(
        keys.authenticated(&adversary, &ns, 6, keys.node.anchor())?,
        replay_to(&store, &ns, 6)?
    );
    Ok(())
}

#[test]
fn transplanted_signature_changes_content_identity() -> TestResult {
    let keys = Keys::new()?;
    let (store, ns, genuine) = honest_with_root(3)?;
    let donor = store.epoch_get(&store.epoch_get_by_number(&ns, 2)?)?;
    // The envelope is part of the root's content identity: a root carrying
    // another epoch's genuine signature is a different object, and serving
    // it under the genuine identity is caught structurally.
    let transplanted = genuine
        .clone()
        .with_signature(donor.cose_signature().clone());
    assert_ne!(transplanted.kappa(), genuine.kappa());
    assert_eq!(transplanted.signable_bytes(), genuine.signable_bytes());
    let adversary = Adversary {
        substitute: Some((genuine.kappa().clone(), transplanted)),
        ..Adversary::honest(&store)
    };
    for result in [
        replay_to(&adversary, &ns, 6),
        keys.authenticated(&adversary, &ns, 6, keys.node.anchor()),
    ] {
        match result {
            Err(StoreError::Rejected(message)) => {
                assert!(message.contains("identity mismatch"), "{message}");
            }
            other => return Err(format!("transplanted root admitted: {other:?}").into()),
        }
    }
    Ok(())
}

#[test]
fn rebuilt_backdated_chain_passes_structure_and_fails_authentication() -> TestResult {
    let keys = Keys::new()?;
    let (store, ns, _) = honest_with_root(1)?;
    let (head, _) = store.epoch_current(&ns)?;
    // Rebuild every root 500 timestamp units earlier, relinked so the
    // chain is internally consistent, each carrying the genuine signature
    // of the root it replaces. Ledgers, mutation roots and state digests
    // are the genuine ones, so every structural check holds.
    let mut chain: Vec<EpochRoot> = Vec::new();
    for number in 1..=head {
        let genuine = store.epoch_get(&store.epoch_get_by_number(&ns, number)?)?;
        let rebuilt = EpochRoot::build(EpochRootInput {
            namespace: &ns,
            epoch_number: number,
            prev_identifier: chain.last().map(EpochRoot::kappa),
            state_digest: genuine.state_digest().try_into()?,
            mutations_root: genuine.mutations_root().try_into()?,
            timestamp: ClockMs::from_raw(genuine.timestamp_ms() - 500),
            signer_anchor: genuine.signer_anchor(),
            tag_count: genuine.tag_count(),
            rotation_kappa: genuine.rotation_kappa(),
            ledger_root: genuine.ledger_root(),
            state: genuine.state(),
        })
        .with_signature(genuine.cose_signature().clone());
        assert_ne!(rebuilt.kappa(), genuine.kappa());
        chain.push(rebuilt);
    }
    let adversary = Adversary {
        chain,
        ..Adversary::honest(&store)
    };

    assert_eq!(
        replay_to(&adversary, &ns, head)?,
        replay_to(&store, &ns, head)?
    );
    match keys.authenticated(&adversary, &ns, head, keys.node.anchor()) {
        Err(StoreError::Rejected(message)) => {
            assert!(message.contains("epoch admission"), "{message}");
        }
        other => return Err(format!("backdated history admitted: {other:?}").into()),
    }
    // Admission covers the whole captured history, not only the target.
    assert!(
        keys.authenticated(&adversary, &ns, 0, keys.node.anchor())
            .is_err()
    );
    Ok(())
}

#[test]
fn tampered_ledger_aborts_every_replay() -> TestResult {
    let keys = Keys::new()?;
    let (store, ns, root) = honest_with_root(2)?;
    let adversary = Adversary {
        tampered_blob: Some(root.ledger_root().clone()),
        ..Adversary::honest(&store)
    };
    assert!(replay_to(&adversary, &ns, 6).is_err());
    assert!(
        keys.authenticated(&adversary, &ns, 6, keys.node.anchor())
            .is_err()
    );
    // Epoch 1 precedes the tampered ledger, but the walk covers the whole
    // captured history before returning any state.
    assert!(replay_to(&adversary, &ns, 1).is_err());
    Ok(())
}

#[test]
fn substituted_epoch_aborts_every_replay() -> TestResult {
    let keys = Keys::new()?;
    let (store, ns, later) = honest_with_root(4)?;
    let adversary = Adversary {
        renumbered: Some((3, later.kappa().clone())),
        ..Adversary::honest(&store)
    };
    for result in [
        replay_to(&adversary, &ns, 6),
        keys.authenticated(&adversary, &ns, 6, keys.node.anchor()),
    ] {
        match result {
            Err(StoreError::Rejected(message)) => {
                assert!(message.contains("discontinuous"), "{message}");
            }
            other => return Err(format!("substituted epoch admitted: {other:?}").into()),
        }
    }
    Ok(())
}
