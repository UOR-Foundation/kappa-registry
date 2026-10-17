//! The directory over the memory store: publication, three-state history,
//! append-only audit, recovery, and client verification from bytes.

use std::sync::Arc;

use kappa_handler::clock_at;
use kappa_store::clock::ClockMs;
use kappa_store::time::Clock;
use kappa_store::traits::KappaStore;
use kappa_store::{Kappa, canonical::canonical_bytes, canonical::from_canonical};
use kappa_transparency::{
    AuditProof, DIRECTORY_NAMESPACE, Directory, DirectoryError, HistoryProof, HistoryState,
    Request, label, verify,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Fixture {
    store: Arc<dyn KappaStore>,
    clock: Arc<dyn Clock>,
    public_key: Vec<u8>,
    namespace_id: [u8; 16],
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let authority = kappa_crypto::testing::fixture_authority(1)?;
    let public_key = authority.signer().public_key().to_vec();
    let store: Arc<dyn KappaStore> = Arc::new(
        kappa_store_memory::test_support::test_store_with_authority(authority)?.into_store(),
    );
    let clock: Arc<dyn Clock> = Arc::new(clock_at(ClockMs::from_raw(1000 << 16))?);
    let namespace =
        kappa_store::namespace_ensure(&*store, DIRECTORY_NAMESPACE, None, None, &*clock)?;
    Ok(Fixture {
        store,
        clock,
        public_key,
        namespace_id: *namespace.id(),
    })
}

fn set(label: Vec<u8>, value: &[u8]) -> Request {
    Request {
        label,
        value: Some(Kappa::sha256(value)),
    }
}

/// Verify a history proof the way a client does: from its canonical bytes
/// and the signing key alone.
fn client_history(
    proof: &HistoryProof,
    namespace_id: &[u8; 16],
    public_key: &[u8],
) -> Result<HistoryState, DirectoryError> {
    let bytes = canonical_bytes(proof);
    let decoded: HistoryProof = from_canonical(&bytes)?;
    verify::history(&decoded, namespace_id, public_key).map(|(state, _)| state)
}

#[test]
fn history_is_provable_in_three_states_and_bound_to_signed_epochs() -> TestResult {
    let f = fixture()?;
    let directory = Directory::open(Arc::clone(&f.store), Arc::clone(&f.clock))?;
    let (genesis, _) = directory.current()?;
    assert_eq!(genesis, 2, "creation epoch, then the genesis commitment");
    // Never asserted in an empty map: provable from the genesis commitment.
    let empty = directory.history(&label("alice", "name/legal"))?;
    assert_eq!(
        client_history(&empty, &f.namespace_id, &f.public_key)?,
        HistoryState::NeverAsserted
    );
    let epoch = directory.publish(&[
        set(label("bob", "name/legal"), b"bob-1"),
        set(label("carol", "name/legal"), b"carol-1"),
    ])?;
    assert_eq!(epoch, 3);
    // A retried publication of the same values publishes nothing.
    assert_eq!(
        directory.publish(&[set(label("bob", "name/legal"), b"bob-1")])?,
        3
    );
    let active = directory.history(&label("bob", "name/legal"))?;
    assert_eq!(
        client_history(&active, &f.namespace_id, &f.public_key)?,
        HistoryState::Active
    );
    assert_eq!(
        active.leaf.as_ref().map(|leaf| leaf.entry.value.clone()),
        Some(Kappa::sha256(b"bob-1"))
    );
    // Absence between two leaves, below the first, and above the last.
    for (subject, facet) in [("bz", "x"), ("a", "x"), ("zzz", "x")] {
        let absent = directory.history(&label(subject, facet))?;
        assert_eq!(
            client_history(&absent, &f.namespace_id, &f.public_key)?,
            HistoryState::NeverAsserted,
            "{subject}/{facet}"
        );
    }
    // A retraction of the wrong value retracts nothing; of the right
    // value it moves the label to the retracted state at that epoch.
    assert_eq!(
        directory.retract(&label("bob", "name/legal"), &Kappa::sha256(b"stale"))?,
        3
    );
    assert_eq!(
        directory.retract(&label("bob", "name/legal"), &Kappa::sha256(b"bob-1"))?,
        4
    );
    let retracted = directory.history(&label("bob", "name/legal"))?;
    assert_eq!(
        client_history(&retracted, &f.namespace_id, &f.public_key)?,
        HistoryState::Retracted
    );
    assert_eq!(
        retracted
            .leaf
            .as_ref()
            .and_then(|leaf| leaf.entry.retracted_at),
        Some(4)
    );
    // Tampering: a proof under another key, another namespace, a changed
    // leaf, or a claimed state that disagrees with the leaf is refused.
    let other_key = kappa_crypto::testing::fixture_authority(2)?
        .signer()
        .public_key()
        .to_vec();
    assert!(client_history(&retracted, &f.namespace_id, &other_key).is_err());
    assert!(client_history(&retracted, &[9; 16], &f.public_key).is_err());
    let mut forged = active;
    if let Some(leaf) = forged.leaf.as_mut() {
        leaf.entry.value = Kappa::sha256(b"forged");
    }
    assert!(client_history(&forged, &f.namespace_id, &f.public_key).is_err());
    let mut relabelled = retracted.clone();
    relabelled.state = HistoryState::Active;
    assert!(client_history(&relabelled, &f.namespace_id, &f.public_key).is_err());
    let mut absence_forged = empty;
    absence_forged.label = retracted.label;
    assert!(
        client_history(&absence_forged, &f.namespace_id, &f.public_key).is_err(),
        "an empty-map absence proof must not transfer to a later label"
    );
    Ok(())
}

#[test]
fn audit_proves_append_only_history_and_recovery_reproduces_the_commitment() -> TestResult {
    let f = fixture()?;
    let directory = Directory::open(Arc::clone(&f.store), Arc::clone(&f.clock))?;
    directory.publish(&[set(label("a", "f"), b"a-1")])?;
    directory.publish(&[set(label("b", "f"), b"b-1"), set(label("a", "f"), b"a-2")])?;
    directory.retract(&label("a", "f"), &Kappa::sha256(b"a-2"))?;
    let (current, commitment) = directory.current()?;
    assert_eq!(current, 5);
    let audit = directory.audit(2, None, None)?;
    let bytes = canonical_bytes(&audit);
    let decoded: AuditProof = from_canonical(&bytes)?;
    verify::audit(&decoded, &f.namespace_id, &f.public_key)?;
    assert_eq!(decoded.from.commitment.log_size, 0);
    assert_eq!(decoded.to.commitment.log_size, 4);
    assert_eq!(decoded.transitions.len(), 4);
    assert_eq!(decoded.next, None);
    let epochs: Vec<u64> = decoded
        .transitions
        .iter()
        .map(|step| step.transition.epoch)
        .collect();
    assert_eq!(epochs, [3, 4, 4, 5]);
    // A partial range and a historical `to`.
    let partial = directory.audit(3, Some(4), None)?;
    verify::audit(&partial, &f.namespace_id, &f.public_key)?;
    assert_eq!(partial.transitions.len(), 2);
    assert!(directory.audit(5, Some(3), None).is_err(), "reversed range");
    assert!(
        directory.audit(1, None, None).is_err(),
        "the creation epoch commits nothing"
    );
    // A transition dropped from the page breaks inclusion; a rewritten
    // earlier log breaks consistency.
    let mut dropped = decoded.clone();
    dropped.transitions.remove(1);
    assert!(verify::audit(&dropped, &f.namespace_id, &f.public_key).is_err());
    let mut rewritten = decoded;
    rewritten.from.commitment.log_size = 1;
    assert!(verify::audit(&rewritten, &f.namespace_id, &f.public_key).is_err());
    // Recovery from the store alone reproduces the served commitment.
    let reopened = Directory::open(Arc::clone(&f.store), Arc::clone(&f.clock))?;
    assert_eq!(reopened.current()?, (current, commitment));
    let proof = reopened.history(&label("a", "f"))?;
    assert_eq!(
        client_history(&proof, &f.namespace_id, &f.public_key)?,
        HistoryState::Retracted
    );
    Ok(())
}

#[test]
fn a_foreign_publication_into_the_directory_namespace_makes_it_unavailable_until_recovered()
-> TestResult {
    let f = fixture()?;
    let directory = Directory::open(Arc::clone(&f.store), Arc::clone(&f.clock))?;
    let namespace = f.store.namespace_resolve(DIRECTORY_NAMESPACE, None)?;
    // Another writer advances the namespace behind the directory's back.
    let mut execution = f.store.begin_execution(&namespace, &*f.clock)?;
    execution.tag_put(
        "stray",
        &kappa_store::TagUpdate::Set {
            kappa: Kappa::sha256(b"stray"),
        },
    )?;
    execution.publish()?;
    assert!(matches!(
        directory.publish(&[set(label("x", "f"), b"x-1")]),
        Err(DirectoryError::Unavailable)
    ));
    assert!(matches!(
        directory.history(&label("x", "f")),
        Err(DirectoryError::Unavailable)
    ));
    // Recovery refuses: the head epoch is not the commitment's.
    assert!(matches!(
        directory.recover(),
        Err(DirectoryError::Verification(_))
    ));
    Ok(())
}
