use kappa_crypto::{Signer, ed25519::Ed25519Signer, signed_types};
use kappa_handler::clock_at;
use kappa_store::KappaStore;
use kappa_store_memory::test_support;
use kappa_types::canonical::from_canonical;
use kappa_types::{
    ClockMs, EpochMutation, Kappa, MutationOp, NamespaceRef, SignedPayload, StoreError, Succession,
    SuccessionReason,
};

fn signed(
    old: &Ed25519Signer,
    new: &Ed25519Signer,
    time: i64,
) -> Result<kappa_crypto::Verified<Succession>, kappa_crypto::CryptoError> {
    let record = signed_types::sign_succession(
        Succession {
            old_anchor: Kappa::from_key(old.algorithm(), old.public_key())?,
            new_anchor: Kappa::from_key(new.algorithm(), new.public_key())?,
            reason: SuccessionReason::Rotation,
            effective_at_ms: time,
            chain_anchor: None,
            prev_identifier: None,
            old_cose_signature: SignedPayload::empty(),
            new_cose_signature: SignedPayload::empty(),
        },
        old,
        new,
    )?;
    signed_types::admit_succession(
        record,
        old.algorithm(),
        old.public_key(),
        new.algorithm(),
        new.public_key(),
    )
}

fn third_anchor(signer: &Ed25519Signer) -> Result<Kappa, kappa_types::KappaParseError> {
    Kappa::from_key(signer.algorithm(), signer.public_key())
}

/// Publish one succession record in its own execution; returns the record's
/// content identity committed by the ledger.
fn publish(
    store: &dyn KappaStore,
    record: &kappa_crypto::Verified<Succession>,
) -> Result<Kappa, StoreError> {
    let ns = NamespaceRef::for_anchor(&record.get().old_anchor);
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(1000))?)?;
    let identity = execution.succession_put(record)?;
    let published = execution.publish()?;
    // The signed record is retrievable and committed by the epoch ledger.
    let root = store.epoch_get(&published.root)?;
    let ledger: Vec<EpochMutation> = from_canonical(&store.blob_get(root.ledger_root())?)?;
    if !ledger
        .iter()
        .any(|mutation| mutation.op == MutationOp::AnchorOrigin && mutation.kappa == identity)
    {
        return Err(StoreError::Internal(
            "succession record missing from ledger".into(),
        ));
    }
    let stored: Succession = from_canonical(&store.blob_get(&identity)?)?;
    if stored.new_anchor != record.get().new_anchor {
        return Err(StoreError::Internal("stored succession differs".into()));
    }
    Ok(identity)
}

fn exercise(store: &dyn KappaStore) -> Result<(), Box<dyn std::error::Error>> {
    let first = Ed25519Signer::from_bytes(&[11; 32])?;
    let second = Ed25519Signer::from_bytes(&[12; 32])?;
    let third = Ed25519Signer::from_bytes(&[13; 32])?;
    let a = signed(&first, &second, 100)?;
    let b = signed(&second, &third, 200)?;
    // Republishing the identical record is idempotent.
    assert_eq!(publish(store, &a)?, publish(store, &a)?);
    publish(store, &b)?;
    let records = store.succession_chain_get(&a.get().old_anchor)?;
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].effective_at_ms, 100);
    assert_eq!(records[1].effective_at_ms, 200);
    signed_types::verify_succession(&records[0], first.public_key(), second.public_key())?;
    signed_types::verify_succession(&records[1], second.public_key(), third.public_key())?;
    assert!(matches!(
        publish(store, &signed(&first, &third, 300)?),
        Err(StoreError::Conflict(_))
    ));
    // A record closing first -> second -> third -> first is refused before
    // publication, so the chain stays resolvable.
    assert!(matches!(
        publish(store, &signed(&third, &first, 300)?),
        Err(StoreError::Rejected(_))
    ));
    assert_eq!(store.succession_chain_get(&a.get().old_anchor)?.len(), 2);
    assert!(matches!(
        store.succession_get(&third_anchor(&third)?),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

#[test]
fn memory_retains_authenticated_succession_records() -> Result<(), Box<dyn std::error::Error>> {
    let store = test_support::test_store()?.into_store();
    exercise(&store)
}

#[test]
fn redb_retains_authenticated_succession_records() -> Result<(), Box<dyn std::error::Error>> {
    exercise(kappa_store_redb::test_support::persistent_store()?.store())
}
