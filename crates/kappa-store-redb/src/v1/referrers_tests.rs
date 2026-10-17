use super::*;
use kappa_store::ClockMs;

fn namespace() -> NamespaceRef {
    NamespaceRef::resolved([9; 16], "n".into(), None)
}

/// A store with `namespace()` created, so its database exists.
fn store_with_namespace() -> Result<PersistentStore, Box<dyn std::error::Error>> {
    let store = crate::test_support::persistent_store()?.into_store();
    let ns = namespace();
    store
        .begin_epoch_execution(&ns, &kappa_handler::clock_at(ClockMs::from_raw(1))?, None)?
        .publish()?;
    Ok(store)
}

#[test]
fn every_kind_roundtrips_and_malformed_identities_are_rejected() -> Result<(), StoreError> {
    let ns = namespace();
    let edge = Kappa::sha256(b"edge");
    for referrer in [
        Referrer::tag(&ns, "latest")?,
        Referrer::edge_record(&ns, &edge),
        Referrer::edge_target(&ns, &edge),
        Referrer::pin(&ns),
        Referrer::epoch_head(&ns),
    ] {
        let encoded = referrer.encode();
        assert_eq!(Referrer::decode(&encoded)?, referrer, "{referrer:?}");
        assert_eq!(&encoded[..16], &[9; 16]);
        assert_eq!(referrer.namespace(), &[9; 16]);
    }
    assert!(Referrer::tag(&ns, "").is_err());
    let mut short = Referrer::pin(&ns).encode();
    short.truncate(16);
    assert!(Referrer::decode(&short).is_err());
    let mut unknown = Referrer::pin(&ns).encode();
    unknown[16] = 200;
    assert!(Referrer::decode(&unknown).is_err());
    let mut pin_with_id = Referrer::pin(&ns).encode();
    pin_with_id.push(1);
    assert!(Referrer::decode(&pin_with_id).is_err());
    let mut head_with_id = Referrer::epoch_head(&ns).encode();
    head_with_id.push(1);
    assert!(Referrer::decode(&head_with_id).is_err());
    let mut tag_without_name = Referrer::tag(&ns, "x")?.encode();
    tag_without_name.truncate(17);
    assert!(Referrer::decode(&tag_without_name).is_err());
    let mut tag_not_utf8 = Referrer::tag(&ns, "x")?.encode();
    tag_not_utf8[17] = 0xFF;
    assert!(Referrer::decode(&tag_not_utf8).is_err());
    let mut edge_truncated = Referrer::edge_target(&ns, &edge).encode();
    edge_truncated.pop();
    assert!(Referrer::decode(&edge_truncated).is_err());
    assert_ne!(
        Referrer::edge_record(&ns, &edge).encode(),
        Referrer::edge_target(&ns, &edge).encode()
    );
    assert_ne!(
        Referrer::pin(&ns).encode(),
        Referrer::epoch_head(&ns).encode()
    );
    assert!(matches!(
        Referrer::decode(&Referrer::epoch_head(&ns).encode())?.source(),
        Source::EpochHead
    ));
    Ok(())
}

#[test]
fn establish_and_release_assert_the_implied_index_state() -> Result<(), Box<dyn std::error::Error>>
{
    let store = store_with_namespace()?;
    let ns = namespace();
    let content = Kappa::sha256(b"referenced");
    let tag = Referrer::tag(&ns, "latest")?;
    let pin = Referrer::pin(&ns);
    let diverged = || {
        store
            .indexes_diverged
            .load(std::sync::atomic::Ordering::Acquire)
    };
    let (db, _active) = store.namespace_db(&ns)?;
    let txn = db.begin_write()?;
    establish(&store, &txn, &content, &tag)?;
    assert!(!diverged(), "a consistent establish records no divergence");
    assert!(matches!(
        establish(&store, &txn, &content, &tag),
        Err(StoreError::Internal(_))
    ));
    assert!(diverged(), "an entry already present is divergence");
    store
        .indexes_diverged
        .store(false, std::sync::atomic::Ordering::Release);
    rebuild(&txn, &content, &tag)?;
    rebuild(&txn, &content, &pin)?;
    rebuild(&txn, &content, &pin)?;
    txn.commit()?;
    {
        assert_eq!(
            store
                .referrers_of(&ns, &Kappa::sha256(b"other"))?
                .referrer()?,
            None,
            "content nothing references has no referrer"
        );
        let mut cursor = store.referrers_of(&ns, &content)?;
        let mut seen = Vec::new();
        while let Some(referrer) = cursor.referrer()? {
            seen.push(referrer.clone());
            cursor.advance()?;
        }
        assert_eq!(seen.len(), 2);
        assert!(seen.contains(&tag));
        assert!(seen.contains(&pin));
        assert_eq!(cursor.key()?, None);
        assert_eq!(cursor.size_hint(), 0);
    }
    let txn = db.begin_write()?;
    release(&store, &txn, &content, &tag)?;
    assert!(!diverged(), "a consistent release records no divergence");
    assert!(matches!(
        release(&store, &txn, &content, &tag),
        Err(StoreError::Internal(_))
    ));
    assert!(diverged(), "an entry already absent is divergence");
    assert!(matches!(
        release(&store, &txn, &content, &Referrer::tag(&ns, "absent")?),
        Err(StoreError::Internal(_))
    ));
    txn.commit()?;
    let cursor = store.referrers_of(&ns, &content)?;
    assert_eq!(cursor.referrer()?, Some(&pin));
    Ok(())
}

/// The cursor retains its read view after the originating transaction is
/// dropped and later commits land; forward seek skips; exhaustion cannot
/// be revived.
#[test]
fn cursor_retains_its_view_across_later_commits() -> Result<(), Box<dyn std::error::Error>> {
    let store = store_with_namespace()?;
    let ns = namespace();
    let content = Kappa::sha256(b"shared");
    let first = Referrer::tag(&ns, "a")?;
    let second = Referrer::tag(&ns, "b")?;
    let third = Referrer::tag(&ns, "c")?;
    let (db, _active) = store.namespace_db(&ns)?;
    let txn = db.begin_write()?;
    for referrer in [&first, &second, &third] {
        establish(&store, &txn, &content, referrer)?;
    }
    txn.commit()?;
    let mut cursor = store.referrers_of(&ns, &content)?;
    let txn = db.begin_write()?;
    release(&store, &txn, &content, &second)?;
    establish(&store, &txn, &content, &Referrer::tag(&ns, "d")?)?;
    txn.commit()?;
    assert_eq!(cursor.referrer()?, Some(&first));
    assert_eq!(
        cursor.seek(&second.encode())?,
        Some(second.encode().as_slice())
    );
    assert_eq!(cursor.referrer()?, Some(&second));
    assert_eq!(cursor.advance()?, Some(third.encode().as_slice()));
    assert_eq!(cursor.advance()?, None);
    assert_eq!(cursor.seek(&first.encode())?, None);
    assert_eq!(cursor.referrer()?, None);
    {
        let mut current = store.referrers_of(&ns, &content)?;
        let mut seen = Vec::new();
        while let Some(referrer) = current.referrer()? {
            seen.push(referrer.clone());
            current.advance()?;
        }
        assert_eq!(seen, [first, third, Referrer::tag(&ns, "d")?]);
    }
    Ok(())
}

/// A malformed entry that sorts after a valid one latches the cursor on
/// the advance that reaches it; every later call reports the failure.
#[test]
fn malformed_entry_after_a_valid_one_latches_the_cursor() -> Result<(), Box<dyn std::error::Error>>
{
    let store = store_with_namespace()?;
    let ns = namespace();
    let content = Kappa::sha256(b"damaged");
    let (db, _active) = store.namespace_db(&ns)?;
    let txn = db.begin_write()?;
    // Kind 0 (tag) sorts before kind 3 (pin) within the namespace.
    establish(&store, &txn, &content, &Referrer::tag(&ns, "first")?)?;
    let mut malformed = Referrer::pin(&ns).encode();
    malformed.push(0);
    txn.open_multimap_table(REFERRERS)?
        .insert(content.key_bytes().as_slice(), malformed.as_slice())?;
    txn.commit()?;
    let mut cursor = store.referrers_of(&ns, &content)?;
    assert_eq!(cursor.referrer()?, Some(&Referrer::tag(&ns, "first")?));
    assert!(matches!(cursor.advance(), Err(StoreError::Internal(_))));
    assert!(matches!(cursor.key(), Err(StoreError::Internal(_))));
    assert!(matches!(cursor.referrer(), Err(StoreError::Internal(_))));
    assert!(matches!(cursor.advance(), Err(StoreError::Internal(_))));
    assert!(matches!(cursor.seek(&[]), Err(StoreError::Internal(_))));
    Ok(())
}

/// A namespace's index holds only its own references and representation
/// dependencies: an entry of another namespace is divergence, so the cursor
/// latches on it instead of reporting it as a referrer, while a
/// representation dependency is reported.
#[test]
fn an_entry_of_another_namespace_latches_the_cursor() -> Result<(), Box<dyn std::error::Error>> {
    let store = store_with_namespace()?;
    let ns = namespace();
    let held = Kappa::sha256(b"held");
    let foreign = Kappa::sha256(b"foreign");
    let representation = Referrer::representation(&Kappa::sha256(b"composite"));
    let (db, _active) = store.namespace_db(&ns)?;
    let txn = db.begin_write()?;
    establish(&store, &txn, &held, &representation)?;
    establish(&store, &txn, &held, &Referrer::tag(&ns, "own")?)?;
    establish(&store, &txn, &foreign, &Referrer::tag(&ns, "own")?)?;
    let other = Referrer::pin(&NamespaceRef::resolved([8; 16], "other".into(), None)).encode();
    txn.open_multimap_table(REFERRERS)?
        .insert(foreign.key_bytes().as_slice(), other.as_slice())?;
    txn.commit()?;
    let mut cursor = store.referrers_of(&ns, &held)?;
    let mut seen = Vec::new();
    while let Some(referrer) = cursor.referrer()? {
        seen.push(referrer.clone());
        cursor.advance()?;
    }
    assert_eq!(seen, [representation, Referrer::tag(&ns, "own")?]);
    // `[8; 16]` sorts before `[9; 16]`: the foreign entry is the first.
    assert!(matches!(
        store.referrers_of(&ns, &foreign),
        Err(StoreError::Internal(_))
    ));
    Ok(())
}

/// A malformed first entry is rejected by construction.
#[test]
fn malformed_first_entry_is_rejected_at_construction() -> Result<(), Box<dyn std::error::Error>> {
    let store = store_with_namespace()?;
    let ns = namespace();
    let content = Kappa::sha256(b"damaged-first");
    let (db, _active) = store.namespace_db(&ns)?;
    let txn = db.begin_write()?;
    let mut malformed = Referrer::tag(&ns, "x")?.encode();
    malformed[17] = 0xFF;
    txn.open_multimap_table(REFERRERS)?
        .insert(content.key_bytes().as_slice(), malformed.as_slice())?;
    establish(&store, &txn, &content, &Referrer::pin(&ns))?;
    txn.commit()?;
    assert!(matches!(
        store.referrers_of(&ns, &content),
        Err(StoreError::Internal(_))
    ));
    Ok(())
}
