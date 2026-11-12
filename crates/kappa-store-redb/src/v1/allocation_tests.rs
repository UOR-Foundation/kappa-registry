use super::*;
use crate::storage_instance::StorageInstance;

#[test]
fn pins_and_claims_exclude_each_other_and_claims_are_exclusive() -> Result<(), StoreError> {
    let protection = Arc::new(Protection::default());
    let id = AllocationId::generate()?;
    let pin = protection.pin(id)?;
    let second = protection.pin(id)?;
    assert!(
        protection.claim(id)?.is_none(),
        "pinned allocation was claimed"
    );
    drop(pin);
    assert!(protection.claim(id)?.is_none(), "still pinned once");
    drop(second);
    let claim = protection
        .claim(id)?
        .ok_or_else(|| StoreError::Internal("no claim".into()))?;
    assert!(protection.claim(id)?.is_none(), "claim was not exclusive");
    assert!(matches!(protection.pin(id), Err(StoreError::NotFound(_))));
    drop(claim);
    assert!(
        protection.pin(id).is_ok(),
        "released claim still blocked pins"
    );
    assert!(!protection.is_pinned(&AllocationId::generate()?)?);
    Ok(())
}

#[test]
fn creation_pins_first_and_deletion_measures_both_files() -> Result<(), Box<dyn std::error::Error>>
{
    let dir = tempfile::tempdir()?;
    precreate_shards(dir.path())?;
    let protection = Arc::new(Protection::default());
    let (pin, mut file) = protection.create(dir.path())?;
    assert!(protection.is_pinned(pin.allocation())?);
    std::io::Write::write_all(&mut file, &[1; 100])?;
    drop(file);
    let mut sidecar = private_create_new().open(chunk_list_path(dir.path(), pin.allocation()))?;
    std::io::Write::write_all(&mut sidecar, &[2; 32])?;
    drop(sidecar);
    let id = *pin.allocation();
    let owner = Owner {
        instance: StorageInstance::generate([7; 16])?,
        identity: Kappa::sha256(b"owned"),
    };
    write_owner_marker(dir.path(), &id, &owner, true)?;
    assert_eq!(read_owner_marker(dir.path(), &id)?, Some(owner.clone()));
    // Custody replay repeats the same installation after an aborted
    // transaction. Exclusion is against a different owner or identity.
    write_owner_marker(dir.path(), &id, &owner, true)?;
    let foreign_owners = [
        Owner {
            instance: StorageInstance::generate([7; 16])?,
            identity: owner.identity.clone(),
        },
        Owner {
            instance: owner.instance,
            identity: Kappa::sha256(b"different-content"),
        },
    ];
    for foreign in foreign_owners {
        assert!(
            matches!(
                write_owner_marker(dir.path(), &id, &foreign, true),
                Err(StoreError::Internal(_))
            ),
            "a second installer was admitted"
        );
        assert_eq!(
            read_owner_marker(dir.path(), &id)?,
            Some(owner.clone()),
            "a refused installer changed the durable owner"
        );
    }
    assert!(protection.claim(id)?.is_none());
    drop(pin);
    let claim = protection.claim(id)?.ok_or("no claim")?;
    let bytes = claim.delete(dir.path(), true).map_err(|(_, error)| error)?;
    assert_eq!(bytes, Some(132), "the marker is not content");
    assert!(!allocation_path(dir.path(), &id).exists());
    assert!(!chunk_list_path(dir.path(), &id).exists());
    assert!(!owner_path(dir.path(), &id).exists());
    assert_eq!(read_owner_marker(dir.path(), &id)?, None);
    // Nothing left to delete is reported as absent, not as a deletion.
    let again = protection.claim(id)?.ok_or("no second claim")?;
    assert_eq!(
        again.delete(dir.path(), true).map_err(|(_, error)| error)?,
        None
    );
    Ok(())
}

#[test]
fn classification_distinguishes_payloads_sidecars_and_strangers() -> Result<(), StoreError> {
    let id = AllocationId::generate()?;
    assert_eq!(classify(&id.hex()), Some((id, Entry::Payload)));
    assert_eq!(
        classify(&format!("{}.chunks", id.hex())),
        Some((id, Entry::Sidecar))
    );
    assert_eq!(
        classify(&format!("{}.owner", id.hex())),
        Some((id, Entry::Owner))
    );
    assert_eq!(classify(&id.hex().to_uppercase()), None);
    assert_eq!(classify("notes.txt"), None);
    assert_eq!(classify(".chunks"), None);
    assert_eq!(classify(".owner"), None);
    Ok(())
}

#[test]
fn an_owner_marker_round_trips_and_refuses_truncation() -> Result<(), StoreError> {
    let owner = Owner {
        instance: StorageInstance::generate([3; 16])?,
        identity: Kappa::sha256(b"marked"),
    };
    let bytes = owner.encode();
    assert_eq!(bytes.len(), 32 + 33);
    assert_eq!(Owner::decode(&bytes)?, owner);
    assert!(matches!(
        Owner::decode(&bytes[..16]),
        Err(StoreError::Internal(_))
    ));
    assert!(Owner::decode(&bytes[..40]).is_err());
    Ok(())
}

/// A record written before incarnations existed, `[namespace:16]
/// [identity]`, decodes as the namespace's unknown instance.
#[test]
fn a_legacy_owner_marker_decodes_as_an_unknown_instance() -> Result<(), StoreError> {
    let identity = Kappa::sha512(b"legacy");
    let mut legacy = vec![5; 16];
    legacy.extend_from_slice(&identity.key_bytes());
    let decoded = Owner::decode(&legacy)?;
    assert_eq!(
        decoded.instance,
        StorageInstance::new([5; 16], crate::storage_instance::Incarnation::Unknown)
    );
    assert_eq!(decoded.identity, identity);
    Ok(())
}

/// The two owner layouts are told apart by which split leaves a valid
/// identity key; that is unambiguous only while no two axis digest
/// lengths differ by the 16 bytes of an incarnation.
#[test]
fn no_two_axis_digest_lengths_differ_by_an_incarnation() {
    let axes = (0u8..=u8::MAX).filter_map(kappa_types::Axis::from_discriminant);
    for first in axes.clone() {
        for second in axes.clone() {
            assert_ne!(
                first.digest_len() + 16,
                second.digest_len(),
                "{first} and {second} make owner records ambiguous"
            );
        }
    }
}

/// Panic while holding the shard of `id`, which poisons it.
#[expect(
    clippy::significant_drop_tightening,
    reason = "the guard is held through the panic: that is what poisons the shard"
)]
fn poison(protection: &Protection, id: &AllocationId) {
    let guard = protection.shard(id).lock();
    assert!(guard.is_ok(), "fresh shard was already poisoned");
    panic!("poison the shard");
}

#[test]
fn a_poisoned_shard_refuses_rather_than_leaks() -> Result<(), StoreError> {
    let protection = Arc::new(Protection::default());
    let id = AllocationId::generate()?;
    let shared = Arc::clone(&protection);
    // The spawned thread panics by design; its join error is the poisoning.
    let joined = std::thread::spawn(move || poison(&shared, &id)).join();
    assert!(joined.is_err(), "the poisoning thread did not panic");
    assert!(matches!(protection.pin(id), Err(StoreError::Internal(_))));
    assert!(matches!(protection.claim(id), Err(StoreError::Internal(_))));
    let mut other = id;
    other.0[0] = other.0[0].wrapping_add(1);
    assert!(protection.pin(other).is_ok(), "unrelated shard was fenced");
    Ok(())
}
