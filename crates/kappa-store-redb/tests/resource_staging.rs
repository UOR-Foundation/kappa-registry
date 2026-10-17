//! Staged resources through the public contract, on both backends: every
//! stage is epoch-committed and recoverable, completion publishes exactly
//! the frozen generation, retries replay the committed outcome, and the
//! guarantees of the replaced staging engines hold: a rejected or refused
//! stage reserves nothing, slots are replaced through their committed
//! reference, membership is paged, a composite of equal parts completes
//! and retires, and a resource is addressed only in its own namespace.
//! Races, expiry, frozen generations and concurrent preparation are in
//! `resource_staging_races.rs`.
//!
//! Limits on concurrent resources and global staging bytes are admission
//! decisions of the handler that opens resources, not of this contract.

mod support;

use kappa_store::resource::{self, Resolution};
use kappa_store::{
    Axis, ContentIdentity, Kappa, ResourceKind, ResourcePhase, Retirement, StoreError,
};

use support::resource::{complete, open, recorded_compositions, stage};
use support::{Staging, TestResult, at, create, prepare, publish, staging_dirs};

fn asserter() -> Kappa {
    support::resource::asserter()
}

fn exercise_sequential(store: &(impl Staging + ?Sized)) -> TestResult {
    let ns = create(store, "sequential")?;
    let now = at(1_700_000_001_000);
    let id = open(store, &ns, ResourceKind::Sequential, 100, now)?;
    let other = open(store, &ns, ResourceKind::Sequential, 100, now)?;
    assert_ne!(id, other, "every open mints a distinct incarnation");

    // Offsets are validated against the committed head: out of order is a
    // conflict and reserves nothing.
    assert_eq!(stage(store, &ns, &id, b"hello ", 0, None, now)?, 6);
    assert!(matches!(
        stage(store, &ns, &id, b"x", 3, None, now),
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(stage(store, &ns, &id, b"world", 6, None, now)?, 11);
    // The byte limit is enforced before anything is installed.
    assert!(matches!(
        stage(store, &ns, &id, &[0u8; 100], 11, None, now),
        Err(StoreError::CapacityExceeded(_))
    ));
    assert!(!store.blob_exists(&Kappa::sha256(&[0u8; 100]))?);
    // An empty member is rejected.
    assert!(matches!(
        stage(store, &ns, &id, b"", 11, None, now),
        Err(StoreError::Rejected(_))
    ));
    let resolved = resource::resolve(store, &ns, &id)?.ok_or("resource vanished")?;
    assert_eq!(resolved.head.total_bytes, 11);
    assert_eq!(resolved.head.member_count, 2);
    assert_eq!(resolved.head.revision, 2);
    assert_eq!(resolved.head.context.as_deref(), Some(&b"context"[..]));
    // Members are committed and recoverable from the head alone.
    let members = resource::members(store, &ns, &resolved.head)?;
    assert_eq!(members.len(), 2);

    // A verified digest mismatch is rejected during preparation.
    let wrong = prepare(
        store,
        ContentIdentity::Verified(Kappa::sha256(b"other")),
        b"bytes",
    );
    assert!(matches!(wrong, Err(StoreError::Rejected(_))));

    let assembled = Kappa::sha256(b"hello world");
    let (result, aliases) = complete(store, &ns, &id, &assembled, &[], Axis::Sha256, now)?;
    assert_eq!(result, assembled);
    // The completing epoch records the composition the new composite's
    // retention of its components rests on, under the identity holding
    // the representation, and replay reconstructs it from history.
    let parts = vec![
        (Kappa::sha256(b"hello "), 6u64),
        (Kappa::sha256(b"world"), 5u64),
    ];
    let recorded = recorded_compositions(store, &ns)?;
    assert_eq!(recorded.len(), 1, "{recorded:?}");
    let composition = &recorded[0];
    assert!(
        composition.identity() == &result || aliases.contains(composition.identity()),
        "{composition:?}"
    );
    assert_eq!(composition.length(), 11);
    let components: Vec<(Kappa, u64)> = composition
        .components()
        .iter()
        .map(|component| (component.identity.clone(), component.length))
        .collect();
    assert_eq!(components, parts);
    let (current, _) = store.epoch_current(&ns)?;
    let replayed = kappa_store::replay_to(store, &ns, current)?;
    assert_eq!(
        replayed.compositions.get(composition.identity()),
        Some(&std::collections::BTreeSet::from([parts]))
    );
    assert_eq!(store.blob_get(&assembled)?, b"hello world");
    assert_eq!(store.blob_get_range(&assembled, 4, 4)?, b"o wo");
    let mut reader = store.blob_open(&assembled)?;
    let mut streamed = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut streamed)?;
    assert_eq!(streamed, b"hello world");

    // Completed: a retry of the same request replays the committed outcome
    // without staging state; the member edges are gone.
    let head = resource::resolve(store, &ns, &id)?.ok_or("completed head vanished")?;
    assert_eq!(head.head.phase, ResourcePhase::Completed);
    assert_eq!(head.head.member_count, 0);
    // The binding fixed at open survives completion, so a replay is still
    // checked against it.
    assert_eq!(head.head.context.as_deref(), Some(&b"context"[..]));
    assert!(resource::members(store, &ns, &head.head)?.is_empty());
    match resource::resolve_completion(store, &ns, &id, &assembled)? {
        Some(Resolution::Replay(binding)) => {
            assert_eq!(binding.result, assembled);
            assert_eq!(binding.receipt.as_deref(), Some(&b"receipt"[..]));
        }
        other => return Err(format!("expected replay, got {other:?}").into()),
    }
    // A different request against the completed head conflicts.
    assert!(matches!(
        resource::resolve_completion(store, &ns, &id, &Kappa::sha256(b"another")),
        Err(StoreError::Conflict(_))
    ));
    // Admission is closed: staging after completion is refused.
    assert!(matches!(
        stage(store, &ns, &id, b"late", 11, None, now),
        Err(StoreError::Conflict(_))
    ));
    Ok(())
}

/// A multi-chunk member completed under a blake3 identity is readable
/// through every mandatory axis.
fn exercise_multi_chunk_axes(store: &(impl Staging + ?Sized)) -> TestResult {
    let ns = create(store, "chunks")?;
    let now = at(1_700_000_001_500);
    let id = open(store, &ns, ResourceKind::Sequential, 0, now)?;
    let content = vec![0x5a; 3 * kappa_store_redb::BLOB_CHUNK_SIZE + 17];
    let claimed = Kappa::blake3(&content);
    let mut offset = 0;
    for part in content.chunks(10_000) {
        offset = stage(store, &ns, &id, part, offset, None, now)?;
    }
    assert_eq!(offset, content.len() as u64);
    let (result, aliases) = complete(store, &ns, &id, &claimed, &[], Axis::Blake3, now)?;
    assert_eq!(result, claimed);
    let secondary = Kappa::sha256(&content);
    assert!(aliases.contains(&secondary), "{aliases:?}");
    assert_eq!(store.blob_get_verified(&claimed)?, content);
    assert_eq!(store.blob_get_verified(&secondary)?, content);
    assert_eq!(store.blob_size(&secondary)?, content.len() as u64);
    Ok(())
}

fn exercise_numbered(store: &(impl Staging + ?Sized)) -> TestResult {
    let ns = create(store, "numbered")?;
    let foreign = create(store, "foreign")?;
    let now = at(1_700_000_002_000);
    let id = open(store, &ns, ResourceKind::Numbered, 1024, now)?;

    // Slots range from 1 to the kind's member limit.
    for slot in [0, resource::max_members(ResourceKind::Numbered) as u64 + 1] {
        assert!(
            matches!(
                stage(store, &ns, &id, b"invalid", slot, None, now),
                Err(StoreError::Rejected(_))
            ),
            "slot {slot}"
        );
    }
    assert!(!store.blob_exists(&Kappa::sha256(b"invalid"))?);
    stage(store, &ns, &id, b"old", 9, Some(b"r-old".to_vec()), now)?;
    stage(store, &ns, &id, b"first", 2, Some(b"r-first".to_vec()), now)?;
    // A slot is replaced through its committed reference, not by scanning.
    let total = stage(
        store,
        &ns,
        &id,
        b"replacement",
        9,
        Some(b"r-new".to_vec()),
        now,
    )?;
    assert_eq!(total, 5 + 11);
    stage(store, &ns, &id, b"unselected", 5, None, now)?;
    let head = resource::resolve(store, &ns, &id)?
        .ok_or("resource vanished")?
        .head;
    assert_eq!(head.member_count, 3);
    let members = resource::members(store, &ns, &head)?;
    let mut positions: Vec<u64> = members.iter().map(|m| m.coordinate.position).collect();
    positions.sort_unstable();
    assert_eq!(positions, [2, 5, 9]);
    let slot9 = members
        .iter()
        .find(|m| m.coordinate.position == 9)
        .ok_or("slot 9 missing")?;
    assert_eq!(slot9.coordinate.receipt.as_deref(), Some(&b"r-new"[..]));
    assert_eq!(slot9.coordinate.length, 11);
    // The replaced member is no longer retained by the resource.
    assert!(!members.iter().any(|m| m.identity == Kappa::sha256(b"old")));

    // The resource is addressed only in its own namespace: it does not
    // resolve there, and a stage or discard there changes nothing here.
    assert!(resource::resolve(store, &foreign, &id)?.is_none());
    assert!(matches!(
        stage(store, &foreign, &id, b"foreign", 1, None, now),
        Err(StoreError::NotFound(_))
    ));
    assert!(!publish(store, &foreign, now, |e| {
        resource::discard(e, &asserter(), &id)
    })?);
    assert_eq!(
        resource::resolve(store, &ns, &id)?
            .ok_or("resource vanished")?
            .head
            .revision,
        head.revision
    );

    // Selection must be non-empty, ascending, and name existing slots. A
    // rejected selection leaves the resource open.
    let request = Kappa::sha256(b"complete 2,9");
    for rejected in [&[9u64, 2][..], &[2, 7], &[]] {
        let outcome = publish(store, &ns, now, |e| {
            resource::prepare(e, &asserter(), &id, &request, rejected).map(|_| ())
        });
        assert!(
            matches!(outcome, Err(StoreError::Rejected(_))),
            "{rejected:?}"
        );
        assert_eq!(
            resource::resolve(store, &ns, &id)?
                .ok_or("resource vanished")?
                .head
                .phase,
            ResourcePhase::Open
        );
    }

    let (assembled, _) = complete(store, &ns, &id, &request, &[2, 9], Axis::Sha256, now)?;
    assert_eq!(assembled, Kappa::sha256(b"firstreplacement"));
    assert_eq!(store.blob_get(&assembled)?, b"firstreplacement");
    // The unselected slot's content is no longer retained by the resource.
    let head = resource::resolve(store, &ns, &id)?
        .ok_or("completed head vanished")?
        .head;
    assert!(resource::members(store, &ns, &head)?.is_empty());
    Ok(())
}

/// A composite that lists one component twice (two equal parts) installs,
/// retires, and releases its component with no divergence recorded: the
/// component is referred to once by the composite, however often listed.
fn exercise_repeated_components(store: &(impl Staging + ?Sized)) -> TestResult {
    let ns = create(store, "repeated")?;
    let now = at(1_700_000_002_250);
    let id = open(store, &ns, ResourceKind::Numbered, 0, now)?;
    let part = b"same part ";
    stage(store, &ns, &id, part, 1, None, now)?;
    stage(store, &ns, &id, part, 2, None, now)?;
    let request = Kappa::sha256(b"complete 1,2");
    let (assembled, aliases) = complete(store, &ns, &id, &request, &[1, 2], Axis::Sha256, now)?;
    let whole = [&part[..], &part[..]].concat();
    assert_eq!(assembled, Kappa::sha256(&whole));
    assert_eq!(store.blob_get(&assembled)?, whole);
    assert_eq!(
        store.repair_indexes()?,
        kappa_store::IndexRepair::default(),
        "a repeated component is not divergence"
    );
    // Nothing names the composite. Its identities retire alias-first (the
    // row holder is retained while an alias selects it, whichever axis
    // holds it); retiring the composite releases its one selection of the
    // repeated part without divergence.
    let mut pending: Vec<Kappa> = std::iter::once(assembled).chain(aliases).collect();
    for _ in 0..=pending.len() {
        let mut retained = Vec::new();
        for identity in pending {
            match publish(store, &ns, now, |e| e.content_retire(&identity))? {
                Retirement::Retired => {}
                Retirement::Retained => retained.push(identity),
                Retirement::Absent => return Err(format!("{identity} vanished").into()),
            }
        }
        pending = retained;
    }
    assert!(pending.is_empty(), "identities never retired: {pending:?}");
    assert_eq!(store.repair_indexes()?, kappa_store::IndexRepair::default());
    Ok(())
}

/// Membership is paged from the anchor's edges: more members than one page
/// are all returned, exactly once, with their coordinates.
fn exercise_member_pagination(store: &(impl Staging + ?Sized)) -> TestResult {
    let ns = create(store, "pagination")?;
    let now = at(1_700_000_002_500);
    let id = open(store, &ns, ResourceKind::Numbered, 0, now)?;
    for slot in 1..=300u64 {
        stage(
            store,
            &ns,
            &id,
            slot.to_string().as_bytes(),
            slot,
            None,
            now,
        )?;
    }
    let head = resource::resolve(store, &ns, &id)?
        .ok_or("resource vanished")?
        .head;
    assert_eq!(head.member_count, 300);
    let members = resource::members(store, &ns, &head)?;
    let mut positions: Vec<u64> = members.iter().map(|m| m.coordinate.position).collect();
    positions.sort_unstable();
    assert_eq!(positions, (1..=300).collect::<Vec<u64>>());
    for member in &members {
        assert_eq!(
            member.identity,
            Kappa::sha256(member.coordinate.position.to_string().as_bytes())
        );
    }
    Ok(())
}

fn exercise(store: &(impl Staging + ?Sized)) -> TestResult {
    exercise_sequential(store)?;
    exercise_multi_chunk_axes(store)?;
    exercise_numbered(store)?;
    exercise_repeated_components(store)?;
    exercise_member_pagination(store)
}

#[test]
fn memory_resources_stage_complete_replay_and_release() -> TestResult {
    let fixture = kappa_store_memory::test_support::test_store()?;
    exercise(fixture.store())?;
    assert_eq!(
        staging_dirs(fixture.blob_root())?,
        Vec::<std::path::PathBuf>::new()
    );
    Ok(())
}

#[test]
fn persistent_resources_stage_complete_replay_and_release() -> TestResult {
    let store = kappa_store_redb::test_support::persistent_store()?;
    exercise(store.store())?;
    assert_eq!(
        staging_dirs(store.blob_root())?,
        Vec::<std::path::PathBuf>::new()
    );
    Ok(())
}
