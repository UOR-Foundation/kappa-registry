//! Key store lifecycle under injected filesystem faults and process death.

use std::os::unix::process::ExitStatusExt;

use super::*;

#[test]
fn activation_retry_reestablishes_durability_before_cleanup() -> TestResult {
    let ks = key_store()?;
    let old = first(&ks)?;
    let old_record = ks
        .keys_dir()
        .join(format!("{}.key", record_name(old.signer().public_key())));
    let keys = ks.node_keys()?;
    let next = keys.stage_successor("ed25519")?.authority;
    // Fail the directory synchronization after `current` was renamed: the
    // pointer names the successor but is not confirmed durable.
    // Synchronizations before it: confirm(record).
    ks.dir().arm(Fault::DirSync, 1);
    assert!(keys.settle(next.anchor()).is_err());
    assert_eq!(
        pointer(&ks, "current")?,
        Some(record_name(next.signer().public_key()))
    );
    assert!(
        old_record.exists(),
        "cleanup ran before activation was durable"
    );
    // The retry finds the pointer already naming the successor and still
    // synchronizes before cleanup: failing that synchronization fails the
    // retry and keeps the retired key.
    ks.dir().arm(Fault::DirSync, 1);
    assert!(keys.settle(next.anchor()).is_err());
    assert!(old_record.exists(), "cleanup ran on an unconfirmed pointer");
    let settled = keys.settle(next.anchor())?;
    settled.cleanup?;
    assert!(!old_record.exists());
    Ok(())
}

#[test]
fn unacknowledged_link_and_rename_are_completed() -> TestResult {
    let ks = key_store()?;
    first(&ks)?;
    let keys = ks.node_keys()?;
    ks.dir().arm(Fault::LinkUnacknowledged, 0);
    let staged = keys.stage_successor("ed25519")?;
    staged.cleanup?;
    let next = staged.authority;
    assert_eq!(node_records(&ks)?.len(), 2);
    ks.dir().arm(Fault::RenameUnacknowledged, 0);
    let settled = keys.settle(next.anchor())?;
    settled.cleanup?;
    assert_eq!(
        pointer(&ks, "current")?,
        Some(record_name(next.signer().public_key()))
    );
    assert!(entries(ks.keys_dir(), ".stage-")?.is_empty());
    Ok(())
}

#[test]
fn failed_staging_leaves_no_secret_and_no_successor() -> TestResult {
    let ks = key_store()?;
    let old = first(&ks)?;
    let keys = ks.node_keys()?;
    for point in [Fault::StageWrite, Fault::Link] {
        ks.dir().arm(point, 0);
        assert!(keys.stage_successor("ed25519").is_err(), "{point:?}");
        assert!(entries(ks.keys_dir(), ".stage-")?.is_empty(), "{point:?}");
        assert!(keys.successor()?.is_none(), "{point:?}");
        assert_eq!(
            node_records(&ks)?,
            vec![record_name(old.signer().public_key())],
            "{point:?}"
        );
    }
    // A failed pointer rename leaves the durable record unselected; the
    // next settlement retires it.
    ks.dir().arm(Fault::Rename, 0);
    assert!(keys.stage_successor("ed25519").is_err());
    assert!(keys.successor()?.is_none());
    keys.settle(old.anchor())?.cleanup?;
    assert_eq!(
        node_records(&ks)?,
        vec![record_name(old.signer().public_key())]
    );
    Ok(())
}

#[test]
fn cleanup_failure_is_reported_and_repeated() -> TestResult {
    let ks = key_store()?;
    let old = first(&ks)?;
    let keys = ks.node_keys()?;
    let next = keys.stage_successor("ed25519")?.authority;
    ks.dir().arm(Fault::Unlink, 0);
    let settled = keys.settle(next.anchor())?;
    assert_eq!(settled.authority.anchor(), next.anchor());
    assert!(
        settled.cleanup.is_err(),
        "a failed removal was not reported"
    );
    assert_eq!(
        pointer(&ks, "current")?,
        Some(record_name(next.signer().public_key()))
    );
    let again = keys.settle(next.anchor())?;
    again.cleanup?;
    assert_eq!(
        node_records(&ks)?,
        vec![record_name(next.signer().public_key())]
    );
    assert!(!node_records(&ks)?.contains(&record_name(old.signer().public_key())));
    Ok(())
}

#[test]
fn process_death_during_activation_resolves_to_committed_evidence() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let path = root.resolve(keys())?;
    let old = first(&key_store_in(&root, keys())?)?;
    let status = child("abort-activation", &path)?;
    assert_eq!(status.signal(), Some(6), "child did not abort: {status:?}");
    let ks = key_store_in(&root, keys())?;
    let custody = ks.node_keys()?;
    let next = custody.successor()?.ok_or("staged successor lost")?;
    assert_eq!(custody.candidates("ed25519")?.keys.len(), 2);
    // Whichever authority the backend committed is restored and the other
    // retired; here, the backend kept the old one.
    let settled = custody.settle(old.anchor())?;
    settled.cleanup?;
    assert_eq!(settled.authority.anchor(), old.anchor());
    assert!(!node_records(&ks)?.contains(&record_name(next.signer().public_key())));
    Ok(())
}

#[test]
fn process_death_during_staging_leaves_no_secret_after_reopen() -> TestResult {
    let root = FixtureRoot::temporary()?;
    let path = root.resolve(keys())?;
    let old = first(&key_store_in(&root, keys())?)?;
    let status = child("abort-staging", &path)?;
    assert_eq!(status.signal(), Some(6), "child did not abort: {status:?}");
    assert_eq!(
        entries(&path, ".stage-")?.len(),
        1,
        "no staged secret to recover"
    );
    let ks = key_store_in(&root, keys())?;
    assert!(entries(&path, ".stage-")?.is_empty());
    let custody = ks.node_keys()?;
    assert!(custody.successor()?.is_none());
    assert_eq!(
        custody.settle(old.anchor())?.authority.anchor(),
        old.anchor()
    );
    Ok(())
}
