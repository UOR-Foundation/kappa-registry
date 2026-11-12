//! The fault backend's own contract: what a crash loses, what restore
//! returns, where a role-placed crash lands, and that every seed has an
//! exact expected file.

use std::path::Path;

use super::fault::{
    Fault, FaultBackend, Fired, Loss, OpOutcome, Role, SECTOR, SplitMix, StorageOp,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn read_all(path: &Path) -> std::io::Result<Vec<u8>> {
    std::fs::read(path)
}

fn sector(i: u64) -> u64 {
    i * SECTOR
}

/// A tracked write after a sync is taken back by a crash of everything
/// unsynced: the file returns to its bytes and length at the sync.
#[test]
fn a_crash_restores_the_file_to_its_last_performed_sync() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("state.redb");
    let (factory, control) = FaultBackend::factory(&path)?;
    let backend = factory();
    backend.write(0, &[1u8; 8])?;
    backend.sync_data()?;
    control.track_unsynced(true);
    backend.write(4, &[2u8; 8])?;
    backend.set_len(sector(4))?;
    backend.write(sector(3), &[3u8; 8])?;
    assert_ne!(read_all(&path)?[..8], [1u8; 8], "control: the write landed");
    assert_eq!(
        read_all(&path)?.len(),
        sector(4) as usize,
        "control: the file grew"
    );
    let lost = control.crash(Loss::All);
    assert_eq!(lost, 2 * SECTOR, "two touched sectors are lost");
    let refused = backend.write(0, &[9u8; 8]);
    assert!(refused.is_err(), "a crashed backend refuses writes");
    assert_eq!(
        control.trace().last(),
        Some(&(StorageOp::Write { offset: 0, len: 8 }, OpOutcome::Refused))
    );
    match control.restore() {
        Err(error) => assert!(error.to_string().contains("still open"), "{error}"),
        Ok(()) => return Err("restore ran beneath an open handle".into()),
    }
    backend.close()?;
    drop(backend);
    control.restore()?;
    assert_eq!(
        read_all(&path)?,
        [1u8; 8],
        "exactly the synced bytes and length"
    );
    assert_eq!(
        control.fired().lost_bytes,
        0,
        "restore consumed the lost record"
    );
    let reopened = factory();
    let mut back = [0u8; 8];
    reopened.read(0, &mut back)?;
    assert_eq!(back, [1u8; 8]);
    reopened.write(0, &[4u8; 8])?;
    assert_eq!(
        read_all(&path)?,
        [4u8; 8],
        "a restored control writes again"
    );
    reopened.close()?;
    Ok(())
}

/// Every seed has an exact expected file: the same generator, drawn in
/// `(file, sector)` order, decides which sectors are lost, so the test
/// computes the file a device would have left and the backend must match
/// it byte for byte. Across the seeds, some run keeps a later sector while
/// losing an earlier one, the case a prefix model never produces, and
/// writes to one sector collapse to one decision.
#[test]
fn independent_loss_matches_its_oracle_for_every_seed() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("state.redb");
    let (factory, control) = FaultBackend::factory(&path)?;
    const SECTORS: u64 = 4;
    let synced = vec![0u8; (SECTORS * SECTOR) as usize];
    let mut later_kept_earlier_lost = false;
    for seed in 0..64u64 {
        let backend = factory();
        backend.write(0, &synced)?;
        backend.sync_data()?;
        control.track_unsynced(true);
        for i in 0..SECTORS {
            backend.write(sector(i), &[i as u8 + 1; 8])?;
        }
        // A second write into sector 0 collapses with the first.
        backend.write(16, &[9u8; 8])?;
        let lost = control.crash(Loss::Independent { percent: 50, seed });
        backend.close()?;
        control.restore()?;
        // The oracle: one decision per touched sector, in sector order.
        let mut rng = SplitMix(seed);
        let mut expected = synced.clone();
        let mut expected_lost = 0u64;
        let mut kept = [false; SECTORS as usize];
        for i in 0..SECTORS {
            if rng.percent() < 50 {
                expected_lost += SECTOR;
            } else {
                kept[i as usize] = true;
                let start = sector(i) as usize;
                expected[start..start + 8].copy_from_slice(&[i as u8 + 1; 8]);
                if i == 0 {
                    expected[16..24].copy_from_slice(&[9u8; 8]);
                }
            }
        }
        assert_eq!(lost, expected_lost, "seed {seed}: lost bytes");
        assert_eq!(read_all(&path)?, expected, "seed {seed}: file contents");
        if kept[3] && !kept[1] {
            later_kept_earlier_lost = true;
        }
    }
    assert!(
        later_kept_earlier_lost,
        "no seed in 0..64 lost an earlier sector while keeping a later one"
    );
    let backend = factory();
    control.track_unsynced(true);
    backend.write(0, &[7u8; 8])?;
    assert_eq!(
        control.crash(Loss::Independent {
            percent: 100,
            seed: 1
        }),
        SECTOR
    );
    backend.close()?;
    control.restore()?;
    let backend = factory();
    control.track_unsynced(true);
    backend.write(0, &[7u8; 8])?;
    assert_eq!(
        control.crash(Loss::Independent {
            percent: 0,
            seed: 1
        }),
        0
    );
    backend.close()?;
    control.restore()?;
    assert_eq!(read_all(&path)?[..8], [7u8; 8], "percent 0 keeps the write");
    Ok(())
}

/// `CrashAtSync { role, nth }` crashes inside the nth sync of a file of
/// that role, before synchronizing: the other role's syncs do not count,
/// the crashed commit's sectors are what a later `crash` selects from, and
/// every file of the control is refused afterwards.
#[test]
fn crash_at_sync_lands_in_the_named_role_and_reaches_every_file() -> TestResult {
    let dir = tempfile::tempdir()?;
    let registry_path = dir.path().join("store.redb");
    let namespace_path = dir.path().join("state.redb");
    let (registry_factory, control) = FaultBackend::factory(&registry_path)?;
    let namespace_factory = control.factory_for(&namespace_path, Role::Namespace)?;
    let registry = registry_factory();
    let namespace = namespace_factory();
    control.track_unsynced(true);
    control.arm(Fault::CrashAtSync {
        role: Role::Namespace,
        nth: 1,
    });
    registry.write(0, &[1u8; 8])?;
    registry.sync_data()?; // a registry sync: not the named role, performed
    namespace.write(0, &[2u8; 8])?;
    let crashed = namespace.sync_data(); // the namespace's first sync: the crash
    assert!(crashed.is_err(), "the named sync is refused");
    assert!(control.crashed());
    assert!(
        registry.write(8, &[3u8; 8]).is_err(),
        "every file of the control is dead after the crash"
    );
    assert_eq!(
        control.crash(Loss::All),
        SECTOR,
        "only the namespace sector is unsynced; the registry synced"
    );
    registry.close()?;
    namespace.close()?;
    control.restore()?;
    assert_eq!(read_all(&registry_path)?, [1u8; 8]);
    assert_eq!(
        read_all(&namespace_path)?,
        Vec::<u8>::new(),
        "returned to its length at its last sync"
    );
    let fired = control.fired();
    assert_eq!(fired.refused, 2, "the crashing sync and the write after it");
    assert_eq!(fired.performed, 3, "two writes and the registry sync");
    Ok(())
}

/// A performed sync, reported failed or not, ends what a crash may take
/// back of that file; the counts name what fired; a second restore has
/// nothing to undo.
#[test]
fn a_performed_sync_is_durable_and_the_counts_name_what_fired() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("state.redb");
    let (factory, control) = FaultBackend::factory(&path)?;
    let backend = factory();
    control.track_unsynced(true);
    backend.write(0, &[5u8; 8])?;
    control.arm(Fault::FailSyncAfter);
    assert!(backend.sync_data().is_err(), "reported failed");
    control.disarm();
    let lost = control.crash(Loss::All);
    assert_eq!(lost, 0, "the performed sync made the write durable");
    backend.close()?;
    control.restore()?;
    assert_eq!(read_all(&path)?, [5u8; 8]);
    assert_eq!(
        control.fired(),
        Fired {
            performed: 0,
            refused: 0,
            performed_then_failed: 1,
            lost_bytes: 0,
        },
        "the trace since arm holds exactly the faulted sync"
    );
    assert!(
        control.restore().is_err(),
        "a second restore has nothing to undo"
    );
    let summed = Fired {
        performed: 1,
        refused: 2,
        performed_then_failed: 3,
        lost_bytes: 4,
    }
    .plus(Fired {
        performed: 10,
        refused: 20,
        performed_then_failed: 30,
        lost_bytes: 40,
    });
    assert_eq!(
        summed,
        Fired {
            performed: 11,
            refused: 22,
            performed_then_failed: 33,
            lost_bytes: 44,
        }
    );
    Ok(())
}
