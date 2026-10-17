use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn table() -> Result<(tempfile::TempDir, AllocationTable), std::io::Error> {
    let root = tempfile::tempdir()?;
    let table = AllocationTable::new(root.path().to_path_buf(), None);
    Ok((root, table))
}

#[test]
fn one_identity_installs_once_while_a_handle_lives() -> TestResult {
    let (_root, table) = table()?;
    let storage = Kappa::sha256(b"bytes");
    let first = table.install_bytes(&storage, b"bytes")?;
    let second = table.install_bytes(&storage, b"bytes")?;
    assert!(first.same(&second));
    assert!(first.path().exists());
    assert_eq!(first.bytes(), 5);
    assert_eq!(table.owed(), (0, 0));
    Ok(())
}

#[test]
fn a_losing_concurrent_install_keeps_only_the_live_instance() -> TestResult {
    let (_root, table) = table()?;
    let storage = Kappa::sha256(b"race");
    let kept = table.install_bytes(&storage, b"race")?;
    // A second preparation staged its own file before the first installed.
    let mut staged = table.staging_file()?;
    std::io::Write::write_all(&mut staged, b"race")?;
    let staged_path = staged.path().to_path_buf();
    let chosen = table.install(&storage, staged, Segments::of(b"race"))?;
    assert!(chosen.same(&kept));
    assert!(
        !staged_path.exists(),
        "the staged file was dropped, not installed"
    );
    assert!(kept.path().exists());
    Ok(())
}

#[test]
fn cleanup_of_a_dead_instance_never_removes_a_later_instance_of_the_same_identity() -> TestResult {
    let (_root, table) = table()?;
    let storage = Kappa::sha256(b"reused");
    let old = table.install_bytes(&storage, b"reused")?;
    let old_path = old.path().to_path_buf();
    let old_instance = old.instance();
    drop(old);
    assert_eq!(table.owed(), (1, 6));
    assert!(table.accounts_for(&storage, old_instance));
    // The identity is reacquired before maintenance discharges the old
    // instance: the new instance has its own path.
    let new = table.install_bytes(&storage, b"reused")?;
    assert_ne!(new.instance(), old_instance);
    assert_ne!(new.path(), old_path.as_path());
    let done = table.discharge(10);
    assert_eq!(done.files, 1);
    assert!(!old_path.exists());
    assert!(
        new.path().exists(),
        "the later instance survived the old cleanup"
    );
    assert!(table.existing(&storage).is_some_and(|live| live.same(&new)));
    assert!(!table.accounts_for(&storage, old_instance));
    Ok(())
}

#[test]
fn a_failed_removal_stays_owed_and_charged() -> TestResult {
    let (_root, table) = table()?;
    let storage = Kappa::sha256(b"stuck");
    let allocation = table.install_bytes(&storage, b"stuck")?;
    let path = allocation.path().to_path_buf();
    let instance = allocation.instance();
    drop(allocation);
    // A directory where the file was makes `remove_file` fail.
    std::fs::remove_file(&path)?;
    std::fs::create_dir(&path)?;
    let done = table.discharge(10);
    assert_eq!(done.retained, 1);
    assert_eq!(table.owed(), (1, 5));
    assert!(table.accounts_for(&storage, instance));
    std::fs::remove_dir(&path)?;
    let done = table.discharge(10);
    assert_eq!((done.absent, done.retained), (1, 0));
    assert_eq!(table.owed(), (0, 0));
    Ok(())
}

#[test]
fn discharge_is_bounded_by_its_limit() -> TestResult {
    let (_root, table) = table()?;
    for index in 0..5u8 {
        let bytes = [index];
        drop(table.install_bytes(&Kappa::sha256(&bytes), &bytes)?);
    }
    assert_eq!(table.discharge(2).files, 2);
    assert_eq!(table.owed().0, 3);
    Ok(())
}

/// A later process over the same root numbers its instances from 1 again;
/// the table nonce keeps its paths apart from the earlier process's
/// files, so installation never collides with residue.
#[test]
fn a_later_table_over_the_same_root_never_collides_with_earlier_files() -> TestResult {
    let root = tempfile::tempdir()?;
    let storage = Kappa::sha256(b"restart");
    let earlier = AllocationTable::new(root.path().to_path_buf(), None);
    let residue = earlier.install_bytes(&storage, b"restart")?;
    let residue_path = residue.path().to_path_buf();
    let earlier_nonce = earlier.nonce();
    // The earlier process ends without removing its file.
    std::mem::forget(residue);
    std::mem::forget(earlier);
    let later = AllocationTable::new(root.path().to_path_buf(), None);
    assert_ne!(later.nonce(), earlier_nonce);
    let fresh = later.install_bytes(&storage, b"restart")?;
    assert_ne!(fresh.path(), residue_path.as_path());
    assert!(fresh.path().exists() && residue_path.exists());
    Ok(())
}

#[test]
fn a_handle_outliving_the_table_keeps_its_file_until_it_drops() -> TestResult {
    let (_root, table) = table()?;
    let storage = Kappa::sha256(b"escaping");
    let reader = table.install_bytes(&storage, b"escaping")?;
    let owed_earlier = {
        let bytes = [7u8];
        let dropped = table.install_bytes(&Kappa::sha256(&bytes), &bytes)?;
        let path = dropped.path().to_path_buf();
        drop(dropped);
        path
    };
    drop(table);
    // The reader still reads; the file owed before the table dropped is
    // still owed by the queue the reader keeps alive.
    assert!(reader.path().exists());
    assert!(owed_earlier.exists());
    let path = reader.path().to_path_buf();
    drop(reader);
    // The last owner gone, the queue removes every file it still owed.
    assert!(!path.exists());
    assert!(!owed_earlier.exists());
    Ok(())
}
