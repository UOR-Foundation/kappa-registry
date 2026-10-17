//! Maintenance tests: repair, the bounded inventory, protection of files
//! open executions and retained readers hold, and residue of other tables.

use std::io::Read;
use std::path::PathBuf;

use kappa_handler::clock_at;
use kappa_store::{
    Axis, BlobStore, ClockMs, EpochStore, ExecutionStore, NamespaceRef, TagStore, TagUpdate,
    VerifiedContent,
};
use kappa_types::kappa::Kappa;

use super::super::InMemoryStore;
use super::super::cache_layout::{instance_path, staging_prefix};
use super::super::view::Representation;
use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// The file `kappa` selects in `ns`'s published view, through an alias.
fn file_of(store: &InMemoryStore, ns: &NamespaceRef, kappa: &Kappa) -> Result<PathBuf, StoreError> {
    let view = store.view(ns.id());
    let mut current = kappa.clone();
    for _ in 0..2 {
        match view
            .admitted
            .get(&current)
            .map(|admission| &admission.representation)
        {
            Some(Representation::File(allocation)) => return Ok(allocation.path().to_path_buf()),
            Some(Representation::Alias(holder)) => current = holder.clone(),
            other => {
                return Err(StoreError::Internal(format!(
                    "{kappa} selects {other:?}, not a file"
                )));
            }
        }
    }
    Err(StoreError::Internal(format!("{kappa} aliases an alias")))
}

/// Files under the root whose name carries this table's nonce: the oracle
/// the walk's owned figure is checked against, taken by a plain listing.
fn own_instance_files(store: &InMemoryStore) -> Result<u64, std::io::Error> {
    let marker = format!(".{:016x}-", store.allocations.nonce());
    let mut count = 0u64;
    let mut pending = vec![store.allocations.root().to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else if entry.file_name().to_string_lossy().contains(&marker) {
                count += 1;
            }
        }
    }
    Ok(count)
}

fn created(store: &InMemoryStore, name: &str) -> Result<NamespaceRef, Box<dyn std::error::Error>> {
    let ns = NamespaceRef::generate(name, ClockMs::from_raw(1))?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(1))?)?;
    execution.namespace_create(None, None)?;
    execution.publish()?;
    Ok(ns)
}

#[test]
fn repair_finds_nothing_to_rebuild_and_changes_nothing() -> TestResult {
    let store = super::super::test_support::test_store()?.into_store();
    let ns = created(&store, "repair")?;
    let content = VerifiedContent::compute(Axis::Sha256, b"indexed")?;
    let kappa = content.kappa().clone();
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2))?)?;
    execution.blob_put(&content)?;
    execution.tag_put(
        "kept",
        &TagUpdate::Set {
            kappa: kappa.clone(),
        },
    )?;
    execution.publish()?;
    let committed = (store.epoch_current(&ns)?, store.tag_get(&ns, "kept")?.kappa);
    let revision = store.view(ns.id()).revision;
    assert_eq!(store.repair_indexes()?, IndexRepair::default());
    assert_eq!(
        store.view(ns.id()).revision,
        revision,
        "repair published a view"
    );
    assert_eq!(store.view(ns.id()).references.get(&kappa), Some(&1));
    assert_eq!(
        (store.epoch_current(&ns)?, store.tag_get(&ns, "kept")?.kappa),
        committed
    );
    Ok(())
}

/// The inventory examines at most its limit per step, resumes where it
/// stopped, removes another table's files, keeps every file of this
/// table's records and its preparations, and reports what it cannot
/// explain.
#[test]
fn inventory_is_bounded_per_step_and_resumes() -> TestResult {
    let store = super::super::test_support::test_store()?.into_store();
    let ns = created(&store, "inventory")?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2))?)?;
    let mut owned = Vec::new();
    for index in 0..3u8 {
        let content = VerifiedContent::compute(Axis::Sha256, &[index; 8])?;
        execution.blob_put(&content)?;
        owned.push(content.kappa().clone());
    }
    execution.publish()?;
    let root = store.allocations.root().to_path_buf();
    // Residue of an earlier process: instance files and a preparation
    // file of another table.
    let foreign = store.allocations.nonce() ^ 1;
    let mut residue = Vec::new();
    for index in 10..13u8 {
        let path = instance_path(&root, &Kappa::sha256(&[index; 8]), foreign, 1)?;
        std::fs::create_dir_all(path.parent().ok_or("instance path has a parent")?)?;
        std::fs::write(&path, [index; 8])?;
        residue.push(path);
    }
    let stale = root.join(format!("{}stale", staging_prefix(foreign)));
    std::fs::write(&stale, b"stale preparation")?;
    let preparation = root.join(format!("{}live", staging_prefix(store.allocations.nonce())));
    std::fs::write(&preparation, b"in flight")?;
    let stranger = root.join("notes.txt");
    std::fs::write(&stranger, b"?")?;
    let expected_owned = own_instance_files(&store)?;

    let mut steps = 0usize;
    let mut total = Reclamation::default();
    loop {
        let step = store.reclaim_unowned(1)?;
        steps += 1;
        let examined = step.files + step.retained() + step.absent + step.failed;
        assert!(
            examined <= 1,
            "a step examined {examined} entries with a limit of 1"
        );
        total.accumulate(&step);
        if step.complete {
            break;
        }
    }
    assert_eq!(total.files, 4, "every residue file was removed");
    assert_eq!(total.bytes, 24 + b"stale preparation".len() as u64);
    assert_eq!(
        total.owned, expected_owned,
        "every file of this table's records is owned"
    );
    assert_eq!((total.protected, total.unrecognized), (1, 1));
    assert_eq!((total.absent, total.failed), (0, 0));
    // Directories count against the limit: more steps than files.
    let files = total.files + total.owned + total.protected + total.unrecognized;
    assert!(
        steps as u64 > files,
        "directory entries were not counted against the limit"
    );
    for path in residue.iter().chain([&stale]) {
        assert!(!path.exists(), "{} survived", path.display());
    }
    assert!(preparation.exists() && stranger.exists());
    for identity in &owned {
        assert!(file_of(&store, &ns, identity)?.exists());
    }
    // A complete pass starts the next from the beginning.
    let again = store.reclaim_unowned(usize::MAX)?;
    assert!(again.complete);
    assert_eq!(
        (again.files, again.owned, again.protected),
        (0, expected_owned, 1)
    );
    Ok(())
}

/// A file an open execution installed is held by its candidate: the
/// inventory keeps it while the execution is open, the abort releases it
/// and the next step removes it, and a published one stays.
#[test]
fn files_of_an_open_execution_are_kept_until_it_ends() -> TestResult {
    use kappa_store::{ContentIdentity, ContentPreparation, PreparationBounds};
    let store = super::super::test_support::test_store()?.into_store();
    let ns = created(&store, "in-flight")?;
    let bytes = vec![7u8; 4096];
    let identity = Kappa::sha256(&bytes);
    let prepare = || {
        store.prepare_content(
            ContentIdentity::Verified(identity.clone()),
            &mut bytes.as_slice(),
            PreparationBounds {
                maximum: 4096,
                deadline: std::time::Instant::now() + std::time::Duration::from_secs(10),
            },
        )
    };
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2))?)?;
    execution.content_install(prepare()?)?;
    let path = store
        .allocations
        .existing(&identity)
        .ok_or("an installed allocation is live")?
        .path()
        .to_path_buf();
    let pass = store.reclaim_unowned(usize::MAX)?;
    assert!(pass.complete);
    assert_eq!(pass.files, 0, "a file an open execution holds was removed");
    assert!(path.exists());
    execution.abort()?;
    let pass = store.reclaim_unowned(usize::MAX)?;
    assert_eq!(
        pass.files, 1,
        "the aborted execution's file was not discharged"
    );
    assert!(!path.exists());
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(3))?)?;
    execution.content_install(prepare()?)?;
    execution.publish()?;
    let published = file_of(&store, &ns, &identity)?;
    let pass = store.reclaim_unowned(usize::MAX)?;
    assert_eq!(pass.files, 0);
    assert!(published.exists());
    Ok(())
}

/// Evidence an open execution stages through `blob_put` is held by its
/// candidate exactly like installed content.
#[test]
fn staged_evidence_of_an_open_execution_is_kept() -> TestResult {
    let store = super::super::test_support::test_store()?.into_store();
    let ns = created(&store, "staged")?;
    let content = VerifiedContent::compute(Axis::Sha256, b"evidence")?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2))?)?;
    execution.blob_put(&content)?;
    let path = store
        .allocations
        .existing(content.kappa())
        .ok_or("staged evidence is live")?
        .path()
        .to_path_buf();
    assert_eq!(
        store.reclaim_unowned(usize::MAX)?.files,
        0,
        "staged evidence was removed"
    );
    assert!(path.exists());
    execution.publish()?;
    assert_eq!(store.reclaim_unowned(usize::MAX)?.files, 0);
    assert_eq!(file_of(&store, &ns, content.kappa())?, path);
    Ok(())
}

/// A reader keeps every file it may read through retirement and
/// reclamation; its file is removed only after the reader drops.
#[test]
fn a_retained_reader_outlives_retirement_and_reclamation() -> TestResult {
    let store = super::super::test_support::test_store()?.into_store();
    let ns = created(&store, "reader")?;
    let content = VerifiedContent::compute(Axis::Sha256, &[9u8; 1024])?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2))?)?;
    execution.blob_put(&content)?;
    execution.publish()?;
    let path = file_of(&store, &ns, content.kappa())?;
    let mut reader = store.blob_open_in(&ns, content.kappa())?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(3))?)?;
    // Retiring the identity releases its digest family with it.
    assert_eq!(
        execution.content_retire(content.kappa())?,
        kappa_store::execution::Retirement::Retired
    );
    execution.publish()?;
    assert!(!store.blob_exists_in(&ns, content.kappa())?);
    assert!(
        !store
            .view(ns.id())
            .admitted
            .values()
            .any(|admission| matches!(&admission.representation, Representation::File(a) if a.path() == path)),
        "a family member still selects the retired file"
    );
    assert_eq!(
        store.reclaim_unowned(usize::MAX)?.files,
        0,
        "a file a reader holds was removed"
    );
    let mut read = Vec::new();
    reader.read_to_end(&mut read)?;
    assert_eq!(read, content.content());
    drop(reader);
    assert_eq!(store.reclaim_unowned(usize::MAX)?.files, 1);
    assert!(!path.exists());
    Ok(())
}
