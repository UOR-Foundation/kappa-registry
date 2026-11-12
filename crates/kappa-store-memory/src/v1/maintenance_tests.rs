//! Maintenance tests: the empty repair and settlement passes, the bounded
//! inventory and its continuation, protection of files open executions and
//! retained readers hold, residue of other tables, and the admission of
//! every step against its budget.

use std::io::Read;
use std::path::PathBuf;
use std::time::{Duration, Instant};

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

fn store() -> Result<InMemoryStore, Box<dyn std::error::Error>> {
    Ok(super::super::test_support::test_store()?.into_store())
}

/// A limit whose deadline has passed.
fn expired() -> WorkLimit {
    let past = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .unwrap_or_else(Instant::now);
    WorkLimit::unbounded().with_deadline(past)
}

/// One whole pass with no budget limit; it must complete.
fn full(store: &InMemoryStore) -> Result<Reclamation, Box<dyn std::error::Error>> {
    let pass = store.reclaim_unowned(&WorkLimit::unbounded(), None)?;
    assert!(pass.complete(), "an unbounded pass did not complete");
    Ok(pass.outcome)
}

/// A pass run in steps of `limit`, accumulated; returns the total and the
/// number of steps.
fn stepped(
    store: &InMemoryStore,
    limit: &WorkLimit,
    per_step: impl Fn(&Work),
) -> Result<(Reclamation, usize), Box<dyn std::error::Error>> {
    let mut total = Reclamation::default();
    let mut from = None;
    let mut steps = 0usize;
    loop {
        let step = store.reclaim_unowned(limit, from)?;
        steps += 1;
        per_step(&step.consumed);
        total.accumulate(&step.outcome);
        match step.continuation {
            Some(next) => from = Some(next),
            None => return Ok((total, steps)),
        }
        assert!(steps < 100_000, "the pass made no progress");
    }
}

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

/// Residue of an earlier process under `store`'s root: three instance
/// files and a preparation file of another table.
fn plant_residue(store: &InMemoryStore) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let root = store.allocations.root().to_path_buf();
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
    residue.push(stale);
    Ok(residue)
}

#[test]
fn repair_and_settlement_are_empty_complete_passes_admitted_by_their_limit() -> TestResult {
    let store = store()?;
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
    let repair = store.repair_indexes(&WorkLimit::unbounded(), None)?;
    assert!(repair.complete());
    assert_eq!(repair.outcome, IndexRepair::default());
    assert_eq!(repair.consumed, Work::default());
    let settlement = store.settle(&WorkLimit::unbounded(), None)?;
    assert!(settlement.complete());
    assert_eq!(settlement.outcome, Settlement::default());
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
    // A passed deadline refuses the step.
    assert!(store.repair_indexes(&expired(), None).is_err());
    assert!(store.settle(&expired(), None).is_err());
    Ok(())
}

/// The inventory charges every move before making it, resumes from its
/// continuation, removes another table's files, keeps every file of this
/// table's records and its preparations, and reports what it cannot
/// explain.
#[test]
fn inventory_is_bounded_per_step_and_resumes() -> TestResult {
    let store = store()?;
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
    let residue = plant_residue(&store)?;
    let preparation = root.join(format!("{}live", staging_prefix(store.allocations.nonce())));
    std::fs::write(&preparation, b"in flight")?;
    let stranger = root.join("notes.txt");
    std::fs::write(&stranger, b"?")?;
    let expected_owned = own_instance_files(&store)?;

    let one = WorkLimit::unbounded().with(Dimension::Entries, 1);
    let (total, steps) = stepped(&store, &one, |consumed| {
        assert!(
            consumed.get(Dimension::Entries) <= 1,
            "a step examined {} entries with a limit of 1",
            consumed.get(Dimension::Entries)
        );
    })?;
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
        "directory moves were not counted against the limit"
    );
    for path in &residue {
        assert!(!path.exists(), "{} survived", path.display());
    }
    assert!(preparation.exists() && stranger.exists());
    for identity in &owned {
        assert!(file_of(&store, &ns, identity)?.exists());
    }
    // A complete pass starts the next from the beginning.
    let again = full(&store)?;
    assert_eq!(
        (again.files, again.owned, again.protected),
        (0, expected_owned, 1)
    );
    Ok(())
}

/// A step that may open one directory handle defers the next directory it
/// finds and opens it first when resumed: a pass in such steps finds
/// exactly what an unbounded pass finds.
#[test]
fn a_refused_directory_admission_is_resumed_not_skipped() -> TestResult {
    let bounded = store()?;
    let unbounded = store()?;
    for store in [&bounded, &unbounded] {
        plant_residue(store)?;
    }
    let one_handle = WorkLimit::unbounded().with(Dimension::Handles, 1);
    let (total, steps) = stepped(&bounded, &one_handle, |consumed| {
        assert!(consumed.get(Dimension::Handles) <= 1);
    })?;
    assert!(steps > 1, "the residue lies under more than one directory");
    assert_eq!(total, full(&unbounded)?);
    assert_eq!(total.files, 4);
    Ok(())
}

/// A continuation is refused by another store instance before that store
/// does any work.
#[test]
fn a_continuation_of_another_store_is_refused_before_any_work() -> TestResult {
    let first = store()?;
    let second = store()?;
    plant_residue(&first)?;
    let residue = plant_residue(&second)?;
    let one = WorkLimit::unbounded().with(Dimension::Entries, 1);
    let paused = first.reclaim_unowned(&one, None)?;
    let continuation = paused
        .continuation
        .ok_or("a one-entry step completed the pass")?;
    let refused = second.reclaim_unowned(&WorkLimit::unbounded(), Some(continuation));
    assert!(
        matches!(refused, Err(StoreError::Rejected(_))),
        "{refused:?}"
    );
    for path in &residue {
        assert!(
            path.exists(),
            "the refusing store removed {}",
            path.display()
        );
    }
    // The empty passes refuse it too.
    let paused = first.reclaim_unowned(&one, None)?;
    let continuation = paused
        .continuation
        .ok_or("a one-entry step completed the pass")?;
    assert!(
        first
            .repair_indexes(&WorkLimit::unbounded(), Some(continuation))
            .is_err(),
        "a reclamation continuation was accepted by repair"
    );
    Ok(())
}

/// A step whose deadline has already passed makes no cleanup attempt: the
/// owed file stays, and the pass resumes from its continuation.
#[test]
fn a_passed_deadline_removes_nothing() -> TestResult {
    let store = store()?;
    let ns = created(&store, "deadline")?;
    let content = VerifiedContent::compute(Axis::Sha256, &[5u8; 64])?;
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2))?)?;
    execution.blob_put(&content)?;
    let path = store
        .allocations
        .existing(content.kappa())
        .ok_or("staged content is live")?
        .path()
        .to_path_buf();
    execution.abort()?;
    assert!(store.allocations.owes(), "the aborted file is owed");
    let late = store.reclaim_unowned(&expired(), None)?;
    assert_eq!(
        late.outcome,
        Reclamation::default(),
        "work was done past the deadline"
    );
    assert_eq!(late.consumed, Work::default());
    assert!(late.continuation.is_some());
    assert!(path.exists(), "an owed file was removed past the deadline");
    assert_eq!(full(&store)?.files, 1);
    assert!(!path.exists());
    Ok(())
}

/// A directory deeper than the layout is reported and not entered.
#[test]
fn a_directory_deeper_than_the_layout_is_reported_not_entered() -> TestResult {
    let store = store()?;
    let deep = store
        .allocations
        .root()
        .join("sha256")
        .join("aa")
        .join("bb")
        .join("deeper");
    std::fs::create_dir_all(&deep)?;
    let buried = deep.join("buried");
    std::fs::write(&buried, b"?")?;
    let pass = full(&store)?;
    assert_eq!(pass.unrecognized, 1);
    assert_eq!(pass.files, 0);
    assert!(buried.exists(), "a file below the layout was acted on");
    Ok(())
}

/// A suspended walk owns what its open listings need: their handles and
/// its deferred-path allowance are reserved while it is suspended, and
/// the filesystem scope they read outlives the store that returned the
/// continuation. Dropping the continuation closes the listings, releases
/// the reservations and then the scope.
#[test]
fn a_suspended_walk_owns_its_listings_scope_and_capacity() -> TestResult {
    let acquired = super::super::test_support::test_store()?;
    let scope = acquired.root().path().to_path_buf();
    let store = acquired.into_store();
    plant_residue(&store)?;
    let handles = std::sync::Arc::clone(&store.maintenance_handles);
    let bytes = std::sync::Arc::clone(&store.maintenance_bytes);
    // Two moves: enter the root, then enter its first directory.
    let paused =
        store.reclaim_unowned(&WorkLimit::unbounded().with(Dimension::Entries, 2), None)?;
    let continuation = paused
        .continuation
        .ok_or("a two-move step completed the pass")?;
    assert!(
        handles.used() >= 1,
        "the suspended walk holds no listing handle"
    );
    assert_eq!(bytes.used(), DEFERRED_PATH_ALLOWANCE);
    drop(store);
    assert!(
        scope.is_dir(),
        "the scope was removed while a suspended walk held listings in it"
    );
    drop(continuation);
    assert_eq!(
        (handles.used(), bytes.used()),
        (0, 0),
        "cancellation kept a reservation"
    );
    assert!(!scope.exists(), "the scope outlived its last holder");
    Ok(())
}

/// A file an open execution installed is held by its candidate: the
/// inventory keeps it while the execution is open, the abort releases it
/// and the next step removes it, and a published one stays.
#[test]
fn files_of_an_open_execution_are_kept_until_it_ends() -> TestResult {
    use kappa_store::{ContentIdentity, ContentPreparation, PreparationBounds};
    let store = store()?;
    let ns = created(&store, "in-flight")?;
    let bytes = vec![7u8; 4096];
    let identity = Kappa::sha256(&bytes);
    let prepare = || {
        store.prepare_content(
            ContentIdentity::Verified(identity.clone()),
            &mut bytes.as_slice(),
            PreparationBounds {
                maximum: 4096,
                deadline: Instant::now() + Duration::from_secs(10),
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
    assert_eq!(
        full(&store)?.files,
        0,
        "a file an open execution holds was removed"
    );
    assert!(path.exists());
    execution.abort()?;
    assert_eq!(
        full(&store)?.files,
        1,
        "the aborted execution's file was not discharged"
    );
    assert!(!path.exists());
    let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(3))?)?;
    execution.content_install(prepare()?)?;
    execution.publish()?;
    let published = file_of(&store, &ns, &identity)?;
    assert_eq!(full(&store)?.files, 0);
    assert!(published.exists());
    Ok(())
}

/// Evidence an open execution stages through `blob_put` is held by its
/// candidate exactly like installed content.
#[test]
fn staged_evidence_of_an_open_execution_is_kept() -> TestResult {
    let store = store()?;
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
    assert_eq!(full(&store)?.files, 0, "staged evidence was removed");
    assert!(path.exists());
    execution.publish()?;
    assert_eq!(full(&store)?.files, 0);
    assert_eq!(file_of(&store, &ns, content.kappa())?, path);
    Ok(())
}

/// A reader keeps every file it may read through retirement and
/// reclamation; its file is removed only after the reader drops.
#[test]
fn a_retained_reader_outlives_retirement_and_reclamation() -> TestResult {
    let store = store()?;
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
    assert_eq!(full(&store)?.files, 0, "a file a reader holds was removed");
    let mut read = Vec::new();
    reader.read_to_end(&mut read)?;
    assert_eq!(read, content.content());
    drop(reader);
    assert_eq!(full(&store)?.files, 1);
    assert!(!path.exists());
    Ok(())
}
