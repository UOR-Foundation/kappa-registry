//! The retirement transitions of a namespace's lifecycle, each schedule
//! driven directly against the storage: what a retiring namespace admits,
//! what holds its release back, what an unknown or refused record leaves,
//! and the state a recorded retirement establishes at the next open.
//!
//! Every schedule keeps no idle handle, so a slot no activity holds is
//! evicted and reopened from its retirement record: the records the
//! closures commit are the fixture's fence table, the durable state a
//! reopened slot is decided by.

use std::sync::Arc;

use kappa_store::StoreError;

use crate::storage::fixture::{Fences, create, storage, storage_fenced};
use crate::storage::{
    Fence, NamespaceController, NamespaceStorage, Opening, Recording, Refusal, WriterGate,
};
use crate::storage_instance::StorageInstance;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ID: [u8; 16] = [1; 16];

/// Storage at `root` keeping no idle handle and admitting `active`
/// activities, fenced by the returned records.
fn fenced(root: &std::path::Path, active: usize) -> (NamespaceStorage, Arc<Fences>) {
    let fences = Arc::new(Fences::default());
    (storage_fenced(root, 0, active, Arc::clone(&fences)), fences)
}

/// Storage of `ID` created and left idle; its instance.
fn created(storage: &NamespaceStorage) -> Result<StorageInstance, StoreError> {
    let grant = storage.admit_publish(&ID, &create(storage))?;
    Ok(grant.controller().instance)
}

/// The intent record: durable for the controller it is shown.
fn record_intent(
    fences: &Fences,
) -> impl FnOnce(&NamespaceController) -> Result<(), StoreError> + '_ {
    move |controller| fences.record(controller.instance, Fence::Retiring)
}

/// The release record of `instance`.
fn record_release(
    fences: &Fences,
    instance: StorageInstance,
) -> impl FnOnce() -> Result<(), Recording> + '_ {
    move || Ok(fences.record(instance, Fence::Released)?)
}

fn directory(root: &std::path::Path) -> std::path::PathBuf {
    NamespaceController::directory(root, &ID)
}

/// A retiring namespace serves reads; publication, maintenance and
/// recorded removal are refused for as long as the intent holds it.
#[test]
fn retiring_admits_reads_only() -> TestResult {
    let root = tempfile::tempdir()?;
    let (storage, fences) = fenced(root.path(), 4);
    created(&storage)?;
    let intent = storage.begin_retiring(&ID, record_intent(&fences))?;
    drop(storage.admit_read(&ID)?);
    assert!(matches!(
        storage.admit_publish(&ID, &Opening::Existing),
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(storage.maintain(&ID)?, Err(Refusal::Retiring)));
    assert!(storage.try_maintain(&ID)?.is_none());
    assert!(matches!(
        storage.remove_recorded(&ID, |_| Ok(())),
        Err(StoreError::Conflict(_))
    ));
    drop(intent);
    // An intent dropped unreleased leaves the namespace retiring: its
    // durable record is what recovery resumes from, after the idle slot
    // is evicted and reopened.
    assert!(matches!(
        storage.admit_publish(&ID, &Opening::Existing),
        Err(StoreError::Conflict(_))
    ));
    assert!(storage.resume_retiring(&ID)?.is_some());
    Ok(())
}

/// How long a thread is given to show it is not blocked.
const WINDOW: std::time::Duration = std::time::Duration::from_millis(200);

/// A publisher holding the writer gate when the retirement begins is
/// waited for; one admitted earlier that reaches the gate while the intent
/// holds it is refused at once, not after waiting the retirement out.
#[test]
fn the_intent_waits_for_the_writer_and_refuses_later_writers() -> TestResult {
    let root = tempfile::tempdir()?;
    let (storage, fences) = fenced(root.path(), 4);
    created(&storage)?;
    let writer = storage.admit_publish(&ID, &Opening::Existing)?;
    let token = WriterGate::acquire(&writer)?;
    let late = storage.admit_publish(&ID, &Opening::Existing)?;
    let intent = std::thread::scope(|scope| {
        let retiring = scope.spawn(|| storage.begin_retiring(&ID, record_intent(&fences)));
        std::thread::sleep(WINDOW);
        assert!(
            !retiring.is_finished(),
            "the intent was recorded while a writer held the gate"
        );
        drop(token);
        retiring.join().map_err(|_| "retiring thread panicked")
    })??;
    std::thread::scope(|scope| {
        let refused = scope.spawn(|| WriterGate::acquire(&late).map(drop));
        std::thread::sleep(WINDOW);
        let waited = !refused.is_finished();
        // Unblock a defective acquire so the scope can end.
        drop(intent);
        let outcome = refused.join().map_err(|_| "acquiring thread panicked")?;
        assert!(!waited, "a refused writer waited for the retirement to end");
        assert!(
            matches!(outcome, Err(StoreError::Conflict(_))),
            "{outcome:?}"
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    drop((late, writer));
    Ok(())
}

/// A record the intent's closure refuses changes nothing.
#[test]
fn a_refused_intent_record_leaves_the_namespace_open() -> TestResult {
    let root = tempfile::tempdir()?;
    let storage = storage(root.path(), 0, 2);
    created(&storage)?;
    assert!(matches!(
        storage.begin_retiring(&ID, |_| Err(StoreError::Rejected("refused".into()))),
        Err(StoreError::Rejected(_))
    ));
    drop(storage.admit_publish(&ID, &Opening::Existing)?);
    assert!(storage.resume_retiring(&ID)?.is_none());
    Ok(())
}

/// A reader holding the namespace keeps its storage: the release is
/// refused, the namespace stays retiring, and once the reader ends the
/// resumed intent releases it.
#[test]
fn a_reader_holds_the_release_back() -> TestResult {
    let root = tempfile::tempdir()?;
    let (storage, fences) = fenced(root.path(), 4);
    let instance = created(&storage)?;
    let intent = storage.begin_retiring(&ID, record_intent(&fences))?;
    let reader = storage.admit_read(&ID)?;
    let mut recorded = false;
    assert!(matches!(
        intent.release(
            |_| Ok(()),
            || {
                recorded = true;
                Ok(())
            }
        ),
        Err(StoreError::Conflict(_))
    ));
    assert!(
        !recorded,
        "a release was recorded while a reader held the namespace"
    );
    assert!(directory(root.path()).exists());
    assert_eq!(reader.controller().id, ID, "the reader's storage is intact");
    drop(reader);
    let intent = storage
        .resume_retiring(&ID)?
        .ok_or("the namespace left retiring")?;
    intent.release(|_| Ok(()), record_release(&fences, instance))?;
    assert!(!directory(root.path()).exists());
    assert!(matches!(
        storage.admit_read(&ID),
        Err(StoreError::NotFound(_))
    ));
    Ok(())
}

/// The release's verification is the last check before the record: a
/// refusal records nothing and keeps the namespace retiring.
#[test]
fn a_refused_verification_records_nothing() -> TestResult {
    let root = tempfile::tempdir()?;
    let (storage, fences) = fenced(root.path(), 2);
    created(&storage)?;
    let intent = storage.begin_retiring(&ID, record_intent(&fences))?;
    let mut recorded = false;
    assert!(matches!(
        intent.release(
            |_| Err(StoreError::Conflict("head moved".into())),
            || {
                recorded = true;
                Ok(())
            }
        ),
        Err(StoreError::Conflict(_))
    ));
    assert!(!recorded);
    assert!(directory(root.path()).exists());
    assert!(storage.resume_retiring(&ID)?.is_some());
    Ok(())
}

/// A refused release record keeps the namespace retiring; one whose commit
/// outcome is unknown leaves it unresolved, its storage kept and nothing
/// admitted.
#[test]
fn release_record_outcomes() -> TestResult {
    let root = tempfile::tempdir()?;
    let (storage, fences) = fenced(root.path(), 2);
    created(&storage)?;
    let intent = storage.begin_retiring(&ID, record_intent(&fences))?;
    assert!(matches!(
        intent.release(
            |_| Ok(()),
            || Err(Recording::Refused(StoreError::Internal("refused".into())))
        ),
        Err(StoreError::Internal(_))
    ));
    let intent = storage
        .resume_retiring(&ID)?
        .ok_or("a refused record left retiring")?;
    assert!(matches!(
        intent.release(
            |_| Ok(()),
            || Err(Recording::Unknown(StoreError::Internal(
                "commit outcome unknown".into()
            )))
        ),
        Err(StoreError::Internal(_))
    ));
    assert!(directory(root.path()).exists());
    storage.evict_idle();
    assert!(matches!(
        storage.admit_read(&ID),
        Err(StoreError::Unavailable(_))
    ));
    assert!(storage.resume_retiring(&ID).is_err());
    Ok(())
}

/// An abandoned intent reopens the namespace for every purpose; one whose
/// record cannot be removed stays retiring.
#[test]
fn abandonment_reopens_only_once_the_intent_is_removed() -> TestResult {
    let root = tempfile::tempdir()?;
    let (storage, fences) = fenced(root.path(), 2);
    let instance = created(&storage)?;
    let intent = storage.begin_retiring(&ID, record_intent(&fences))?;
    assert!(matches!(
        intent.abandon(|| Err(StoreError::Internal("intent kept".into()))),
        Err(StoreError::Internal(_))
    ));
    let intent = storage
        .resume_retiring(&ID)?
        .ok_or("a failed abandon left retiring")?;
    intent.abandon(|| fences.remove(&instance))?;
    drop(storage.admit_publish(&ID, &Opening::Existing)?);
    assert!(storage.try_maintain(&ID)?.is_some());
    Ok(())
}

/// After a restart the instance's recorded retirement decides its state
/// before anything is admitted: an intent opens it retiring, a release
/// opens it released, and another instance of the namespace is unaffected.
#[test]
fn the_record_fences_storage_at_its_next_open() -> TestResult {
    let root = tempfile::tempdir()?;
    let fences = Arc::new(Fences::default());
    let instance = created(&storage_fenced(root.path(), 0, 2, Arc::clone(&fences)))?;
    let other = StorageInstance::generate(ID)?;
    fences.record(other, Fence::Released)?;
    {
        let restarted = storage_fenced(root.path(), 0, 2, Arc::clone(&fences));
        drop(restarted.admit_publish(&ID, &Opening::Existing)?);
    }
    fences.record(instance, Fence::Retiring)?;
    {
        let restarted = storage_fenced(root.path(), 0, 2, Arc::clone(&fences));
        drop(restarted.admit_read(&ID)?);
        assert!(matches!(
            restarted.admit_publish(&ID, &Opening::Existing),
            Err(StoreError::Conflict(_))
        ));
        assert!(restarted.resume_retiring(&ID)?.is_some());
    }
    fences.record(instance, Fence::Released)?;
    let restarted = storage_fenced(root.path(), 0, 2, fences);
    assert!(matches!(
        restarted.admit_read(&ID),
        Err(StoreError::NotFound(_))
    ));
    assert!(directory(root.path()).exists(), "opening removed storage");
    Ok(())
}
