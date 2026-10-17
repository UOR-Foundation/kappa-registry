//! Repository writes applied through executions on the memory backend.

use kappa_handler::{HandlerError, clock_at, events_from_ledger};
use kappa_module_atproto::protocol_id;
use kappa_module_atproto::repo::apply::{
    Applied, RecordAction, RecordOp, RecordSwap, apply_record_writes,
};
use kappa_store::canonical::from_canonical;
use kappa_store::clock::ClockMs;
use kappa_store::{
    BlobStore, EpochMutation, EpochStore, ExecutionStore, NamespaceRef, StoreError, TagStore,
    namespace_ensure,
};
use kappa_store_memory::{InMemoryStore, test_support};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const REPO: &str = "did:plc:alice";
const COLLECTION: &str = "app.bsky.feed.post";

struct Fixture {
    store: InMemoryStore,
    ns: NamespaceRef,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let store = test_support::test_store()?.into_store();
        let ns = namespace_ensure(
            &store,
            REPO,
            None,
            Some(protocol_id()),
            &clock_at(at(1000))?,
        )?;
        Ok(Self { store, ns })
    }

    /// Apply `ops` in one execution and publish it when it committed,
    /// discarding it otherwise, as the XRPC write handlers do.
    fn write(
        &self,
        now: ClockMs,
        swap_commit: Option<&str>,
        ops: &[RecordOp],
    ) -> Result<Applied, HandlerError> {
        let mut execution = self.store.begin_execution(&self.ns, &clock_at(now)?)?;
        match apply_record_writes(&self.store, &mut *execution, REPO, swap_commit, ops) {
            Ok(applied) => {
                if applied.commit.is_some() {
                    execution.publish()?;
                } else {
                    execution.abort()?;
                }
                Ok(applied)
            }
            Err(error) => {
                execution.abort()?;
                Err(error)
            }
        }
    }

    fn epoch(&self) -> Result<u64, StoreError> {
        Ok(self.store.epoch_current(&self.ns)?.0)
    }

    fn record(&self, rkey: &str) -> Result<Option<String>, StoreError> {
        match self
            .store
            .tag_get(&self.ns, &format!("record/{COLLECTION}/{rkey}"))
        {
            Ok(entry) => Ok(Some(entry.kappa.to_string())),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn head(&self) -> Result<String, StoreError> {
        Ok(self
            .store
            .tag_get(&self.ns, "commit/head")?
            .kappa
            .to_string())
    }

    /// Names of every mutation the current epoch's ledger commits.
    fn current_epoch_mutations(&self) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        let (number, root) = self.store.epoch_current(&self.ns)?;
        let epoch = self.store.epoch_get(&root)?;
        let ledger = self.store.blob_get_verified(epoch.ledger_root())?;
        let mutations: Vec<EpochMutation> = from_canonical(&ledger)?;
        Ok(events_from_ledger(REPO, number, &root, &mutations)?
            .into_iter()
            .map(|event| event.name)
            .collect())
    }
}

const fn at(ms: i64) -> ClockMs {
    ClockMs::from_raw(ms)
}

fn create(rkey: &str, text: &str) -> RecordOp {
    RecordOp {
        collection: COLLECTION.into(),
        rkey: rkey.into(),
        action: RecordAction::Create(serde_json::json!({"text": text})),
        swap: None,
    }
}

fn protocol_code(error: &HandlerError) -> Option<&str> {
    match error {
        HandlerError::Protocol { code, .. } => Some(code),
        _ => None,
    }
}

fn cids(applied: &Applied) -> Vec<Option<String>> {
    applied
        .records
        .iter()
        .map(|record| record.as_ref().map(|record| record.cid.clone()))
        .collect()
}

#[test]
fn apply_writes_with_several_records_publishes_one_epoch_containing_all() -> TestResult {
    let f = Fixture::new()?;
    let before = f.epoch()?;
    let applied = f.write(
        at(2000),
        None,
        &[
            create("a1", "one"),
            create("a2", "two"),
            create("a3", "three"),
        ],
    )?;
    assert_eq!(f.epoch()?, before + 1);
    assert_eq!(
        vec![f.record("a1")?, f.record("a2")?, f.record("a3")?],
        cids(&applied)
    );
    let commit = applied.commit.ok_or("records changed but no commit")?;
    assert_eq!(f.head()?, commit.kappa.to_string());
    let mutations = f.current_epoch_mutations()?;
    for name in [
        "record/app.bsky.feed.post/a1",
        "record/app.bsky.feed.post/a2",
        "record/app.bsky.feed.post/a3",
        "commit/head",
        "commit/rev",
    ] {
        assert!(
            mutations.iter().any(|mutation| mutation == name),
            "{name} missing from {mutations:?}"
        );
    }
    Ok(())
}

#[test]
fn failing_write_in_batch_publishes_nothing() -> TestResult {
    let f = Fixture::new()?;
    f.write(at(2000), None, &[create("a1", "one")])?;
    let epoch = f.epoch()?;
    let head = f.head()?;
    let result = f.write(
        at(3000),
        None,
        &[create("a2", "two"), create("a1", "duplicate")],
    );
    let Err(error) = result else {
        return Err("a create of an existing record succeeded".into());
    };
    assert_eq!(protocol_code(&error), Some("InvalidRequest"), "{error}");
    assert_eq!(f.epoch()?, epoch);
    assert_eq!(f.head()?, head);
    assert_eq!(f.record("a2")?, None);
    Ok(())
}

#[test]
fn swap_commit_mismatch_returns_invalid_swap_and_publishes_nothing() -> TestResult {
    let f = Fixture::new()?;
    f.write(at(2000), None, &[create("a1", "one")])?;
    let epoch = f.epoch()?;
    let head = f.head()?;
    let stale = kappa_store::Kappa::sha256(b"stale commit").to_string();
    let Err(error) = f.write(at(3000), Some(&stale), &[create("a2", "two")]) else {
        return Err("a stale swapCommit was accepted".into());
    };
    assert_eq!(protocol_code(&error), Some("InvalidSwap"), "{error}");
    assert_eq!(f.epoch()?, epoch);
    assert_eq!(f.record("a2")?, None);

    f.write(at(4000), Some(&head), &[create("a2", "two")])?;
    assert_eq!(f.epoch()?, epoch + 1);
    Ok(())
}

#[test]
fn swap_record_mismatch_returns_invalid_swap_and_publishes_nothing() -> TestResult {
    let f = Fixture::new()?;
    let first = f.write(at(2000), None, &[create("a1", "one")])?;
    let epoch = f.epoch()?;
    let update = |swap| RecordOp {
        collection: COLLECTION.into(),
        rkey: "a1".into(),
        action: RecordAction::Update(serde_json::json!({"text": "replaced"})),
        swap: Some(swap),
    };
    for swap in [
        RecordSwap::Absent,
        RecordSwap::Cid(kappa_store::Kappa::sha256(b"other").to_string()),
    ] {
        let Err(error) = f.write(at(3000), None, &[update(swap)]) else {
            return Err("a mismatched swapRecord was accepted".into());
        };
        assert_eq!(protocol_code(&error), Some("InvalidSwap"), "{error}");
        assert_eq!(f.epoch()?, epoch);
    }
    let current = cids(&first)
        .pop()
        .flatten()
        .ok_or("create reported no record")?;
    let replaced = f.write(at(4000), None, &[update(RecordSwap::Cid(current))])?;
    assert_eq!(f.epoch()?, epoch + 1);
    assert_eq!(vec![f.record("a1")?], cids(&replaced));
    Ok(())
}

#[test]
fn delete_of_absent_record_publishes_nothing() -> TestResult {
    let f = Fixture::new()?;
    f.write(at(2000), None, &[create("a1", "one")])?;
    let epoch = f.epoch()?;
    let delete = RecordOp {
        collection: COLLECTION.into(),
        rkey: "missing".into(),
        action: RecordAction::Delete,
        swap: None,
    };
    let applied = f.write(at(3000), None, &[delete])?;
    assert_eq!(applied.commit, None);
    assert_eq!(f.epoch()?, epoch);
    Ok(())
}

#[test]
fn delete_removes_record_and_advances_head() -> TestResult {
    let f = Fixture::new()?;
    f.write(at(2000), None, &[create("a1", "one"), create("a2", "two")])?;
    let head = f.head()?;
    let delete = RecordOp {
        collection: COLLECTION.into(),
        rkey: "a1".into(),
        action: RecordAction::Delete,
        swap: None,
    };
    let applied = f.write(at(3000), Some(&head), &[delete])?;
    assert_eq!(f.record("a1")?, None);
    assert!(f.record("a2")?.is_some());
    let commit = applied.commit.ok_or("deletion produced no commit")?;
    assert_eq!(f.head()?, commit.kappa.to_string());
    assert_ne!(f.head()?, head);
    Ok(())
}

#[test]
fn invalid_record_key_is_rejected_before_writing() -> TestResult {
    let f = Fixture::new()?;
    let epoch = f.epoch()?;
    let Err(error) = f.write(at(2000), None, &[create("has space", "one")]) else {
        return Err("an invalid record key was accepted".into());
    };
    assert_eq!(protocol_code(&error), Some("InvalidRequest"), "{error}");
    assert_eq!(f.epoch()?, epoch);
    Ok(())
}
