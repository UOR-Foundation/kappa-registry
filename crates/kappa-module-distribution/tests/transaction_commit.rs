//! Transaction commit as one execution: the members' pins and the
//! resource's discard publish with the commit's epoch or not at all, a
//! failed commit leaves the transaction committable, the commit of an empty
//! transaction ends it, and a committed transaction cannot commit again.

use std::time::{Duration, Instant};

use kappa_fixture::FixtureRoot;
use kappa_handler::{HandlerError, Outcome, clock_at};
use kappa_module_distribution::transaction::commit_transaction;
use kappa_store::resource;
use kappa_store::{
    Axis, BlobStore, ClockMs, ContentIdentity, ContentPreparation, EpochStore, Execution,
    ExecutionStore, Kappa, NamespaceRef, NamespaceStore, PreparationBounds, ResourceKind,
    StoreError,
};
use kappa_store_memory::InMemoryStore;
use kappa_store_memory::test_support::StoreSpec;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const fn at(ms: i64) -> ClockMs {
    ClockMs::from_raw(ms << 16)
}

fn asserter() -> Kappa {
    Kappa::sha256(b"transaction commit")
}

/// One scope holding the store; the namespace is created in its own epoch.
struct Fixture {
    store: InMemoryStore,
    namespace: NamespaceRef,
    root: FixtureRoot,
}

impl Fixture {
    fn close(self) -> TestResult {
        let Self {
            store,
            namespace: _,
            root,
        } = self;
        drop(store);
        Ok(root.close()?)
    }

    fn publish<T>(
        &self,
        now: ClockMs,
        write: impl FnOnce(&mut dyn Execution) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut execution = self
            .store
            .begin_execution(&self.namespace, &clock_at(now)?)?;
        let value = write(&mut *execution)?;
        execution.publish()?;
        Ok(value)
    }

    /// Begin a transaction staging every item of `contents`, each put its
    /// own epoch as the handler publishes it.
    fn staged(&self, contents: &[&[u8]]) -> Result<(String, Vec<Kappa>), StoreError> {
        let now = at(1_700_000_001_000);
        let id = self.publish(now, |e| {
            Ok(resource::open(
                e,
                &asserter(),
                ResourceKind::Membership,
                0,
                now.add_physical_ms(3_600_000),
                None,
            )?
            .id())
        })?;
        let mut members = Vec::with_capacity(contents.len());
        for content in contents {
            let prepared = self.store.prepare_content(
                ContentIdentity::Computed(Axis::Sha256),
                &mut &content[..],
                PreparationBounds {
                    maximum: 4096,
                    deadline: Instant::now() + Duration::from_secs(30),
                },
            )?;
            let installed = self.publish(now, |e| {
                Ok(resource::stage(e, &asserter(), &id, prepared, 0, None)?.1)
            })?;
            members.push(installed.kappa);
        }
        Ok((id, members))
    }

    fn pinned(&self, identity: &Kappa) -> Result<bool, StoreError> {
        Ok(kappa_store::absent(
            self.store
                .namespace_get_meta(&self.namespace, &format!("_pin/{identity}")),
        )?
        .is_some())
    }

    fn open(&self, id: &str) -> Result<bool, StoreError> {
        Ok(resource::resolve(&self.store, &self.namespace, id)?.is_some())
    }
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = FixtureRoot::temporary()?;
    let store = StoreSpec::new().in_root(&root).acquire()?.into_store();
    let namespace = NamespaceRef::generate("transactions", at(1_700_000_000_000))?;
    let mut execution = store.begin_execution(&namespace, &clock_at(at(1_700_000_000_000))?)?;
    execution.namespace_create(None, None)?;
    execution.publish()?;
    Ok(Fixture {
        store,
        namespace,
        root,
    })
}

#[test]
fn commit_pins_the_members_and_ends_the_transaction_in_one_epoch_and_not_before() -> TestResult {
    let fixture = fixture()?;
    let (alpha, beta): (&[u8], &[u8]) = (b"alpha", b"beta");
    let (id, members) = fixture.staged(&[alpha, beta])?;
    assert_eq!(members, [Kappa::sha256(alpha), Kappa::sha256(beta)]);
    // Staged content is epoch-committed by its put and retained by the
    // transaction.
    assert_eq!(fixture.store.blob_get(&members[0])?, alpha);
    let before = fixture.store.epoch_current(&fixture.namespace)?;

    let mut execution = fixture
        .store
        .begin_execution(&fixture.namespace, &clock_at(at(1_700_000_002_000))?)?;
    let now = at(1_700_000_002_000);
    let mut work = commit_transaction(asserter(), id.clone(), members.clone(), now);
    let Outcome::Publish(mut promoted) = work(&mut *execution)? else {
        return Err("a commit must publish".into());
    };
    promoted.sort();
    let mut expected = vec![members[0].to_string(), members[1].to_string()];
    expected.sort();
    assert_eq!(promoted, expected);

    // Private to the execution: the pins and the discard are not visible.
    assert!(!fixture.pinned(&members[0])?);
    assert!(fixture.open(&id)?);
    assert_eq!(fixture.store.epoch_current(&fixture.namespace)?, before);

    let published = execution.publish()?;
    assert_eq!(
        fixture.store.epoch_current(&fixture.namespace)?,
        (published.epoch_number, published.root.clone())
    );
    assert!(fixture.pinned(&members[0])?);
    assert!(fixture.pinned(&members[1])?);
    assert!(!fixture.open(&id)?);
    assert_eq!(fixture.store.blob_get(&members[1])?, beta);

    // A committed transaction cannot commit again.
    let mut again = fixture
        .store
        .begin_execution(&fixture.namespace, &clock_at(at(1_700_000_003_000))?)?;
    assert!(matches!(
        work(&mut *again),
        Err(HandlerError::NotFound { .. })
    ));
    again.abort()?;
    fixture.close()
}

#[test]
fn failed_commit_leaves_the_transaction_committable_and_a_retry_publishes() -> TestResult {
    let fixture = fixture()?;
    let content: &[u8] = b"retried";
    let (id, members) = fixture.staged(&[content])?;
    let now = at(1_700_000_002_000);

    let mut failing = fixture
        .store
        .begin_execution(&fixture.namespace, &clock_at(now)?)?;
    let expired = Instant::now()
        .checked_sub(Duration::from_secs(1))
        .ok_or("monotonic clock cannot express a past deadline")?;
    failing.set_deadline(expired);
    let mut work = commit_transaction(asserter(), id.clone(), members.clone(), now);
    assert!(matches!(work(&mut *failing)?, Outcome::Publish(_)));
    assert!(matches!(
        failing.publish(),
        Err(StoreError::DeadlineExceeded { .. })
    ));

    assert!(!fixture.pinned(&members[0])?);
    assert!(fixture.open(&id)?);
    assert_eq!(fixture.store.blob_get(&members[0])?, content);

    let mut retry = fixture
        .store
        .begin_execution(&fixture.namespace, &clock_at(at(1_700_000_003_000))?)?;
    let Outcome::Publish(promoted) = work(&mut *retry)? else {
        return Err("a retried commit must publish".into());
    };
    assert_eq!(promoted, vec![members[0].to_string()]);
    retry.publish()?;
    assert!(fixture.pinned(&members[0])?);
    assert!(!fixture.open(&id)?);
    fixture.close()
}

#[test]
fn commit_of_an_empty_transaction_ends_it() -> TestResult {
    let fixture = fixture()?;
    let (id, members) = fixture.staged(&[])?;
    assert!(members.is_empty());
    let now = at(1_700_000_002_000);
    let mut execution = fixture
        .store
        .begin_execution(&fixture.namespace, &clock_at(now)?)?;
    let mut work = commit_transaction(asserter(), id.clone(), members, now);
    let Outcome::Publish(promoted) = work(&mut *execution)? else {
        return Err("an empty commit still ends the transaction".into());
    };
    assert_eq!(promoted, Vec::<String>::new());
    execution.publish()?;
    assert!(!fixture.open(&id)?);
    fixture.close()
}
