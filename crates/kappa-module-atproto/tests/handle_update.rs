//! AT Protocol handle updates through `_handles` executions.

use kappa_handler::clock_at;
use kappa_module_atproto::identity::update_handle::{did_meta_key, did_tag, publish_handle};
use kappa_module_atproto::protocol_id;
use kappa_store::clock::{CausalTime, ClockMs, TimeError};
use kappa_store::{
    EpochStore, ExecutionStore, HandleRecord, IdentityStore, Kappa, NamespaceRef, NamespaceStore,
    StoreError, TagStore, namespace_ensure,
};
use kappa_store_memory::{InMemoryStore, test_support};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GRACE: i64 = 1000;

struct Fixture {
    store: InMemoryStore,
    handles: NamespaceRef,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let store = test_support::test_store()?.into_store();
        let handles = namespace_ensure(&store, "_handles", None, None, &clock_at(at(1000)?)?)?;
        Ok(Self { store, handles })
    }

    /// Publish `record` for `did` in one execution, or discard the
    /// execution when the update fails, as the XRPC handler does.
    fn update(&self, now: ClockMs, did: &str, record: &HandleRecord) -> Result<(), StoreError> {
        let mut execution = self.store.begin_execution(&self.handles, &clock_at(now)?)?;
        match publish_handle(&mut *execution, did, record, GRACE) {
            Ok(()) => {
                execution.publish()?;
                Ok(())
            }
            Err(error) => {
                execution.abort()?;
                Err(error)
            }
        }
    }

    fn epoch(&self) -> Result<u64, StoreError> {
        Ok(self.store.epoch_current(&self.handles)?.0)
    }

    fn owner(&self, handle: &str) -> Result<Option<Kappa>, StoreError> {
        match self.store.handle_get(protocol_id().clone(), handle) {
            Ok(record) => Ok(Some(record.anchor)),
            Err(StoreError::NotFound(_)) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// The timestamp the HLC authority issues at physical millisecond `ms`
/// with a zero logical counter: physical time in the upper 48 bits. Grace
/// periods are physical milliseconds on this encoding.
fn at(ms: u64) -> Result<ClockMs, TimeError> {
    Ok(CausalTime::new(ms, 0)?.encoded())
}

fn record(anchor: &Kappa, handle: &str, now: ClockMs, attested: Option<ClockMs>) -> HandleRecord {
    HandleRecord {
        anchor: anchor.clone(),
        handle: handle.into(),
        protocol: protocol_id().clone(),
        claimed_at_ms: now.as_i64(),
        attested_at_ms: attested.map(ClockMs::as_i64),
    }
}

#[test]
fn unattested_handle_within_grace_conflicts_and_publishes_nothing() -> TestResult {
    let f = Fixture::new()?;
    let alice = Kappa::sha256(b"alice anchor");
    let mallory = Kappa::sha256(b"mallory anchor");
    f.update(
        at(2000)?,
        "did:plc:alice",
        &record(&alice, "alice.test", at(2000)?, None),
    )?;
    let epoch = f.epoch()?;
    let result = f.update(
        at(2500)?,
        "did:plc:mallory",
        &record(&mallory, "alice.test", at(2500)?, None),
    );
    assert!(matches!(result, Err(StoreError::Conflict(_))), "{result:?}");
    assert_eq!(f.epoch()?, epoch);
    assert_eq!(f.owner("alice.test")?, Some(alice));
    Ok(())
}

#[test]
fn unattested_handle_past_grace_is_reclaimed() -> TestResult {
    let f = Fixture::new()?;
    let alice = Kappa::sha256(b"alice anchor");
    let bob = Kappa::sha256(b"bob anchor");
    f.update(
        at(2000)?,
        "did:plc:alice",
        &record(&alice, "shared.test", at(2000)?, None),
    )?;
    let epoch = f.epoch()?;
    f.update(
        at(3500)?,
        "did:plc:bob",
        &record(&bob, "shared.test", at(3500)?, None),
    )?;
    assert_eq!(f.epoch()?, epoch + 1);
    assert_eq!(f.owner("shared.test")?, Some(bob));
    Ok(())
}

#[test]
fn attested_handle_conflicts_after_grace() -> TestResult {
    let f = Fixture::new()?;
    let carol = Kappa::sha256(b"carol anchor");
    let mallory = Kappa::sha256(b"mallory anchor");
    f.update(
        at(2000)?,
        "did:plc:carol",
        &record(&carol, "carol.test", at(2000)?, Some(at(2000)?)),
    )?;
    let epoch = f.epoch()?;
    let result = f.update(
        at(90_000)?,
        "did:plc:mallory",
        &record(&mallory, "carol.test", at(90_000)?, None),
    );
    assert!(matches!(result, Err(StoreError::Conflict(_))), "{result:?}");
    assert_eq!(f.epoch()?, epoch);
    assert_eq!(f.owner("carol.test")?, Some(carol));
    Ok(())
}

#[test]
fn update_replaces_previous_handle_and_binds_did_in_one_epoch() -> TestResult {
    let f = Fixture::new()?;
    let alice = Kappa::sha256(b"alice anchor");
    f.update(
        at(2000)?,
        "did:plc:alice",
        &record(&alice, "old.test", at(2000)?, None),
    )?;
    let epoch = f.epoch()?;
    let renamed = record(&alice, "new.test", at(3000)?, None);
    f.update(at(3000)?, "did:plc:alice", &renamed)?;
    assert_eq!(f.epoch()?, epoch + 1);
    assert_eq!(f.owner("old.test")?, None);
    assert_eq!(f.owner("new.test")?, Some(alice));
    assert_eq!(
        f.store.tag_get(&f.handles, &did_tag(&renamed))?.kappa,
        Kappa::sha256(b"did:plc:alice")
    );
    assert_eq!(
        f.store
            .namespace_get_meta(&f.handles, &did_meta_key(&renamed))?,
        b"did:plc:alice".to_vec()
    );
    Ok(())
}
