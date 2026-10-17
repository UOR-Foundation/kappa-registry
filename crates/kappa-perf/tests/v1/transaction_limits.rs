//! PERF-STO-007: staged transaction limits. The per-transaction byte limit
//! is enforced with `CapacityExceeded` at the limit before anything is
//! installed; a refused put reserves nothing; restaging identical content
//! converges; abort and expiry release the membership; expiry is measured
//! in physical time on the HLC clock production issues.
//!
//! Release races, completion and namespace binding are covered by
//! `kappa-store-redb/tests/resource_staging.rs`.

use std::time::{Duration, Instant};

use kappa_handler::clock_at;
use kappa_store::kappa::Kappa;
use kappa_store::resource;
use kappa_store::{
    ClockMs, ContentIdentity, KappaStore, NamespaceRef, PreparationBounds, ResourceKind, StoreError,
};

use crate::common::{TestResult, WALL_T0, create_ns, hlc, on_both_backends};

/// 1024 bytes per transaction, 1 s TTL.
const MAX_BYTES: u64 = 1024;
const TTL_MS: u64 = 1000;

fn asserter() -> Kappa {
    Kappa::sha256(b"limits")
}

fn blob(fill: u8, len: usize) -> (Kappa, Vec<u8>) {
    let content = vec![fill; len];
    (Kappa::sha256(&content), content)
}

fn begin(store: &dyn KappaStore, ns: &NamespaceRef, at: ClockMs) -> Result<String, StoreError> {
    let mut execution = store.begin_execution(ns, &clock_at(at)?)?;
    let head = resource::open(
        &mut *execution,
        &asserter(),
        ResourceKind::Membership,
        MAX_BYTES,
        at.add_physical_ms(TTL_MS),
        None,
    )?;
    execution.publish()?;
    Ok(head.id())
}

/// Put `content` under its verified identity; the head's total after.
fn put(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    id: &str,
    kappa: &Kappa,
    content: &[u8],
    at: ClockMs,
) -> Result<(u64, bool), StoreError> {
    let prepared = store.prepare_content(
        ContentIdentity::Verified(kappa.clone()),
        &mut &content[..],
        PreparationBounds {
            maximum: MAX_BYTES,
            deadline: Instant::now() + Duration::from_secs(30),
        },
    )?;
    let mut execution = store.begin_execution(ns, &clock_at(at)?)?;
    let (head, installed) = resource::stage(&mut *execution, &asserter(), id, prepared, 0, None)?;
    execution.publish()?;
    Ok((head.total_bytes, installed.newly_stored))
}

fn total(store: &dyn KappaStore, ns: &NamespaceRef, id: &str) -> Result<u64, StoreError> {
    Ok(resource::resolve(store, ns, id)?
        .ok_or_else(|| StoreError::NotFound(format!("transaction {id}")))?
        .head
        .total_bytes)
}

#[test]
fn per_transaction_limit_is_inclusive_and_refusals_reserve_nothing() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "limits")?;
        let now = hlc(WALL_T0)?;
        let id = begin(store, &ns, now)?;
        let (first, first_bytes) = blob(0x41, 1000);
        assert_eq!(
            put(store, &ns, &id, &first, &first_bytes, now)?,
            (1000, true)
        );
        let (over, over_bytes) = blob(0x42, 25);
        assert!(matches!(
            put(store, &ns, &id, &over, &over_bytes, now),
            Err(StoreError::CapacityExceeded(_))
        ));
        assert_eq!(
            total(store, &ns, &id)?,
            1000,
            "a refused put reserved bytes"
        );
        assert!(
            !store.blob_exists(&over)?,
            "a refused put installed content"
        );
        // Exactly at the limit is admitted.
        let (exact, exact_bytes) = blob(0x43, 24);
        assert_eq!(put(store, &ns, &id, &exact, &exact_bytes, now)?.0, 1024);
        // Restaging identical content converges and reserves nothing new.
        assert_eq!(
            put(store, &ns, &id, &first, &first_bytes, now)?,
            (1024, false)
        );
        Ok(())
    })
}

#[test]
fn digest_mismatch_is_rejected_before_reservation() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "mismatch")?;
        let now = hlc(WALL_T0)?;
        let id = begin(store, &ns, now)?;
        let claimed = Kappa::sha256(b"claimed");
        assert!(matches!(
            put(store, &ns, &id, &claimed, b"actual content", now),
            Err(StoreError::Rejected(_))
        ));
        assert_eq!(total(store, &ns, &id)?, 0);
        assert!(!store.blob_exists(&claimed)?);
        let (kappa, content) = blob(0x58, 1);
        assert!(matches!(
            put(store, &ns, "missing", &kappa, &content, now),
            Err(StoreError::NotFound(_))
        ));
        Ok(())
    })
}

#[test]
fn expiry_is_measured_in_physical_time() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "expiry")?;
        let opened = hlc(WALL_T0)?;
        let id = begin(store, &ns, opened)?;
        let (kappa, content) = blob(0x51, 512);
        put(store, &ns, &id, &kappa, &content, opened)?;
        let observed = resource::resolve(store, &ns, &id)?
            .ok_or("transaction vanished")?
            .head
            .revision;
        // One millisecond, and the full second, after begin: still live.
        for elapsed in [1, 999, 1000] {
            let mut execution = store.begin_execution(&ns, &clock_at(hlc(WALL_T0 + elapsed)?)?)?;
            assert!(
                !resource::expire(&mut *execution, &asserter(), &id, observed)?,
                "{elapsed} ms into a 1 s TTL"
            );
            execution.abort()?;
        }
        assert_eq!(total(store, &ns, &id)?, 512);
        let mut execution = store.begin_execution(&ns, &clock_at(hlc(WALL_T0 + 1001)?)?)?;
        assert!(resource::expire(
            &mut *execution,
            &asserter(),
            &id,
            observed
        )?);
        execution.publish()?;
        assert!(resource::resolve(store, &ns, &id)?.is_none());
        // Staging into the expired transaction is refused.
        assert!(matches!(
            put(store, &ns, &id, &kappa, &content, hlc(WALL_T0 + 1002)?),
            Err(StoreError::NotFound(_))
        ));
        Ok(())
    })
}

#[test]
fn aborted_transactions_release_their_membership() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "abort")?;
        let now = hlc(WALL_T0)?;
        let (kappa, content) = blob(0x61, 700);
        let id = begin(store, &ns, now)?;
        put(store, &ns, &id, &kappa, &content, now)?;
        let mut execution = store.begin_execution(&ns, &clock_at(now)?)?;
        assert!(resource::discard(&mut *execution, &asserter(), &id)?);
        execution.publish()?;
        assert!(resource::resolve(store, &ns, &id)?.is_none());
        // A second abort of the same transaction changes nothing.
        let mut execution = store.begin_execution(&ns, &clock_at(now)?)?;
        assert!(!resource::discard(&mut *execution, &asserter(), &id)?);
        execution.abort()?;
        // The released member is retained by nothing and retires.
        let mut execution = store.begin_execution(&ns, &clock_at(now)?)?;
        assert_eq!(
            execution.content_retire(&kappa)?,
            kappa_store::Retirement::Retired
        );
        execution.publish()?;
        assert!(!store.blob_exists(&kappa)?);
        Ok(())
    })
}
