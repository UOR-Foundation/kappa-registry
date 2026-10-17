//! PERF-IDN-008: handle claim, attestation and update flows.
//!
//! Every exercise runs on both backends with timestamps as `Clock::now`
//! issues them: HLC-encoded, physical milliseconds in the upper 48 bits.
//! Producers store `claimed_at_ms` and `attested_at_ms` in that encoding,
//! so a grace window measured in milliseconds must be applied to the
//! physical component; adding milliseconds to the packed integer would
//! shrink a seven-day window to under ten seconds.
//!
//! Covered: lifecycle and anchor index; the reclaim boundary at exactly
//! `claimed_at + grace`; attested and unrepresentable-deadline records
//! that are never reclaimable; nonnegative grace; attestation that only
//! succeeds against the current record (absent, stale, already attested
//! and taken-over records all refuse); claims decided against the
//! execution's own private writes; `handle_update` replacing only the
//! owner's handles in one protocol; protocol isolation; credential
//! rotation grace on the same physical-time basis.

use kappa_handler::clock_at;
use kappa_store::identity::HandleRecord;
use kappa_store::namespace::ProtocolId;
use kappa_store::page::PageRequest;
use kappa_store::{
    ClockMs, Execution, Kappa, KappaStore, NamespaceRef, StoreError, default_handle_grace_ms,
    handle_claim, handle_update,
};

use crate::common::{TestResult, WALL_T0, create_ns, hlc, on_both_backends};

/// Seven days in milliseconds, as production configures it.
fn grace() -> Result<u64, std::num::TryFromIntError> {
    u64::try_from(default_handle_grace_ms())
}

fn anchor(seed: &str) -> Kappa {
    Kappa::sha256(seed.as_bytes())
}

fn atproto() -> Result<ProtocolId, kappa_store::namespace::InvalidProtocolId> {
    ProtocolId::new("atproto")
}

fn record(owner: &Kappa, handle: &str, protocol: &ProtocolId, claimed: ClockMs) -> HandleRecord {
    HandleRecord {
        anchor: owner.clone(),
        handle: handle.into(),
        protocol: protocol.clone(),
        claimed_at_ms: claimed.as_i64(),
        attested_at_ms: None,
    }
}

/// Publish one execution at `now`; on a write failure abort it and return
/// the failure, so a refused write publishes nothing.
fn publish(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    now: ClockMs,
    write: impl FnOnce(&mut dyn Execution) -> Result<(), StoreError>,
) -> Result<(), StoreError> {
    let mut execution = store.begin_execution(ns, &clock_at(now)?)?;
    match write(&mut *execution) {
        Ok(()) => execution.publish().map(drop),
        Err(error) => {
            execution.abort()?;
            Err(error)
        }
    }
}

fn claim(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    now: ClockMs,
    claimed: &HandleRecord,
    grace_ms: i64,
) -> Result<(), StoreError> {
    publish(store, ns, now, |execution| {
        handle_claim(execution, claimed, grace_ms)
    })
}

/// Attest in its own execution; a refused attestation publishes nothing.
fn attest(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    now: ClockMs,
    expected: &HandleRecord,
) -> Result<bool, StoreError> {
    let mut execution = store.begin_execution(ns, &clock_at(now)?)?;
    if execution.handle_attest(expected)? {
        execution.publish()?;
        Ok(true)
    } else {
        execution.abort()?;
        Ok(false)
    }
}

fn handles_of(store: &dyn KappaStore, owner: &Kappa) -> Result<Vec<String>, StoreError> {
    let page = store.handle_list_by_anchor(owner, &PageRequest::first(64))?;
    Ok(page.items.into_iter().map(|record| record.handle).collect())
}

fn expect_conflict(result: Result<(), StoreError>, context: &str) -> TestResult {
    match result {
        Err(StoreError::Conflict(_)) => Ok(()),
        other => Err(format!("{context}: expected conflict, got {other:?}").into()),
    }
}

#[test]
fn lifecycle_maintains_the_anchor_index() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "handles")?;
        let protocol = atproto()?;
        let alice = anchor("alice");
        let claimed = record(&alice, "alice.test", &protocol, hlc(WALL_T0)?);
        publish(store, &ns, hlc(WALL_T0)?, |execution| {
            execution.handle_put(&claimed)
        })?;

        let got = store.handle_get(protocol.clone(), "alice.test")?;
        assert_eq!(got.anchor, alice);
        assert_eq!(got.claimed_at_ms, hlc(WALL_T0)?.as_i64());
        assert_eq!(handles_of(store, &alice)?, ["alice.test"]);

        publish(store, &ns, hlc(WALL_T0 + 1)?, |execution| {
            execution.handle_delete(&protocol, "alice.test")
        })?;
        assert!(matches!(
            store.handle_get(protocol.clone(), "alice.test"),
            Err(StoreError::NotFound(_))
        ));
        assert!(handles_of(store, &alice)?.is_empty());
        // Deleting an absent handle is a no-op, not a failure.
        publish(store, &ns, hlc(WALL_T0 + 2)?, |execution| {
            execution.handle_delete(&protocol, "alice.test")
        })?;
        Ok(())
    })
}

#[test]
fn reclaim_opens_exactly_at_claim_plus_grace() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "grace")?;
        let protocol = atproto()?;
        let grace_ms = default_handle_grace_ms();
        let (first, second) = (anchor("first"), anchor("second"));
        claim(
            store,
            &ns,
            hlc(WALL_T0)?,
            &record(&first, "contested", &protocol, hlc(WALL_T0)?),
            grace_ms,
        )?;

        // One minute, one day, and one millisecond before the deadline: the
        // unattested claim still holds.
        for elapsed in [60_000, 86_400_000, grace()? - 1] {
            let now = hlc(WALL_T0 + elapsed)?;
            expect_conflict(
                claim(
                    store,
                    &ns,
                    now,
                    &record(&second, "contested", &protocol, now),
                    grace_ms,
                ),
                &format!("{elapsed} ms after the claim"),
            )?;
            assert_eq!(
                store.handle_get(protocol.clone(), "contested")?.anchor,
                first
            );
        }

        let deadline = hlc(WALL_T0 + grace()?)?;
        claim(
            store,
            &ns,
            deadline,
            &record(&second, "contested", &protocol, deadline),
            grace_ms,
        )?;
        assert_eq!(store.handle_get(protocol, "contested")?.anchor, second);
        assert!(
            handles_of(store, &first)?.is_empty(),
            "reclaimed handle left in the old owner's index"
        );
        assert_eq!(handles_of(store, &second)?, ["contested"]);
        Ok(())
    })
}

#[test]
fn attested_and_unbounded_claims_are_never_reclaimed() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "held")?;
        let protocol = atproto()?;
        let grace_ms = default_handle_grace_ms();
        let (owner, rival) = (anchor("owner"), anchor("rival"));

        let held = record(&owner, "held", &protocol, hlc(WALL_T0)?);
        claim(store, &ns, hlc(WALL_T0)?, &held, grace_ms)?;
        assert!(attest(store, &ns, hlc(WALL_T0 + 5)?, &held)?);
        assert_eq!(
            store.handle_get(protocol.clone(), "held")?.attested_at_ms,
            Some(hlc(WALL_T0 + 5)?.as_i64())
        );
        let far = hlc(WALL_T0 + 10 * grace()?)?;
        expect_conflict(
            claim(
                store,
                &ns,
                far,
                &record(&rival, "held", &protocol, far),
                grace_ms,
            ),
            "attested",
        )?;

        // A claim time whose deadline is not representable never expires.
        let unbounded = HandleRecord {
            claimed_at_ms: i64::MAX,
            ..record(&owner, "unbounded", &protocol, far)
        };
        publish(store, &ns, far, |execution| {
            execution.handle_put(&unbounded)
        })?;
        let later = hlc(WALL_T0 + 11 * grace()?)?;
        expect_conflict(
            claim(
                store,
                &ns,
                later,
                &record(&rival, "unbounded", &protocol, later),
                10,
            ),
            "unbounded",
        )?;

        assert!(matches!(
            claim(
                store,
                &ns,
                later,
                &record(&rival, "fresh", &protocol, later),
                -1
            ),
            Err(StoreError::Rejected(_))
        ));

        // The owner may always re-claim; the record is replaced as given.
        let renewed = record(&owner, "held", &protocol, later);
        claim(store, &ns, later, &renewed, grace_ms)?;
        let stored = store.handle_get(protocol, "held")?;
        assert_eq!(stored.claimed_at_ms, later.as_i64());
        assert_eq!(stored.attested_at_ms, None);
        Ok(())
    })
}

#[test]
fn attestation_requires_the_current_record() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "attest")?;
        let protocol = atproto()?;
        let (owner, rival) = (anchor("owner"), anchor("rival"));
        let current = record(&owner, "probe", &protocol, hlc(WALL_T0)?);

        assert!(
            !attest(store, &ns, hlc(WALL_T0)?, &current)?,
            "absent record attested"
        );
        claim(
            store,
            &ns,
            hlc(WALL_T0 + 1)?,
            &current,
            default_handle_grace_ms(),
        )?;

        let stale = HandleRecord {
            claimed_at_ms: current.claimed_at_ms - 1,
            ..current.clone()
        };
        assert!(
            !attest(store, &ns, hlc(WALL_T0 + 2)?, &stale)?,
            "stale record attested"
        );
        assert_eq!(
            store.handle_get(protocol.clone(), "probe")?.attested_at_ms,
            None
        );

        assert!(attest(store, &ns, hlc(WALL_T0 + 3)?, &current)?);
        // The stored record now differs from the probe that attested it.
        assert!(
            !attest(store, &ns, hlc(WALL_T0 + 4)?, &current)?,
            "attested twice from one probe"
        );

        // A record taken over by another owner refuses the old owner's probe.
        let lapsed = record(&owner, "lapsed", &protocol, hlc(WALL_T0)?);
        claim(
            store,
            &ns,
            hlc(WALL_T0 + 5)?,
            &lapsed,
            default_handle_grace_ms(),
        )?;
        let takeover = hlc(WALL_T0 + grace()?)?;
        claim(
            store,
            &ns,
            takeover,
            &record(&rival, "lapsed", &protocol, takeover),
            default_handle_grace_ms(),
        )?;
        assert!(!attest(store, &ns, hlc(WALL_T0 + grace()? + 1)?, &lapsed)?);
        assert_eq!(store.handle_get(protocol, "lapsed")?.attested_at_ms, None);
        Ok(())
    })
}

#[test]
fn claims_are_decided_against_the_execution_view() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "view")?;
        let protocol = atproto()?;
        let now = hlc(WALL_T0)?;
        let mut execution = store.begin_execution(&ns, &clock_at(now)?)?;
        execution.handle_put(&record(&anchor("first"), "private", &protocol, now))?;
        assert!(
            store.handle_get(protocol.clone(), "private").is_err(),
            "unpublished claim visible"
        );
        let rival = record(&anchor("second"), "private", &protocol, now);
        assert!(matches!(
            handle_claim(&mut *execution, &rival, default_handle_grace_ms()),
            Err(StoreError::Conflict(_))
        ));
        execution.abort()?;
        assert!(
            store.handle_get(protocol, "private").is_err(),
            "aborted claim visible"
        );
        Ok(())
    })
}

#[test]
fn update_replaces_only_the_owners_handles_in_one_protocol() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "update")?;
        let (at, dns) = (atproto()?, ProtocolId::new("dns")?);
        let (owner, other) = (anchor("owner"), anchor("other"));
        let now = hlc(WALL_T0)?;
        publish(store, &ns, now, |execution| {
            for (handle, protocol) in [("one", &at), ("two", &at), ("site", &dns)] {
                execution.handle_put(&record(&owner, handle, protocol, now))?;
            }
            execution.handle_put(&record(&other, "taken", &at, now))
        })?;

        let later = hlc(WALL_T0 + 10)?;
        let replacement = record(&owner, "three", &at, later);
        publish(store, &ns, later, |execution| {
            handle_update(
                execution,
                &owner,
                &replacement,
                &at,
                default_handle_grace_ms(),
            )
        })?;
        let mut held = handles_of(store, &owner)?;
        held.sort();
        assert_eq!(held, ["site", "three"]);
        assert_eq!(store.handle_get(dns, "site")?.anchor, owner);

        // Wrong owner: refused before anything is read or written.
        assert!(matches!(
            publish(store, &ns, hlc(WALL_T0 + 20)?, |execution| {
                handle_update(
                    execution,
                    &other,
                    &replacement,
                    &at,
                    default_handle_grace_ms(),
                )
            }),
            Err(StoreError::Rejected(_))
        ));
        // A contested target conflicts and leaves the current handles intact.
        let contested = record(&owner, "taken", &at, hlc(WALL_T0 + 30)?);
        expect_conflict(
            publish(store, &ns, hlc(WALL_T0 + 30)?, |execution| {
                handle_update(
                    execution,
                    &owner,
                    &contested,
                    &at,
                    default_handle_grace_ms(),
                )
            }),
            "update onto a held handle",
        )?;
        let mut held = handles_of(store, &owner)?;
        held.sort();
        assert_eq!(held, ["site", "three"]);
        Ok(())
    })
}

#[test]
fn protocols_are_isolated() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "protocols")?;
        let (at, dns) = (atproto()?, ProtocolId::new("dns")?);
        let now = hlc(WALL_T0)?;
        let (first, second) = (anchor("cross-at"), anchor("cross-dns"));
        publish(store, &ns, now, |execution| {
            execution.handle_put(&record(&first, "shared.test", &at, now))?;
            execution.handle_put(&record(&second, "shared.test", &dns, now))
        })?;
        assert_eq!(store.handle_get(at, "shared.test")?.anchor, first);
        assert_eq!(store.handle_get(dns, "shared.test")?.anchor, second);
        Ok(())
    })
}

#[test]
fn credential_rotation_grace_uses_physical_time() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "credentials")?;
        let (owner, intruder) = (anchor("owner"), anchor("intruder"));
        let rotated_at = hlc(WALL_T0)?;
        publish(store, &ns, hlc(WALL_T0 - 1)?, |execution| {
            execution.credential_put("key", &owner, b"old")
        })?;
        publish(store, &ns, rotated_at, |execution| {
            execution.credential_rotate("key", &owner, b"new", 60_000)
        })?;

        let expires = hlc(WALL_T0 + 60_000)?.as_i64();
        for elapsed in [0, 1, 1_000, 59_999] {
            let (holder, secret, grace) = store.credential_get("key", hlc(WALL_T0 + elapsed)?)?;
            assert_eq!(holder, owner);
            assert_eq!(secret, b"new");
            assert_eq!(
                grace,
                Some((b"old".to_vec(), expires)),
                "{elapsed} ms into a 60 s grace"
            );
        }
        let (_, _, grace) = store.credential_get("key", hlc(WALL_T0 + 60_000)?)?;
        assert_eq!(grace, None, "grace survived its deadline");

        // A refused rotation latches its execution; nothing publishes.
        let later = hlc(WALL_T0 + 1)?;
        assert!(matches!(
            publish(store, &ns, later, |execution| {
                execution.credential_rotate("key", &intruder, b"stolen", 60_000)
            }),
            Err(StoreError::Rejected(_))
        ));
        assert!(
            publish(store, &ns, later, |execution| {
                execution.credential_rotate("key", &owner, b"overflow", u64::MAX)
            })
            .is_err()
        );
        let (_, secret, _) = store.credential_get("key", rotated_at)?;
        assert_eq!(secret, b"new", "refused rotation changed the secret");
        Ok(())
    })
}
