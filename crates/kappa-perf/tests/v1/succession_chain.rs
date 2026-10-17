//! PERF-IDN-003: succession requires both signatures; a chain holds at
//! most `SUCCESSION_CHAIN_MAX` (64) links; cycles and self-succession are
//! rejected.
//!
//! The record-level cases go through the crypto boundary. The store-level
//! cases publish through executions on both backends and assert the
//! invariant the store promises: no published record makes a chain
//! unresolvable. A chain therefore stays within 64 links whether it grows
//! at its head, at its origin, or by joining two chains, and every chain
//! the store admits resolves from every anchor on it.

use kappa_crypto::Signer;
use kappa_crypto::ed25519::Ed25519Signer;
use kappa_crypto::signed_types::{admit_succession, sign_succession, sign_watermark};
use kappa_crypto::testing::Impostor;
use kappa_handler::clock_at;
use kappa_store::identity::{
    SUCCESSION_CHAIN_MAX, Succession, SuccessionReason, Watermark, WatermarkReason,
};
use kappa_store::signed::SignedPayload;
use kappa_store::{
    ClockMs, Kappa, KappaStore, NamespaceRef, StoreError, VerifiedSuccession,
    default_watermark_for_succession, succession_chain, succession_put,
    succession_put_with_default_watermark, succession_resolve, verify_succession_chain,
};

use crate::common::{TestResult, create_ns, on_both_backends};

fn signer(index: usize) -> Result<Ed25519Signer, Box<dyn std::error::Error>> {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&u64::try_from(index)?.to_le_bytes());
    seed[31] = 0x5c;
    Ok(Ed25519Signer::from_bytes(&seed)?)
}

fn anchor(index: usize) -> Result<Kappa, Box<dyn std::error::Error>> {
    let signer = signer(index)?;
    Ok(Kappa::from_key(signer.algorithm(), signer.public_key())?)
}

fn record(
    old: usize,
    new: usize,
    effective_at_ms: i64,
) -> Result<Succession, Box<dyn std::error::Error>> {
    let unsigned = Succession {
        old_anchor: anchor(old)?,
        new_anchor: anchor(new)?,
        reason: SuccessionReason::Rotation,
        effective_at_ms,
        chain_anchor: None,
        prev_identifier: None,
        old_cose_signature: SignedPayload::empty(),
        new_cose_signature: SignedPayload::empty(),
    };
    Ok(sign_succession(unsigned, &signer(old)?, &signer(new)?)?)
}

fn verified(old: usize, new: usize) -> Result<VerifiedSuccession, Box<dyn std::error::Error>> {
    let (old_signer, new_signer) = (signer(old)?, signer(new)?);
    Ok(VerifiedSuccession::verify(
        record(old, new, 1000)?,
        old_signer.algorithm(),
        old_signer.public_key(),
        new_signer.algorithm(),
        new_signer.public_key(),
    )?)
}

/// Publish an admitted `succession` in its own execution; a refused record
/// aborts it. The result is the store's own, typed.
fn link(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    now: &mut i64,
    succession: &VerifiedSuccession,
) -> Result<(), StoreError> {
    *now += 1;
    let mut execution = store.begin_execution(ns, &clock_at(ClockMs::from_raw(*now))?)?;
    match succession_put(&mut *execution, succession) {
        Ok(_) => execution.publish().map(drop),
        Err(error) => {
            execution.abort()?;
            Err(error)
        }
    }
}

/// Publish the links `first -> first+1 -> ... -> last`, origin first.
fn chain(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    now: &mut i64,
    first: usize,
    last: usize,
) -> TestResult {
    for index in first..last {
        link(store, ns, now, &verified(index, index + 1)?)?;
    }
    Ok(())
}

fn key_material(anchor_of: &Kappa) -> Option<(String, Vec<u8>)> {
    (0..256).find_map(|index| {
        let signer = signer(index).ok()?;
        (Kappa::from_key(signer.algorithm(), signer.public_key()).ok()? == *anchor_of)
            .then(|| (signer.algorithm().to_owned(), signer.public_key().to_vec()))
    })
}

fn expect_capacity(result: Result<(), StoreError>, context: &str) -> TestResult {
    match result {
        Err(StoreError::CapacityExceeded(_)) => Ok(()),
        other => Err(format!("{context}: expected capacity rejection, got {other:?}").into()),
    }
}

// -- Record level --

#[test]
fn dual_signature_required() -> TestResult {
    let (old, new, wrong) = (signer(1)?, signer(2)?, signer(99)?);
    let signed = record(1, 2, 1000)?;
    let admitted = admit_succession(
        signed.clone(),
        old.algorithm(),
        old.public_key(),
        new.algorithm(),
        new.public_key(),
    )?;
    assert_eq!(admitted.get().old_anchor, anchor(1)?);
    assert_eq!(admitted.get().new_anchor, anchor(2)?);
    assert!(
        admit_succession(
            signed.clone(),
            wrong.algorithm(),
            wrong.public_key(),
            new.algorithm(),
            new.public_key()
        )
        .is_err()
    );
    assert!(
        admit_succession(
            signed.clone(),
            old.algorithm(),
            old.public_key(),
            wrong.algorithm(),
            wrong.public_key()
        )
        .is_err()
    );
    // Swapped keys: each signature binds its own anchor.
    assert!(
        admit_succession(
            signed,
            new.algorithm(),
            new.public_key(),
            old.algorithm(),
            old.public_key()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn every_signed_field_is_bound() -> TestResult {
    let (old, new) = (signer(3)?, signer(4)?);
    let signed = record(3, 4, 1000)?;
    let tampered: [fn(&mut Succession); 4] = [
        |s| s.effective_at_ms = 9999,
        |s| s.reason = SuccessionReason::KeyCompromise,
        |s| s.chain_anchor = Some(Kappa::sha256(b"chain")),
        |s| s.prev_identifier = Some(Kappa::sha256(b"prev")),
    ];
    for (index, tamper) in tampered.iter().enumerate() {
        let mut copy = signed.clone();
        tamper(&mut copy);
        assert!(
            admit_succession(
                copy,
                old.algorithm(),
                old.public_key(),
                new.algorithm(),
                new.public_key()
            )
            .is_err(),
            "tamper {index} admitted"
        );
    }
    let mut unsigned = signed.clone();
    unsigned.old_cose_signature = SignedPayload::empty();
    unsigned.new_cose_signature = SignedPayload::empty();
    assert_eq!(
        unsigned.signable_bytes(),
        signed.signable_bytes(),
        "signatures are outside the signed bytes"
    );
    Ok(())
}

#[test]
fn chain_max_is_64() {
    assert_eq!(SUCCESSION_CHAIN_MAX, 64);
}

// -- Store level, both backends --

#[test]
fn a_chain_of_exactly_64_links_resolves_from_every_anchor() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "chain64")?;
        let mut now = 1000;
        chain(store, &ns, &mut now, 0, SUCCESSION_CHAIN_MAX)?;
        let head = anchor(SUCCESSION_CHAIN_MAX)?;
        for start in [0, 1, 32, SUCCESSION_CHAIN_MAX - 1, SUCCESSION_CHAIN_MAX] {
            assert_eq!(
                succession_resolve(store, &anchor(start)?)?,
                head,
                "from anchor {start}"
            );
            assert_eq!(
                succession_chain(store, &anchor(start)?)?.len(),
                SUCCESSION_CHAIN_MAX - start + 1
            );
        }
        let verified = verify_succession_chain(store, &anchor(0)?, &key_material)?;
        assert_eq!(verified.links().len(), SUCCESSION_CHAIN_MAX);
        Ok(())
    })
}

#[test]
fn growing_a_full_chain_at_its_head_is_refused() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "head")?;
        let mut now = 1000;
        chain(store, &ns, &mut now, 0, SUCCESSION_CHAIN_MAX)?;
        expect_capacity(
            link(
                store,
                &ns,
                &mut now,
                &verified(SUCCESSION_CHAIN_MAX, SUCCESSION_CHAIN_MAX + 1)?,
            ),
            "65th link at the head",
        )?;
        // The refused link published nothing; the chain still resolves.
        assert_eq!(
            succession_resolve(store, &anchor(0)?)?,
            anchor(SUCCESSION_CHAIN_MAX)?
        );
        assert!(matches!(
            store.succession_get(&anchor(SUCCESSION_CHAIN_MAX)?),
            Err(StoreError::NotFound(_))
        ));
        Ok(())
    })
}

#[test]
fn growing_a_full_chain_at_its_origin_is_refused() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "origin")?;
        let mut now = 1000;
        chain(store, &ns, &mut now, 1, SUCCESSION_CHAIN_MAX + 1)?;
        expect_capacity(
            link(store, &ns, &mut now, &verified(0, 1)?),
            "65th link at the origin",
        )?;
        assert!(matches!(
            store.succession_get(&anchor(0)?),
            Err(StoreError::NotFound(_))
        ));
        assert_eq!(
            succession_resolve(store, &anchor(1)?)?,
            anchor(SUCCESSION_CHAIN_MAX + 1)?
        );
        Ok(())
    })
}

#[test]
fn joining_two_chains_past_the_bound_is_refused() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "join")?;
        let mut now = 1000;
        // 32 links ending at anchor 32, and 32 links starting at 100.
        chain(store, &ns, &mut now, 0, 32)?;
        chain(store, &ns, &mut now, 100, 132)?;
        // Joining them adds a 65th link in the middle.
        expect_capacity(
            link(store, &ns, &mut now, &verified(32, 100)?),
            "join into 65 links",
        )?;
        // One link shorter on the left joins into exactly 64.
        chain(store, &ns, &mut now, 200, 231)?;
        link(store, &ns, &mut now, &verified(231, 100)?)?;
        assert_eq!(succession_resolve(store, &anchor(200)?)?, anchor(132)?);
        assert_eq!(
            succession_chain(store, &anchor(200)?)?.len(),
            SUCCESSION_CHAIN_MAX + 1
        );
        Ok(())
    })
}

#[test]
fn cycles_and_self_succession_are_refused() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "cycles")?;
        let mut now = 1000;
        chain(store, &ns, &mut now, 0, 3)?;
        for (old, new) in [(3, 0), (3, 1), (2, 0)] {
            match link(store, &ns, &mut now, &verified(old, new)?) {
                Err(StoreError::Rejected(message) | StoreError::Conflict(message)) => {
                    assert!(
                        message.contains("cycle") || message.contains("another succession"),
                        "{old}->{new}: {message}"
                    );
                }
                other => return Err(format!("{old}->{new} formed a cycle: {other:?}").into()),
            }
        }
        assert!(matches!(
            link(store, &ns, &mut now, &verified(5, 5)?),
            Err(StoreError::Rejected(_))
        ));
        assert_eq!(succession_resolve(store, &anchor(0)?)?, anchor(3)?);
        Ok(())
    })
}

#[test]
fn succession_watermark_verifies_against_the_old_anchors_key() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "watermark")?;
        let succession = verified(10, 11)?;
        let now = ClockMs::from_raw(2000);
        let genuine = default_watermark_for_succession(succession.inner(), now, &signer(10)?)?;
        // Same policy, asserter and protected headers, signed by a key that
        // is not the old anchor's: refused, and the refusal publishes nothing.
        let forged = sign_watermark(
            genuine.clone(),
            &Impostor {
                claimed: signer(10)?,
                actual: signer(12)?,
            },
        )?;
        assert_ne!(forged.cose_signature, genuine.cose_signature);
        let mut execution = store.begin_execution(&ns, &clock_at(now)?)?;
        match succession_put_with_default_watermark(&mut *execution, &succession, &forged) {
            Err(StoreError::Rejected(message)) => {
                assert!(message.contains("watermark verification"), "{message}");
                execution.abort()?;
            }
            other => return Err(format!("forged watermark admitted: {other:?}").into()),
        }
        assert!(matches!(
            store.succession_get(&anchor(10)?),
            Err(StoreError::NotFound(_))
        ));

        let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(2001))?)?;
        succession_put_with_default_watermark(&mut *execution, &succession, &genuine)?;
        execution.publish()?;
        assert_eq!(succession_resolve(store, &anchor(10)?)?, anchor(11)?);
        Ok(())
    })
}

/// Offer `watermark` with `succession` in a fresh execution and require a
/// rejection whose message contains `expected`; the refusal publishes
/// neither the succession nor the watermark.
fn expect_watermark_rejected(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    now: &mut i64,
    succession: &VerifiedSuccession,
    watermark: &Watermark,
    expected: &str,
    case: &str,
) -> TestResult {
    *now += 1;
    let mut execution = store.begin_execution(ns, &clock_at(ClockMs::from_raw(*now))?)?;
    match succession_put_with_default_watermark(&mut *execution, succession, watermark) {
        Err(StoreError::Rejected(message)) => {
            execution.abort()?;
            assert!(
                message.contains(expected),
                "{case}: expected '{expected}', got '{message}'"
            );
        }
        other => {
            execution.abort()?;
            return Err(format!("{case}: watermark admitted: {other:?}").into());
        }
    }
    let old_anchor = &succession.inner().old_anchor;
    match store.succession_get(old_anchor) {
        Err(StoreError::NotFound(_)) => {}
        other => return Err(format!("{case}: refusal published a successor: {other:?}").into()),
    }
    let watermarks = store.watermark_list_by_asserter(old_anchor)?;
    assert!(
        watermarks.is_empty(),
        "{case}: refusal published watermarks {watermarks:?}"
    );
    Ok(())
}

#[test]
fn succession_watermark_rejects_every_malformed_or_misattributed_watermark() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "watermark-negative")?;
        let mut now = 3000;
        let succession = verified(20, 21)?;
        let genuine = default_watermark_for_succession(
            succession.inner(),
            ClockMs::from_raw(now),
            &signer(20)?,
        )?;
        assert_eq!(
            genuine.invalidate_before_ms, 1000,
            "rotation cutoff is effective_at"
        );
        assert_eq!(genuine.reason, WatermarkReason::Rotation);

        let mut unsigned = genuine.clone();
        unsigned.cose_signature = SignedPayload::empty();

        let mut tampered = genuine.clone();
        tampered.set_at_ms += 1;

        // The successor cannot void its predecessor's assertions: a
        // watermark claiming the old anchor but signed by the new key.
        let by_successor = sign_watermark(
            genuine.clone(),
            &Impostor {
                claimed: signer(20)?,
                actual: signer(21)?,
            },
        )?;

        // A correctly signed watermark issued by some other anchor.
        let mut other_asserter = genuine.clone();
        other_asserter.asserter = anchor(22)?;
        let other_asserter = sign_watermark(other_asserter, &signer(22)?)?;

        let mut early_cutoff = genuine.clone();
        early_cutoff.invalidate_before_ms -= 1;
        let early_cutoff = sign_watermark(early_cutoff, &signer(20)?)?;

        let mut wrong_reason = genuine.clone();
        wrong_reason.reason = WatermarkReason::Administrative;
        let wrong_reason = sign_watermark(wrong_reason, &signer(20)?)?;

        // A rotation never voids assertions made after it took effect.
        let mut compromise_scope = genuine.clone();
        compromise_scope.invalidate_before_ms = i64::MAX;
        compromise_scope.reason = WatermarkReason::KeyCompromise;
        let compromise_scope = sign_watermark(compromise_scope, &signer(20)?)?;

        let cases: [(&Watermark, &str, &str); 7] = [
            (&unsigned, "watermark verification", "unsigned"),
            (
                &tampered,
                "watermark verification",
                "tampered after signing",
            ),
            (
                &by_successor,
                "watermark verification",
                "signed by the successor",
            ),
            (
                &other_asserter,
                "does not match succession policy",
                "other asserter",
            ),
            (
                &early_cutoff,
                "does not match succession policy",
                "early cutoff",
            ),
            (
                &wrong_reason,
                "does not match succession policy",
                "wrong reason",
            ),
            (
                &compromise_scope,
                "does not match succession policy",
                "compromise scope",
            ),
        ];
        for (watermark, expected, case) in cases {
            expect_watermark_rejected(
                store,
                &ns,
                &mut now,
                &succession,
                watermark,
                expected,
                case,
            )?;
        }

        now += 1;
        let mut execution = store.begin_execution(&ns, &clock_at(ClockMs::from_raw(now))?)?;
        succession_put_with_default_watermark(&mut *execution, &succession, &genuine)?;
        execution.publish()?;
        assert_eq!(succession_resolve(store, &anchor(20)?)?, anchor(21)?);
        assert_eq!(
            store.watermark_list_by_asserter(&anchor(20)?)?,
            vec![genuine]
        );
        Ok(())
    })
}

#[test]
fn an_anchor_has_one_successor_and_republication_is_idempotent() -> TestResult {
    on_both_backends(|store| {
        let ns = create_ns(store, "unique")?;
        let mut now = 1000;
        let first = verified(0, 1)?;
        link(store, &ns, &mut now, &first)?;
        link(store, &ns, &mut now, &first)?;
        assert!(matches!(
            link(store, &ns, &mut now, &verified(0, 2)?),
            Err(StoreError::Conflict(_))
        ));
        assert_eq!(store.succession_get(&anchor(0)?)?, anchor(1)?);
        Ok(())
    })
}
