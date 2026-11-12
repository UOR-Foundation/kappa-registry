//! Signature, typed-boundary, AEAD and epoch-signing floors (PERF-CAL-019,
//! PERF-CAL-020, PERF-CRY-010, PERF-CRY-012).
//!
//! Raw sign and verify per algorithm, then the same work through every
//! layer the substrate puts on top of it: the COSE envelope, typed
//! admission of assertions, revocations and dual-signed successions, and
//! epoch signing. The ratio of each layer to the raw primitive is the
//! boundary's cost. AEAD runs through the production framed encryptor.
//! Every verification result is checked: a verify that returns false is a
//! failure, not a fast sample.

use std::hint::black_box;

use criterion::Criterion;
use kappa_crypto::ecdsa::{K256EcdsaVerifier, K256Signer, P256EcdsaVerifier, P256Signer};
use kappa_crypto::ed25519::{Ed25519Signer, Ed25519Verifier};
use kappa_crypto::kms::FileKms;
use kappa_crypto::{Signer, Verifier, aead::BlobEncryptor, cose, signed_types};
use kappa_perf::bench::{BenchResult, Failure, bench, bytes, mag, osc, pattern, timed};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use kappa_types::clock::ClockMs;
use kappa_types::epoch_root::{EpochRoot, EpochRootInput};
use kappa_types::identity::{
    IdentityAssertion, Revocation, RevocationReason, Succession, SuccessionReason,
};
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::signed::{SignedPayload, content_types};

/// The message every signature floor signs, production and reference alike.
pub const MESSAGE: &[u8] = b"kappa-perf signature floor: a 64-byte canonical record payload..";

pub fn register(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    primitives(c, s)?;
    envelope(c, s)?;
    admissions(c, s)?;
    epoch_signing(c, s)?;
    aead(c, s)
}

/// The signing key every typed-boundary floor uses, and its anchor.
fn signing_identity(seed: u8) -> Result<(Ed25519Signer, Kappa), Box<dyn std::error::Error>> {
    let signer = Ed25519Signer::from_bytes(&[seed; 32])?;
    let anchor = Kappa::from_key(signer.algorithm(), signer.public_key())?;
    Ok((signer, anchor))
}

fn verified(failure: &Failure, result: Result<bool, kappa_crypto::CryptoError>) {
    if failure.ok(result) == Some(false) {
        failure.fail("signature did not verify");
    }
}

fn primitives(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let ed = Ed25519Signer::from_bytes(&[42; 32])?;
    let p256 = P256Signer::from_bytes(&[7; 32])?;
    let k256 = K256Signer::from_bytes(&[7; 32])?;
    let algorithms: [(&str, &dyn Signer, &dyn Verifier); 3] = [
        ("ed25519", &ed, &Ed25519Verifier),
        ("p256", &p256, &P256EcdsaVerifier),
        ("k256", &k256, &K256EcdsaVerifier),
    ];
    let failure = Failure::default();
    CalibratedGroup::scope(c, "signature", |group| -> BenchResult {
        for (name, signer, verifier) in algorithms {
            let signature = signer.sign(MESSAGE)?;
            let id = osc(&format!("osc:lat/crypto.sign.{name}"))?;
            group.bench(s, &bench(id, name, "sign", None, "PERF-CAL-020"), |iters| {
                timed(iters, || {
                    black_box(failure.ok(signer.sign(black_box(MESSAGE))));
                })
            })?;
            let id = osc(&format!("osc:lat/crypto.verify.{name}"))?;
            group.bench(
                s,
                &bench(id, name, "verify", None, "PERF-CAL-020"),
                |iters| {
                    timed(iters, || {
                        verified(
                            &failure,
                            verifier.verify(signer.public_key(), black_box(MESSAGE), &signature),
                        );
                    })
                },
            )?;
            failure.check(name)?;
        }
        Ok(())
    })
}

fn assertion(asserter: &Kappa) -> IdentityAssertion {
    IdentityAssertion {
        asserter: asserter.clone(),
        subject: "did:example:subject".into(),
        facet: "handle".into(),
        value: b"alice.example".to_vec(),
        basis: "dns".into(),
        valid_from_ms: 1_700_000_000_000,
        valid_until_ms: None,
        cose_signature: SignedPayload::empty(),
    }
}

fn envelope(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let (signer, anchor) = signing_identity(42)?;
    let envelope = cose::sign(&signer, &anchor, content_types::ASSERTION, MESSAGE)?;
    let failure = Failure::default();
    CalibratedGroup::scope(c, "typed_boundary_cose", |group| -> BenchResult {
        group.bench(
            s,
            &bench(
                osc("osc:lat/crypto.cose.sign")?,
                "cose",
                "sign",
                None,
                "PERF-CRY-012",
            ),
            |iters| {
                timed(iters, || {
                    black_box(failure.ok(cose::sign(
                        &signer,
                        &anchor,
                        content_types::ASSERTION,
                        black_box(MESSAGE),
                    )));
                })
            },
        )?;
        group.bench(
            s,
            &bench(
                osc("osc:lat/crypto.cose.verify")?,
                "cose",
                "verify",
                None,
                "PERF-CRY-012",
            ),
            |iters| {
                timed(iters, || {
                    black_box(failure.ok(cose::verify(
                        &envelope,
                        &anchor,
                        signer.public_key(),
                        content_types::ASSERTION,
                        black_box(MESSAGE),
                    )));
                })
            },
        )?;
        failure.check("crypto.cose")
    })
}

fn admissions(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let (signer, anchor) = signing_identity(42)?;
    let (successor, new_anchor) = signing_identity(43)?;
    let signed_assertion = signed_types::sign_assertion(assertion(&anchor), &signer)?;
    let revocation = signed_types::sign_revocation(
        Revocation {
            assertion_kappa: Kappa::sha256(&signed_assertion.signable_bytes()),
            asserter: anchor.clone(),
            reason: RevocationReason::Superseded,
            revoked_at_ms: 1_700_000_100_000,
            cose_signature: SignedPayload::empty(),
        },
        &signer,
    )?;
    let succession = signed_types::sign_succession(
        Succession {
            old_anchor: anchor,
            new_anchor,
            reason: SuccessionReason::Rotation,
            effective_at_ms: 1_700_000_200_000,
            chain_anchor: None,
            prev_identifier: None,
            old_cose_signature: SignedPayload::empty(),
            new_cose_signature: SignedPayload::empty(),
        },
        &signer,
        &successor,
    )?;
    let failure = Failure::default();
    CalibratedGroup::scope(c, "typed_boundary_admit", |group| -> BenchResult {
        group.bench(
            s,
            &bench(
                osc("osc:lat/crypto.admit.assertion")?,
                "admit",
                "assertion",
                None,
                "PERF-CRY-012",
            ),
            |iters| {
                timed(iters, || {
                    black_box(failure.ok(signed_types::admit_assertion(
                        signed_assertion.clone(),
                        signer.public_key(),
                    )));
                })
            },
        )?;
        group.bench(
            s,
            &bench(
                osc("osc:lat/crypto.admit.revocation")?,
                "admit",
                "revocation",
                None,
                "PERF-CRY-012",
            ),
            |iters| {
                timed(iters, || {
                    black_box(failure.ok(signed_types::admit_revocation(
                        revocation.clone(),
                        signer.public_key(),
                    )));
                })
            },
        )?;
        group.bench(
            s,
            &bench(
                osc("osc:lat/crypto.admit.succession")?,
                "admit",
                "succession",
                None,
                "PERF-CRY-012",
            ),
            |iters| {
                timed(iters, || {
                    black_box(failure.ok(signed_types::admit_succession(
                        succession.clone(),
                        signer.algorithm(),
                        signer.public_key(),
                        successor.algorithm(),
                        successor.public_key(),
                    )));
                })
            },
        )?;
        failure.check("crypto.admit")
    })
}

fn epoch_signing(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let (signer, anchor) = signing_identity(42)?;
    let ledger = Kappa::sha256(b"ledger");
    let ns = NamespaceRef::deterministic("floors");
    let root = EpochRoot::build(EpochRootInput {
        namespace: &ns,
        epoch_number: 2,
        prev_identifier: Some(&ledger),
        state_digest: [7; 32],
        mutations_root: [9; 32],
        timestamp: ClockMs::from_raw(1_700_000_000_000),
        signer_anchor: &anchor,
        tag_count: 1_000,
        rotation_kappa: None,
        ledger_root: &ledger,
        state: &Kappa::sha256(b"crypto-bench-namespace-state"),
    });
    let signed_root = signed_types::sign_epoch(root.clone(), &signer)?;
    let failure = Failure::default();
    CalibratedGroup::scope(c, "epoch_signing", |group| -> BenchResult {
        group.bench(
            s,
            &bench(
                osc("osc:lat/epoch.sign")?,
                "epoch",
                "sign",
                None,
                "PERF-EPO-021",
            ),
            |iters| {
                timed(iters, || {
                    black_box(failure.ok(signed_types::sign_epoch(root.clone(), &signer)));
                })
            },
        )?;
        group.bench(
            s,
            &bench(
                osc("osc:lat/epoch.verify")?,
                "epoch",
                "verify",
                None,
                "PERF-EPO-021",
            ),
            |iters| {
                timed(iters, || {
                    black_box(failure.ok(signed_types::verify_epoch(
                        &signed_root,
                        signer.public_key(),
                    )));
                })
            },
        )?;
        failure.check("epoch signing")
    })
}

fn aead(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let dir = tempfile::tempdir()?;
    let kms = FileKms::new([3; 32], dir.path().join("erased"))?;
    let encryptor = BlobEncryptor::new(&kms, "floors")?;
    let failure = Failure::default();
    for size in [4usize << 10, 64 << 10, 1 << 20, 16 << 20] {
        let data = pattern(size, 12);
        let sealed = encryptor.encrypt("sigma:floor", &data)?;
        let m = mag(size);
        CalibratedGroup::scope(c, &format!("aead_{m}"), |group| -> BenchResult {
            let id = osc(&format!(
                "osc:bw/crypto.aead.seal?size={m}&variant=aes256gcm_framed"
            ))?;
            group.bench(
                s,
                &bench(id, "seal", m.clone(), bytes(size), "PERF-CRY-010"),
                |iters| {
                    timed(iters, || {
                        black_box(failure.ok(encryptor.encrypt("sigma:floor", black_box(&data))));
                    })
                },
            )?;
            let id = osc(&format!(
                "osc:bw/crypto.aead.open?size={m}&variant=aes256gcm_framed"
            ))?;
            group.bench(
                s,
                &bench(id, "open", m.clone(), bytes(size), "PERF-CRY-010"),
                |iters| {
                    timed(iters, || {
                        black_box(failure.ok(encryptor.decrypt_all(
                            "sigma:floor",
                            &sealed.disk_bytes,
                            &sealed.base_nonce,
                            sealed.plaintext_size,
                        )));
                    })
                },
            )?;
            failure.check("crypto.aead")
        })?;
    }
    Ok(())
}
