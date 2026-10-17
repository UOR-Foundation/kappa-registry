//! Reference implementations of the digest and signature floors
//! (PERF-HSH-012, PERF-HSH-013, PERF-CAL-020).
//!
//! The operations the production floors measure, through the best existing
//! implementations on this host, by the same harness, on the same bytes and
//! at the same conditions plus `impl`: aws-lc's assembly SHA-256, SHA-512
//! and SHA3-256 and its Ed25519, P-256 and secp256k1 ECDSA; BLAKE3 called
//! directly; ISA-L's AVX2 multi-buffer SHA-256 lanes (through rekindle-hash)
//! over the same objects the production multi-object floor hashes. The
//! calibration pairs every production record with the best of these
//! (`reference::compare`). SHA-1 has no reference: the production axis
//! detects collisions (`sha1-checked`), which no faster implementation here
//! does, so a comparison would be of different work. aws-lc has no
//! Keccak-256.

use std::hint::black_box;

use aws_lc_rs::digest;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{
    self, EcdsaKeyPair, EcdsaSigningAlgorithm, EcdsaVerificationAlgorithm, Ed25519KeyPair, KeyPair,
    UnparsedPublicKey,
};
use criterion::Criterion;
use kappa_perf::bench::{BenchResult, Failure, Tier, bench, bytes, mag, osc, pattern, timed};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use kappa_store_redb::BLOB_CHUNK_SIZE;

use super::crypto::MESSAGE;
use super::hash::sizes;

/// Digest axes aws-lc implements, by kappa axis token.
const DIGESTS: [(&str, &digest::Algorithm); 3] = [
    ("sha256", &digest::SHA256),
    ("sha512", &digest::SHA512),
    ("sha3_256", &digest::SHA3_256),
];

/// ECDSA curves aws-lc implements, by kappa algorithm token: signing with
/// SHA-256 of the message, as the production signers do.
const ECDSA: [(&str, &EcdsaSigningAlgorithm, &EcdsaVerificationAlgorithm); 2] = [
    (
        "p256",
        &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &signature::ECDSA_P256_SHA256_FIXED,
    ),
    (
        "k256",
        &signature::ECDSA_P256K1_SHA256_FIXED_SIGNING,
        &signature::ECDSA_P256K1_SHA256_FIXED,
    ),
];

pub fn register(c: &mut Criterion, s: &mut CalibratedSession, tier: Tier) -> BenchResult {
    digests(c, s, tier)?;
    signatures(c, s)
}

fn digests(c: &mut Criterion, s: &mut CalibratedSession, tier: Tier) -> BenchResult {
    for &size in sizes(tier) {
        // The production digest floors hash `pattern(size, 11)`.
        let data = pattern(size, 11);
        let m = mag(size);
        CalibratedGroup::scope(c, &format!("hash_reference_{m}"), |group| -> BenchResult {
            for (token, algorithm) in DIGESTS {
                let id = osc(&format!("osc:bw/hash.{token}?impl=aws_lc&size={m}"))?;
                group.bench(
                    s,
                    &bench(id, token, m.clone(), bytes(size), "PERF-HSH-012"),
                    |iters| {
                        timed(iters, || {
                            black_box(digest::digest(algorithm, black_box(&data)));
                        })
                    },
                )?;
                // The ingest path's work: the same digest fed in the store's
                // chunks.
                let id = osc(&format!(
                    "osc:bw/hash.{token}?impl=aws_lc&size={m}&variant=ingest"
                ))?;
                let function = format!("{token}_ingest");
                group.bench(
                    s,
                    &bench(id, &function, m.clone(), bytes(size), "PERF-HSH-014"),
                    |iters| {
                        timed(iters, || {
                            let mut context = digest::Context::new(algorithm);
                            for chunk in black_box(&data).chunks(BLOB_CHUNK_SIZE) {
                                context.update(chunk);
                            }
                            black_box(context.finish());
                        })
                    },
                )?;
            }
            let id = osc(&format!("osc:bw/hash.blake3?impl=blake3&size={m}"))?;
            group.bench(
                s,
                &bench(id, "blake3", m.clone(), bytes(size), "PERF-HSH-012"),
                |iters| {
                    timed(iters, || {
                        black_box(blake3::hash(black_box(&data)));
                    })
                },
            )?;
            let id = osc(&format!(
                "osc:bw/hash.blake3?impl=blake3&size={m}&variant=ingest"
            ))?;
            group.bench(
                s,
                &bench(id, "blake3_ingest", m.clone(), bytes(size), "PERF-HSH-014"),
                |iters| {
                    timed(iters, || {
                        let mut hasher = blake3::Hasher::new();
                        for chunk in black_box(&data).chunks(BLOB_CHUNK_SIZE) {
                            hasher.update(chunk);
                        }
                        black_box(hasher.finalize());
                    })
                },
            )?;
            multi_buffer(group, s, size, &m)
        })?;
    }
    Ok(())
}

/// Every supported ISA-L multi-buffer SHA-256 kernel over the production
/// multi-object floor's objects, one record per kernel, each checked
/// against aws-lc's single-buffer digest before timing.
#[cfg(feature = "sha256-mb")]
fn multi_buffer(
    group: &mut CalibratedGroup<'_>,
    s: &mut CalibratedSession,
    size: usize,
    m: &str,
) -> BenchResult {
    use super::hash::{OBJECTS, objects};
    use rekindle_hash::multi_buffer::{Workspace, sha256_mb_with, supported};

    let kernels = supported();
    if kernels.is_empty() {
        eprintln!("hash.sha256 impl=isal_mb_* not measured: no multi-buffer kernel on this host");
        return Ok(());
    }
    let batch = objects(size);
    let chunks: Vec<&[u8]> = batch.iter().map(Vec::as_slice).collect();
    let mut workspace = Workspace::new();
    for kernel in kernels {
        let impl_name = format!("isal_mb_{}", kernel.name());
        let mut digests = vec![[0u8; 32]; OBJECTS];
        sha256_mb_with(&mut workspace, kernel, &chunks, &mut digests).map_err(|error| {
            format!("ISA-L {kernel} multi-buffer SHA-256 of {m} objects: {error}")
        })?;
        for (object, lane) in batch.iter().zip(&digests) {
            if digest::digest(&digest::SHA256, object).as_ref() != lane.as_slice() {
                return Err(format!(
                    "ISA-L {kernel} multi-buffer SHA-256 of a {m} object disagrees with aws-lc"
                )
                .into());
            }
        }
        let id = osc(&format!(
            "osc:bw/hash.sha256?impl={impl_name}&objects={OBJECTS}&size={m}"
        ))?;
        let function = format!("sha256_{impl_name}");
        group.bench(
            s,
            &bench(
                id,
                &function,
                m.to_owned(),
                bytes(size * OBJECTS),
                "PERF-HSH-013",
            ),
            |iters| {
                timed(iters, || {
                    let _ =
                        sha256_mb_with(&mut workspace, kernel, black_box(&chunks), &mut digests);
                    black_box(&digests);
                })
            },
        )?;
    }
    Ok(())
}

#[cfg(not(feature = "sha256-mb"))]
fn multi_buffer(
    _group: &mut CalibratedGroup<'_>,
    _s: &mut CalibratedSession,
    _size: usize,
    _m: &str,
) -> BenchResult {
    eprintln!("hash.sha256 impl=isal_mb_* not measured: sha256-mb feature not enabled");
    Ok(())
}

fn signatures(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let failure = Failure::default();
    let rng = SystemRandom::new();
    // The production Ed25519 floor signs with the seed [42; 32].
    let ed = Ed25519KeyPair::from_seed_unchecked(&[42; 32])?;
    let ed_signature = ed.try_sign(MESSAGE)?;
    let ed_public = UnparsedPublicKey::new(&signature::ED25519, ed.public_key().as_ref().to_vec());
    ed_public.verify(MESSAGE, ed_signature.as_ref())?;
    CalibratedGroup::scope(c, "signature_reference", |group| -> BenchResult {
        group.bench(
            s,
            &bench(
                osc("osc:lat/crypto.sign.ed25519?impl=aws_lc")?,
                "ed25519",
                "sign",
                None,
                "PERF-CAL-020",
            ),
            |iters| {
                timed(iters, || {
                    black_box(failure.ok(ed.try_sign(black_box(MESSAGE))));
                })
            },
        )?;
        group.bench(
            s,
            &bench(
                osc("osc:lat/crypto.verify.ed25519?impl=aws_lc")?,
                "ed25519",
                "verify",
                None,
                "PERF-CAL-020",
            ),
            |iters| {
                timed(iters, || {
                    black_box(
                        failure.ok(ed_public.verify(black_box(MESSAGE), ed_signature.as_ref())),
                    );
                })
            },
        )?;
        failure.check("aws-lc ed25519")?;
        for (name, signing, verification) in ECDSA {
            let key = EcdsaKeyPair::generate(signing)?;
            let signed = key.sign(&rng, MESSAGE)?;
            let public = UnparsedPublicKey::new(verification, key.public_key().as_ref().to_vec());
            public.verify(MESSAGE, signed.as_ref())?;
            group.bench(
                s,
                &bench(
                    osc(&format!("osc:lat/crypto.sign.{name}?impl=aws_lc"))?,
                    name,
                    "sign",
                    None,
                    "PERF-CAL-020",
                ),
                |iters| {
                    timed(iters, || {
                        black_box(failure.ok(key.sign(&rng, black_box(MESSAGE))));
                    })
                },
            )?;
            group.bench(
                s,
                &bench(
                    osc(&format!("osc:lat/crypto.verify.{name}?impl=aws_lc"))?,
                    name,
                    "verify",
                    None,
                    "PERF-CAL-020",
                ),
                |iters| {
                    timed(iters, || {
                        black_box(failure.ok(public.verify(black_box(MESSAGE), signed.as_ref())));
                    })
                },
            )?;
            failure.check(name)?;
        }
        Ok(())
    })
}
