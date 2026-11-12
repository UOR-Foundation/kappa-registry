//! Commitment and publication floors (PERF-EPO-021, PERF-EPO-022,
//! PERF-STO-028).
//!
//! RFC 9162 Merkle root, proof and verification from 2^10 leaves up to
//! 2^24 at the full tier; the additive state digest; canonical dCBOR
//! encode and decode of the records every publication writes; and the
//! generation-publication primitives the memory store is built from
//! (`ArcSwap` load and store, persistent `imbl` map insert into a cloned
//! generation).

use std::hint::black_box;
use std::sync::Arc;

use arc_swap::ArcSwap;
use criterion::{Criterion, SamplingMode};
use imbl::OrdMap;
use kappa_perf::bench::{BenchResult, Failure, SplitMix, Tier, bench, osc, timed};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use kappa_types::StateDigest;
use kappa_types::canonical::{canonical_bytes, from_canonical};
use kappa_types::clock::ClockMs;
use kappa_types::epoch_root::{EpochRoot, EpochRootInput};
use kappa_types::kappa::Kappa;
use kappa_types::merkle::{merkle_proof, merkle_root, merkle_verify};
use kappa_types::namespace::NamespaceRef;
use kappa_types::tag::TagEntry;

pub fn register(c: &mut Criterion, s: &mut CalibratedSession, tier: Tier) -> BenchResult {
    merkle(c, s, tier)?;
    digest(c, s)?;
    canonical(c, s)?;
    publication(c, s, tier)
}

fn merkle(c: &mut Criterion, s: &mut CalibratedSession, tier: Tier) -> BenchResult {
    let exponents: &[u32] = tier.pick(&[10, 14], &[10, 14, 18, 20], &[10, 14, 18, 20, 22, 24]);
    let failure = Failure::default();
    for &exponent in exponents {
        let count = 1usize << exponent;
        let leaves: Vec<[u8; 8]> = (0..count as u64).map(u64::to_le_bytes).collect();
        let refs: Vec<&[u8]> = leaves.iter().map(<[u8; 8]>::as_slice).collect();
        let root = merkle_root(&refs);
        let probe = count / 3;
        let proof = merkle_proof(&refs, probe).ok_or("leaf out of range")?;
        let param = count.to_string();
        CalibratedGroup::scope(c, &format!("merkle_{count}"), |group| -> BenchResult {
            if exponent >= 18 {
                group.configure(|g| {
                    g.sampling_mode(SamplingMode::Flat);
                });
            }
            group.bench(
                s,
                &bench(
                    osc(&format!("osc:lat/merkle.root?leaves={count}"))?,
                    "root",
                    param.clone(),
                    None,
                    "PERF-EPO-022",
                ),
                |iters| {
                    timed(iters, || {
                        black_box(merkle_root(black_box(&refs)));
                    })
                },
            )?;
            group.bench(
                s,
                &bench(
                    osc(&format!("osc:lat/merkle.proof?leaves={count}"))?,
                    "proof",
                    param.clone(),
                    None,
                    "PERF-EPO-022",
                ),
                |iters| {
                    timed(iters, || {
                        black_box(merkle_proof(black_box(&refs), probe));
                    })
                },
            )?;
            group.bench(
                s,
                &bench(
                    osc(&format!("osc:lat/merkle.verify?leaves={count}"))?,
                    "verify",
                    param.clone(),
                    None,
                    "PERF-EPO-022",
                ),
                |iters| {
                    timed(iters, || {
                        if !merkle_verify(&root, black_box(&leaves[probe]), &proof) {
                            failure.fail("inclusion proof did not verify");
                        }
                    })
                },
            )?;
            failure.check("merkle.verify")
        })?;
    }
    Ok(())
}

fn digest(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let kappa = Kappa::sha256(b"digest floor");
    let names: Vec<String> = (0..4096).map(|i| format!("tags/release-{i:05}")).collect();
    let mut accumulator = StateDigest::default();
    let mut other = StateDigest::default();
    other.insert("other", &kappa);
    CalibratedGroup::scope(c, "state_digest", |group| -> BenchResult {
        let mut next = 0usize;
        group.bench(
            s,
            &bench(
                osc("osc:lat/digest.insert")?,
                "insert",
                "tag",
                None,
                "PERF-EPO-021",
            ),
            |iters| {
                timed(iters, || {
                    accumulator.insert(&names[next % names.len()], &kappa);
                    next += 1;
                    black_box(&accumulator);
                })
            },
        )?;
        group.bench(
            s,
            &bench(
                osc("osc:lat/digest.merge")?,
                "merge",
                "peer",
                None,
                "PERF-EPO-021",
            ),
            |iters| {
                timed(iters, || {
                    accumulator.merge(black_box(other));
                    black_box(&accumulator);
                })
            },
        )?;
        Ok(())
    })
}

fn canonical(c: &mut Criterion, s: &mut CalibratedSession) -> BenchResult {
    let entry = TagEntry {
        name: "releases/v1.42.0".into(),
        kappa: Kappa::sha256(b"content"),
        version: 42,
        created_at_ms: 1_700_000_000_000,
        updated_at_ms: 1_700_000_001_000,
        symref: None,
    };
    let anchor = Kappa::sha256(b"anchor");
    let ledger = Kappa::sha256(b"ledger");
    let ns = NamespaceRef::deterministic("floors");
    let root = EpochRoot::build(EpochRootInput {
        namespace: &ns,
        epoch_number: 9,
        prev_identifier: Some(&ledger),
        state_digest: [1; 32],
        mutations_root: [2; 32],
        timestamp: ClockMs::from_raw(1_700_000_000_000),
        signer_anchor: &anchor,
        tag_count: 10_000,
        rotation_kappa: None,
        ledger_root: &ledger,
        state: &Kappa::sha256(b"commit-bench-namespace-state"),
    });
    let entry_bytes = canonical_bytes(&entry);
    let root_bytes = root.to_bytes();
    let failure = Failure::default();
    CalibratedGroup::scope(c, "canonical", |group| -> BenchResult {
        group.bench(
            s,
            &bench(
                osc("osc:lat/canonical.encode?record=tag_entry")?,
                "encode",
                "tag_entry",
                None,
                "PERF-EPO-021",
            ),
            |iters| {
                timed(iters, || {
                    black_box(canonical_bytes(black_box(&entry)));
                })
            },
        )?;
        group.bench(
            s,
            &bench(
                osc("osc:lat/canonical.decode?record=tag_entry")?,
                "decode",
                "tag_entry",
                None,
                "PERF-EPO-021",
            ),
            |iters| {
                timed(iters, || {
                    black_box(failure.ok(from_canonical::<TagEntry>(black_box(&entry_bytes))));
                })
            },
        )?;
        group.bench(
            s,
            &bench(
                osc("osc:lat/canonical.encode?record=epoch_root")?,
                "encode",
                "epoch_root",
                None,
                "PERF-EPO-021",
            ),
            |iters| {
                timed(iters, || {
                    black_box(black_box(&root).to_bytes());
                })
            },
        )?;
        group.bench(
            s,
            &bench(
                osc("osc:lat/canonical.decode?record=epoch_root")?,
                "decode",
                "epoch_root",
                None,
                "PERF-EPO-021",
            ),
            |iters| {
                timed(iters, || {
                    black_box(failure.ok(EpochRoot::from_bytes(black_box(&root_bytes))));
                })
            },
        )?;
        failure.check("canonical.decode")
    })
}

fn publication(c: &mut Criterion, s: &mut CalibratedSession, tier: Tier) -> BenchResult {
    let current = ArcSwap::from_pointee(vec![0u8; 64]);
    let next = Arc::new(vec![1u8; 64]);
    let mut rng = SplitMix(13);
    CalibratedGroup::scope(c, "generation", |group| -> BenchResult {
        group.bench(
            s,
            &bench(
                osc("osc:lat/arcswap.load")?,
                "arcswap",
                "load",
                None,
                "PERF-STO-028",
            ),
            |iters| {
                timed(iters, || {
                    black_box(current.load().len());
                })
            },
        )?;
        group.bench(
            s,
            &bench(
                osc("osc:lat/arcswap.store")?,
                "arcswap",
                "store",
                None,
                "PERF-STO-028",
            ),
            |iters| {
                timed(iters, || {
                    current.store(Arc::clone(&next));
                })
            },
        )?;
        for keys in tier.pick(
            [1_000usize, 100_000],
            [1_000, 1_000_000],
            [1_000, 10_000_000],
        ) {
            let base: OrdMap<u64, u64> = (0..keys as u64)
                .map(|k| (k.wrapping_mul(0x9E37_79B9_7F4A_7C15), k))
                .collect();
            let id = osc(&format!("osc:lat/imbl.insert?keys={keys}"))?;
            group.bench(
                s,
                &bench(id, "imbl_insert", keys.to_string(), None, "PERF-STO-028"),
                |iters| {
                    timed(iters, || {
                        let mut candidate = base.clone();
                        candidate.insert(rng.next_u64(), 1);
                        black_box(candidate.len());
                    })
                },
            )?;
        }
        Ok(())
    })
}
