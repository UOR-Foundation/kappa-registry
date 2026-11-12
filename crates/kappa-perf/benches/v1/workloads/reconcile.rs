//! Tag reconciliation workloads over the namespace Merkle search tree
//! (`kappa_reconcile::NamespaceMst`): building a tree from a tag
//! population, and the diff of two trees at a given divergence. Every
//! diff is checked against what it must find: nothing between identical
//! trees, and every changed key covered otherwise.

use std::collections::BTreeMap;
use std::hint::black_box;

use criterion::Criterion;
use kappa_perf::bench::fixture::{tag_name, tag_target};
use kappa_perf::bench::{BenchResult, Failure, Tier, bench, elements, osc, timed};
use kappa_perf::calibrate::{CalibratedGroup, CalibratedSession};
use kappa_reconcile::NamespaceMst;

const fn populations(tier: Tier) -> &'static [usize] {
    tier.pick(&[1_000], &[1_000, 100_000], &[1_000, 100_000, 1_000_000])
}

/// Changed keys between the two trees: none, one, one in a thousand, one
/// in a hundred.
fn divergences(keys: usize) -> [usize; 4] {
    [0, 1, keys / 1_000, keys / 100]
}

fn tags(keys: usize, changed: usize, round: u64) -> BTreeMap<String, String> {
    (0..keys)
        .map(|index| {
            let generation = if index < changed { round } else { 0 };
            (tag_name(index), tag_target(index, generation).to_string())
        })
        .collect()
}

pub fn register(c: &mut Criterion, s: &mut CalibratedSession, tier: Tier) -> BenchResult {
    let failure = Failure::default();
    for &keys in populations(tier) {
        let local_tags = tags(keys, 0, 0);
        CalibratedGroup::scope(c, &format!("reconcile_{keys}"), |group| -> BenchResult {
            let id = osc(&format!("osc:lat/reconcile.rebuild?keys={keys}"))?;
            group.bench(
                s,
                &bench(
                    id,
                    "rebuild",
                    keys.to_string(),
                    elements(keys),
                    "PERF-DST-010",
                ),
                |iters| {
                    timed(iters, || {
                        let mut tree = NamespaceMst::new("reconcile".into());
                        tree.rebuild(black_box(&local_tags));
                        black_box(tree.root_hash());
                    })
                },
            )?;
            let mut local = NamespaceMst::new("reconcile".into());
            local.rebuild(&local_tags);
            for divergence in divergences(keys) {
                let mut remote = NamespaceMst::new("reconcile".into());
                remote.rebuild(&tags(keys, divergence, 1));
                let snapshot = remote.snapshot()?;
                let id = osc(&format!(
                    "osc:lat/reconcile.diff?divergence={divergence}&keys={keys}"
                ))?;
                group.bench(
                    s,
                    &bench(id, "diff", divergence.to_string(), None, "PERF-DST-010"),
                    |iters| {
                        timed(iters, || {
                            let Some(diff) = failure.ok(local.diff(black_box(&snapshot))) else {
                                return;
                            };
                            if divergence == 0 {
                                if !diff.is_empty() {
                                    failure.fail("identical trees reported a difference");
                                }
                            } else if let Some(missed) =
                                (0..divergence).find(|index| !diff.covers(&tag_name(*index)))
                            {
                                failure.fail(format!(
                                    "changed key {} is not covered by the diff",
                                    tag_name(missed)
                                ));
                            }
                        })
                    },
                )?;
                failure.check("reconcile.diff")?;
            }
            Ok(())
        })?;
    }
    Ok(())
}
