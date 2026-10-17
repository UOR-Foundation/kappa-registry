//! Reference ceilings: the best existing implementation of an operation,
//! measured on the same host by the same harness.
//!
//! A record whose conditions carry `impl` measures a reference
//! implementation of its operation (aws-lc's assembly digests and
//! signatures, ISA-L's multi-buffer SHA-256 lanes, a crate called directly);
//! a record without it measures kappa's production path. Every production
//! record is paired with the best same-host reference agreeing with it on
//! quantity, operation and every other condition, and carries the fraction
//! of that reference it achieves. No target number is written down anywhere:
//! the ceiling is whatever the best known implementation does on this host,
//! and a production path below 1.0 of it is behind prior art. The roofline
//! reads the same records, since its terms take the best measured floor, so
//! a reference also raises every composite bound built on that floor.

use super::grammar::OscId;
use super::record::ReferenceComparison;
use super::validate::Established;

/// Condition naming the reference implementation a record measures.
pub const IMPL: &str = "impl";

/// Whether `id` measures a reference implementation.
pub fn is_reference(id: &OscId) -> bool {
    id.conditions().contains_key(IMPL)
}

/// `reference` measures the same quantity of the same operation under the
/// same conditions as the production record `subject`, apart from `impl`.
fn pairs(subject: &OscId, reference: &OscId) -> bool {
    is_reference(reference)
        && subject.quantity() == reference.quantity()
        && subject.operation() == reference.operation()
        && subject.conditions().len() + 1 == reference.conditions().len()
        && reference
            .conditions()
            .iter()
            .filter(|(key, _)| *key != IMPL)
            .all(|(key, value)| subject.conditions().get(key) == Some(value))
}

/// The production record `subject` against the best reference among
/// `established`. `None` for a reference record, or when no reference pairs
/// with it.
pub fn compare(
    subject: &Established<'_>,
    established: &[Established<'_>],
) -> Option<ReferenceComparison> {
    if is_reference(subject.id) {
        return None;
    }
    let quantity = subject.id.quantity();
    let best = established
        .iter()
        .filter(|candidate| pairs(subject.id, candidate.id))
        .reduce(|a, b| {
            let better = if quantity.higher_is_better() {
                b.value > a.value
            } else {
                b.value < a.value
            };
            if better { b } else { a }
        })?;
    let fraction = quantity.achieved_fraction(subject.value, best.value)?;
    Some(ReferenceComparison {
        reference_id: best.id.canonical(),
        implementation: best.id.conditions().get(IMPL)?.to_owned(),
        reference_value: best.value,
        fraction,
        meets: fraction >= 1.0,
        reference_from_baseline: best.from_baseline,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn id(raw: &str) -> Result<OscId, Box<dyn std::error::Error>> {
        Ok(raw.parse()?)
    }

    const fn at(id: &OscId, value: f64) -> Established<'_> {
        Established {
            id,
            value,
            tail: None,
            from_baseline: false,
        }
    }

    #[test]
    fn production_paths_pair_with_the_best_reference_at_their_conditions() -> TestResult {
        let ours = id("osc:bw/hash.sha256?size=64k")?;
        let aws_lc = id("osc:bw/hash.sha256?impl=aws_lc&size=64k")?;
        let slower = id("osc:bw/hash.sha256?impl=portable&size=64k")?;
        let other_size = id("osc:bw/hash.sha256?impl=aws_lc&size=1m")?;
        let batched = id("osc:bw/hash.sha256?impl=isal_mb&objects=8&size=64k")?;
        let established = [
            at(&aws_lc, 4.4e8),
            at(&slower, 2.0e8),
            at(&other_size, 9.9e9),
            at(&batched, 9.9e9),
        ];
        let comparison = compare(&at(&ours, 1.32e8), &established).ok_or("unpaired")?;
        assert_eq!(comparison.implementation, "aws_lc");
        assert_eq!(comparison.reference_id, aws_lc.canonical());
        assert!((comparison.fraction - 0.3).abs() < 1e-9, "{comparison:?}");
        assert!(!comparison.meets);
        assert!(
            compare(&at(&aws_lc, 4.4e8), &established).is_none(),
            "a reference is never graded against references"
        );
        let unpaired = id("osc:bw/hash.sha256?size=4k")?;
        assert!(compare(&at(&unpaired, 1.0e8), &established).is_none());
        Ok(())
    }

    #[test]
    fn latency_references_are_best_when_lowest_and_meeting_counts() -> TestResult {
        let ours = id("osc:lat/crypto.sign.ed25519")?;
        let fast = id("osc:lat/crypto.sign.ed25519?impl=aws_lc")?;
        let slow = id("osc:lat/crypto.sign.ed25519?impl=other")?;
        let established = [at(&fast, 20_000.0), at(&slow, 40_000.0)];
        let behind = compare(&at(&ours, 25_000.0), &established).ok_or("unpaired")?;
        assert_eq!(behind.implementation, "aws_lc");
        assert!((behind.fraction - 0.8).abs() < 1e-9);
        assert!(!behind.meets);
        let ahead = compare(&at(&ours, 18_000.0), &established).ok_or("unpaired")?;
        assert!(ahead.meets && ahead.fraction > 1.0);
        Ok(())
    }
}
