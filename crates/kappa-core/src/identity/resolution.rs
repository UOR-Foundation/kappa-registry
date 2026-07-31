//! Assertion resolution: query assertions about a subject.
//!
//! resolve_at returns assertions valid at a specific point in time.
//! resolve_all returns all assertions across all asserters.
//! Both filter by watermarks and revocations.

use crate::identity::assertion::IdentityAssertion;
use crate::identity::revocation::Revocation;
use crate::identity::watermark::Watermark;

/// Result of resolving assertions about a subject.
#[derive(Debug, Clone)]
pub struct ResolutionResult {
    /// Assertions that are currently valid (not revoked, not watermarked).
    pub valid: Vec<IdentityAssertion>,
    /// Assertions that were revoked.
    pub revoked: Vec<(IdentityAssertion, Revocation)>,
    /// Assertions invalidated by watermarks.
    pub watermarked: Vec<(IdentityAssertion, Watermark)>,
}

/// Resolve assertions about a subject at a specific timestamp.
///
/// Filters out:
/// - Assertions whose valid_from_ms is after `at_ms`
/// - Assertions whose valid_until_ms is before `at_ms`
/// - Assertions revoked by any revocation in `revocations`
/// - Assertions invalidated by any watermark in `watermarks`
pub fn resolve_at(
    assertions: &[IdentityAssertion],
    revocations: &[Revocation],
    watermarks: &[Watermark],
    at_ms: u64,
) -> ResolutionResult {
    let mut valid = Vec::new();
    let mut revoked = Vec::new();
    let mut watermarked = Vec::new();

    for assertion in assertions {
        if assertion.valid_from_ms > at_ms {
            continue;
        }
        if let Some(until) = assertion.valid_until_ms {
            if until < at_ms {
                continue;
            }
        }

        let assertion_kappa =
            crate::kappa::kappa_from_bytes(&crate::canonical::canonical_bytes(assertion));

        let rev = revocations
            .iter()
            .find(|r| r.assertion_kappa == assertion_kappa && r.asserter == assertion.asserter);
        if let Some(r) = rev {
            revoked.push((assertion.clone(), r.clone()));
            continue;
        }

        let wm = watermarks
            .iter()
            .find(|w| w.asserter == assertion.asserter && w.invalidates(assertion.valid_from_ms));
        if let Some(w) = wm {
            watermarked.push((assertion.clone(), w.clone()));
            continue;
        }

        valid.push(assertion.clone());
    }

    ResolutionResult {
        valid,
        revoked,
        watermarked,
    }
}

/// Resolve all assertions about a subject across all asserters.
///
/// Same filtering as resolve_at but without time bounds.
pub fn resolve_all(
    assertions: &[IdentityAssertion],
    revocations: &[Revocation],
    watermarks: &[Watermark],
) -> ResolutionResult {
    resolve_at(assertions, revocations, watermarks, u64::MAX)
}

/// Resolve all assertions with an optional asserter filter.
///
/// After the standard revocation/watermark filtering, applies the
/// asserter_filter closure to exclude assertions from untrusted asserters.
/// Pass None to allow all asserters (equivalent to resolve_all).
///
/// The filter is a closure rather than a trait to avoid kappa-core
/// depending on kappa-server's TrustPolicy type. The server layer
/// wires AllowList::believes as the closure.
pub fn resolve_all_filtered(
    assertions: &[IdentityAssertion],
    revocations: &[Revocation],
    watermarks: &[Watermark],
    asserter_filter: Option<&dyn Fn(&str) -> bool>,
) -> ResolutionResult {
    let mut result = resolve_all(assertions, revocations, watermarks);
    if let Some(filter) = asserter_filter {
        result.valid.retain(|a| filter(&a.asserter));
    }
    result
}

/// Resolve assertions at a specific time with an optional asserter filter.
pub fn resolve_at_filtered(
    assertions: &[IdentityAssertion],
    revocations: &[Revocation],
    watermarks: &[Watermark],
    at_ms: u64,
    asserter_filter: Option<&dyn Fn(&str) -> bool>,
) -> ResolutionResult {
    let mut result = resolve_at(assertions, revocations, watermarks, at_ms);
    if let Some(filter) = asserter_filter {
        result.valid.retain(|a| filter(&a.asserter));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::revocation::RevocationReason;

    fn make_assertion(
        asserter: &str,
        facet: &str,
        from: u64,
        until: Option<u64>,
    ) -> IdentityAssertion {
        IdentityAssertion {
            asserter: asserter.into(),
            subject: "subject-1".into(),
            facet: facet.into(),
            value: b"value".to_vec(),
            basis: "self-asserted".into(),
            valid_from_ms: from,
            valid_until_ms: until,
            signature: vec![],
        }
    }

    #[test]
    fn resolve_at_filters_by_time() {
        let assertions = vec![
            make_assertion("a", "f1", 100, Some(200)),
            make_assertion("a", "f2", 300, None),
        ];
        let result = resolve_at(&assertions, &[], &[], 150);
        assert_eq!(result.valid.len(), 1);
        assert_eq!(result.valid[0].facet, "f1");
    }

    #[test]
    fn resolve_at_excludes_expired() {
        let assertions = vec![make_assertion("a", "f1", 100, Some(200))];
        let result = resolve_at(&assertions, &[], &[], 300);
        assert_eq!(result.valid.len(), 0);
    }

    #[test]
    fn resolve_at_excludes_revoked() {
        let assertion = make_assertion("a", "f1", 100, None);
        let assertion_kappa =
            crate::kappa::kappa_from_bytes(&crate::canonical::canonical_bytes(&assertion));
        let revocation = Revocation {
            asserter: "a".into(),
            assertion_kappa,
            reason: RevocationReason::Superseded,
            revoked_at_ms: 500,
            signature: vec![],
        };
        let result = resolve_at(&[assertion], &[revocation], &[], 200);
        assert_eq!(result.valid.len(), 0);
        assert_eq!(result.revoked.len(), 1);
    }

    #[test]
    fn resolve_at_excludes_watermarked() {
        let assertion = make_assertion("a", "f1", 100, None);
        let watermark = Watermark {
            asserter: "a".into(),
            invalidate_before_ms: 200,
            reason: "key compromise".into(),
            set_at_ms: 300,
        };
        let result = resolve_at(&[assertion], &[], &[watermark], 150);
        assert_eq!(result.valid.len(), 0);
        assert_eq!(result.watermarked.len(), 1);
    }

    #[test]
    fn resolve_all_returns_everything_valid() {
        let assertions = vec![
            make_assertion("a", "f1", 100, None),
            make_assertion("b", "f2", 200, None),
        ];
        let result = resolve_all(&assertions, &[], &[]);
        assert_eq!(result.valid.len(), 2);
    }

    #[test]
    fn resolve_all_filtered_excludes_untrusted() {
        let assertions = vec![
            make_assertion("trusted", "f1", 100, None),
            make_assertion("untrusted", "f2", 200, None),
        ];
        let result = resolve_all_filtered(
            &assertions,
            &[],
            &[],
            Some(&|asserter: &str| asserter == "trusted"),
        );
        assert_eq!(result.valid.len(), 1);
        assert_eq!(result.valid[0].asserter, "trusted");
    }

    #[test]
    fn resolve_all_filtered_none_allows_all() {
        let assertions = vec![
            make_assertion("a", "f1", 100, None),
            make_assertion("b", "f2", 200, None),
        ];
        let result = resolve_all_filtered(&assertions, &[], &[], None);
        assert_eq!(result.valid.len(), 2);
    }

    #[test]
    fn resolve_at_filtered_combines_time_and_trust() {
        let assertions = vec![
            make_assertion("trusted", "f1", 100, Some(300)),
            make_assertion("untrusted", "f2", 100, None),
            make_assertion("trusted", "f3", 500, None),
        ];
        // At time 200: f1 is valid (100-300), f2 is valid, f3 not yet valid
        // Filter: only "trusted"
        let result = resolve_at_filtered(
            &assertions,
            &[],
            &[],
            200,
            Some(&|asserter: &str| asserter == "trusted"),
        );
        assert_eq!(result.valid.len(), 1);
        assert_eq!(result.valid[0].facet, "f1");
    }
}
