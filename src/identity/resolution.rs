//! Assertion resolution -- the read path.
//!
//! D-3: resolve_at is asserter-scoped (single asserter, comparable
//! epochs). resolve_all groups results by asserter. Cross-asserter
//! bitemporal comparison is not offered because it is not sound under
//! per-asserter Lamport counters.
//!
//! resolve_at returns ALL matching assertions, unmerged. The caller
//! (trust policy) decides what to believe. No merge operation exists.

use crate::identity::assertion::IdentityAssertion;
use crate::identity::revocation::Revocation;
use crate::store::StoreError;

/// Result of resolving assertions from a single asserter.
///
/// Contains the matching assertions and any revocations that apply
/// to them, so the caller can filter at the trust-policy level.
#[derive(Debug, Clone)]
pub struct ResolutionResult {
    /// Assertions matching the query, unfiltered for revocation.
    pub assertions: Vec<IdentityAssertion>,
    /// Revocations in the asserter's namespace targeting any of the
    /// returned assertions.
    pub revocations: Vec<Revocation>,
}

impl ResolutionResult {
    /// Filter out revoked assertions, returning only those with no
    /// matching revocation in the set.
    pub fn unrevoked(&self) -> Vec<&IdentityAssertion> {
        let revoked_targets: std::collections::HashSet<&str> =
            self.revocations.iter().map(|r| r.target.as_str()).collect();
        self.assertions
            .iter()
            .filter(|a| !revoked_targets.contains(a.kappa().as_str()))
            .collect()
    }
}

/// Resolve assertions from a single asserter about a subject on a facet.
///
/// This is the asserter-scoped read path where epochs are comparable.
/// `valid` and `observed` are both in the asserter's epoch space.
///
/// This function is the store-level primitive. The HTTP handler wraps
/// it with trust policy filtering.
///
/// # Arguments
///
/// * `store` - the KappaStore implementation
/// * `asserter_ns` - the asserter's namespace (safe_name of asserter anchor)
/// * `subject` - subject anchor kappa
/// * `facet` - facet path
/// * `valid` - "what was true at this epoch?" (asserter's epoch)
/// * `observed` - "what did we know at this epoch?" (asserter's epoch)
/// * `audience` - audience filter (None = all)
pub fn resolve_at(
    store: &dyn crate::store::KappaStore,
    asserter_ns: &str,
    subject: &str,
    facet: &str,
    valid: u64,
    observed: u64,
    audience: Option<&str>,
) -> Result<ResolutionResult, StoreError> {
    // Query assertions from the asserter's edge store.
    // The edge key format is: asserter + subject + facet (as relation) + assertion_kappa.
    // We scan by subject+facet prefix within the asserter's namespace.
    let edges = store.edge_query(
        asserter_ns,
        subject,
        crate::store::Direction::Outbound,
        Some(facet),
        None,
        None,
    )?;

    let mut assertions = Vec::new();
    let mut revocations = Vec::new();

    for edge in &edges {
        // Load the assertion blob
        if let Some(blob) = store.get(&edge.target)? {
            // Try to deserialize as assertion
            if let Ok(assertion) = serde_json::from_slice::<IdentityAssertion>(&blob) {
                // Apply temporal filters
                if assertion.valid_from <= valid && assertion.valid_to.is_none_or(|vt| vt > valid) {
                    // Apply audience filter
                    let audience_matches = match (audience, &assertion.audience) {
                        (None, _) => true,
                        (Some(aud), Some(a_aud)) => aud == a_aud,
                        (Some(_), None) => true,
                    };
                    if audience_matches {
                        assertions.push(assertion);
                    }
                }
            }
            // Try to deserialize as revocation
            if let Ok(revocation) = serde_json::from_slice::<Revocation>(&blob) {
                if revocation.epoch <= observed {
                    revocations.push(revocation);
                }
            }
        }
    }

    // Also scan for revocations targeting any of these assertions.
    // Revocations are stored as edges from the revoker to the target assertion kappa.
    for assertion in &assertions {
        let assertion_kappa = assertion.kappa();
        let rev_edges = store.edge_query(
            asserter_ns,
            &assertion_kappa,
            crate::store::Direction::Inbound,
            Some("revocation"),
            None,
            None,
        )?;
        for rev_edge in &rev_edges {
            if let Some(blob) = store.get(&rev_edge.target)? {
                if let Ok(revocation) = serde_json::from_slice::<Revocation>(&blob) {
                    if revocation.epoch <= observed {
                        revocations.push(revocation);
                    }
                }
            }
        }
    }

    Ok(ResolutionResult {
        assertions,
        revocations,
    })
}

/// Resolve assertions from all federated asserter namespaces,
/// grouped by asserter.
///
/// This is the cross-asserter read path. No epoch comparison across
/// asserters -- results are grouped so the caller can apply per-asserter
/// temporal reasoning.
///
/// # Arguments
///
/// * `store` - the KappaStore implementation
/// * `asserter_namespaces` - list of asserter namespace identifiers to query
/// * `subject` - subject anchor kappa
/// * `facet` - facet path
/// * `audience` - audience filter (None = all)
pub fn resolve_all(
    store: &dyn crate::store::KappaStore,
    asserter_namespaces: &[&str],
    subject: &str,
    facet: &str,
    audience: Option<&str>,
) -> Result<Vec<(String, ResolutionResult)>, StoreError> {
    let mut results = Vec::with_capacity(asserter_namespaces.len());
    for asserter_ns in asserter_namespaces {
        // For resolve_all, we use the asserter's current epoch as both
        // valid and observed -- "what does this asserter currently say?"
        let current_epoch = store.sequence_current(asserter_ns, "identity_epoch")?;
        let result = resolve_at(
            store,
            asserter_ns,
            subject,
            facet,
            current_epoch,
            current_epoch,
            audience,
        )?;
        if !result.assertions.is_empty() {
            results.push((asserter_ns.to_string(), result));
        }
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolution_result_unrevoked_filters_correctly() {
        let a1 = IdentityAssertion {
            asserter: "sha256:alice".to_owned(),
            subject: "sha256:bob".to_owned(),
            facet: "key/signing".to_owned(),
            value: b"key1".to_vec(),
            valid_from: 1,
            valid_to: None,
            basis: None,
            audience: None,
            matching_rule: None,
            signature: vec![0u8; 64],
        };
        let a1_kappa = a1.kappa();

        let a2 = IdentityAssertion {
            asserter: "sha256:alice".to_owned(),
            subject: "sha256:bob".to_owned(),
            facet: "key/signing".to_owned(),
            value: b"key2".to_vec(),
            valid_from: 2,
            valid_to: None,
            basis: None,
            audience: None,
            matching_rule: None,
            signature: vec![0u8; 64],
        };

        let revocation = Revocation {
            revoker: "sha256:alice".to_owned(),
            target: a1_kappa,
            reason: crate::identity::revocation::RevocationReason::Superseded,
            epoch: 3,
            signature: vec![0u8; 64],
        };

        let result = ResolutionResult {
            assertions: vec![a1, a2.clone()],
            revocations: vec![revocation],
        };

        let unrevoked = result.unrevoked();
        assert_eq!(unrevoked.len(), 1);
        assert_eq!(unrevoked[0].value, b"key2");
    }
}
