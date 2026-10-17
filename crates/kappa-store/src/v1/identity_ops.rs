//! Composed identity operations over the raw storage primitives.
//!
//! Covers handles, assertion creation, resolution, and locator freshness.
//! Succession lives in `succession_ops`, delegation chain verification in
//! `delegation_chain`.
//!
//! Every mutating function writes through an execution. Its reads observe
//! the execution's own private writes, and its records become visible only
//! when the caller publishes the execution with its signed epoch. A failed
//! write latches the execution, so a partially applied composition can only
//! be aborted.
//!
//! Read-only functions take `&dyn KappaStore` or `&dyn IdentityStore`.

use std::collections::HashSet;

use crate::execution::ExecutionWrites;
use crate::traits::identity::IdentityStore;
use kappa_types::clock::ClockMs;
use kappa_types::edge::{BuiltinRelation, EdgeInput, EdgeRelation};
use kappa_types::error::StoreError;
use kappa_types::identity::{HandleRecord, IdentityAssertion, Revocation, Watermark};
use kappa_types::kappa::Kappa;
use kappa_types::namespace::ProtocolId;
use kappa_types::page::PageRequest;

/// Maps an anchor to its (algorithm, public key), for verifying records
/// the anchor signed.
pub type AnchorKeyResolver<'a> = dyn Fn(&Kappa) -> Option<(String, Vec<u8>)> + 'a;

// =========================================================================
// Handle operations (mutating: writes through an execution)
// =========================================================================

const DEFAULT_HANDLE_GRACE_MS: i64 = 7 * 24 * 3600 * 1000;

/// Claim a handle through an execution. The ownership check reads the
/// execution's own view, so it is decided under the same writer that
/// publishes the claim.
///
/// Conflict detection:
/// - Same anchor: update in place (re-verification, handle change)
/// - Different anchor, existing is attested: reject (409 Conflict)
/// - Different anchor, existing is unattested, within grace: reject
/// - Different anchor, existing is unattested, past grace: allow reclaim
/// - Not found: create
///
/// `claimed_at_ms` is an encoded `ClockMs`; the grace window is physical
/// milliseconds added to its physical component. A claim whose reclaim
/// deadline is not representable is never reclaimable.
pub fn handle_claim<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    record: &HandleRecord,
    grace_ms: i64,
) -> Result<(), StoreError> {
    let grace = u64::try_from(grace_ms)
        .map_err(|_| StoreError::Rejected("handle grace must be nonnegative".into()))?;
    if let Some(existing) = execution.handle_get(&record.protocol, &record.handle)?
        && existing.anchor != record.anchor
    {
        let is_attested = existing.attested_at_ms.is_some();
        let reclaim_at = ClockMs::from_raw(existing.claimed_at_ms).checked_add_physical_ms(grace);
        if is_attested || reclaim_at.is_none_or(|deadline| execution.now() < deadline) {
            return Err(StoreError::Conflict(format!(
                "handle {}:{} already claimed by {}",
                record.protocol, record.handle, existing.anchor,
            )));
        }
    }
    execution.handle_put(record)
}

/// Update handles for an anchor: remove all existing handles for the
/// given protocol and anchor, then claim the new handle.
///
/// Both identity module handle endpoints and AT Protocol updateHandle
/// call this function. One conflict check. One code path for all
/// handle mutations.
pub fn handle_update<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    anchor: &Kappa,
    new_record: &HandleRecord,
    protocol: &ProtocolId,
    grace_ms: i64,
) -> Result<(), StoreError> {
    if &new_record.anchor != anchor || &new_record.protocol != protocol {
        return Err(StoreError::Rejected(
            "replacement handle does not match requested owner and protocol".into(),
        ));
    }
    let mut request = PageRequest::first(256);
    let mut continuations = HashSet::new();
    let mut old_handles = Vec::new();
    loop {
        let page = execution.handle_list_by_anchor(anchor, &request)?;
        if page.items.len() > request.limit {
            return Err(StoreError::Rejected(
                "handle page exceeds requested bound".into(),
            ));
        }
        let empty = page.items.is_empty();
        for old in page.items {
            if &old.anchor != anchor {
                return Err(StoreError::Rejected(
                    "handle index returned another owner".into(),
                ));
            }
            if &old.protocol == protocol {
                old_handles.push(old.handle);
            }
        }
        match page.next_after {
            Some(next) => {
                if empty || !continuations.insert(next.clone()) {
                    return Err(StoreError::Rejected(
                        "handle continuation did not progress".into(),
                    ));
                }
                request.after = Some(next);
            }
            None => break,
        }
    }
    handle_claim(execution, new_record, grace_ms)?;
    for old in old_handles {
        if old != new_record.handle {
            execution.handle_delete(protocol, &old)?;
        }
    }

    Ok(())
}

pub const fn default_handle_grace_ms() -> i64 {
    DEFAULT_HANDLE_GRACE_MS
}

// =========================================================================
// Resolution (read-only)
// =========================================================================

#[derive(Debug, Clone)]
pub struct ResolutionResult {
    pub valid: Vec<IdentityAssertion>,
    pub revoked: Vec<(IdentityAssertion, Revocation)>,
    pub watermarked: Vec<(IdentityAssertion, Watermark)>,
}

pub fn resolve_at(
    assertions: &[(Kappa, IdentityAssertion)],
    revocations: &[Revocation],
    watermarks: &[Watermark],
    at_ms: i64,
) -> ResolutionResult {
    let mut valid = Vec::new();
    let mut revoked = Vec::new();
    let mut watermarked = Vec::new();

    for (kappa, assertion) in assertions {
        if assertion.valid_from_ms > at_ms {
            continue;
        }
        if assertion.valid_until_ms.is_some_and(|until| until < at_ms) {
            continue;
        }

        let rev = revocations
            .iter()
            .find(|r| r.assertion_kappa == *kappa && r.asserter == assertion.asserter);
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

pub fn resolve_all(
    assertions: &[(Kappa, IdentityAssertion)],
    revocations: &[Revocation],
    watermarks: &[Watermark],
) -> ResolutionResult {
    resolve_at(assertions, revocations, watermarks, i64::MAX)
}

pub fn resolve_all_filtered(
    assertions: &[(Kappa, IdentityAssertion)],
    revocations: &[Revocation],
    watermarks: &[Watermark],
    asserter_filter: Option<&dyn Fn(&Kappa) -> bool>,
) -> ResolutionResult {
    let mut result = resolve_all(assertions, revocations, watermarks);
    if let Some(filter) = asserter_filter {
        result.valid.retain(|a| filter(&a.asserter));
    }
    result
}

pub fn resolve_at_filtered(
    assertions: &[(Kappa, IdentityAssertion)],
    revocations: &[Revocation],
    watermarks: &[Watermark],
    at_ms: i64,
    asserter_filter: Option<&dyn Fn(&Kappa) -> bool>,
) -> ResolutionResult {
    let mut result = resolve_at(assertions, revocations, watermarks, at_ms);
    if let Some(filter) = asserter_filter {
        result.valid.retain(|a| filter(&a.asserter));
    }
    result
}

// =========================================================================
// Assertion creation (mutating: writes through an execution)
// =========================================================================

/// Create an assertion with semantic edge through an execution.
pub fn assertion_create<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    assertion: &IdentityAssertion,
) -> Result<Kappa, StoreError> {
    let kappa = execution.assertion_put(assertion)?;

    let subject_kappa = Kappa::sha256(assertion.subject.as_bytes());

    execution.edge_put(&EdgeInput {
        source: assertion.asserter.clone(),
        target: subject_kappa,
        relation: EdgeRelation::Builtin(BuiltinRelation::Assertion),
        asserter: assertion.asserter.clone(),
        created_at_ms: execution.now().as_i64(),
        metadata: None,
    })?;

    Ok(kappa)
}

/// Create two assertions as a double-entry pair through one execution, so
/// both entries publish in the same epoch or neither does.
pub fn assert_double_entry<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    assertion_a: &IdentityAssertion,
    assertion_b: &IdentityAssertion,
) -> Result<(Kappa, Kappa), StoreError> {
    let kappa_a = assertion_create(execution, assertion_a)?;
    let kappa_b = assertion_create(execution, assertion_b)?;
    Ok((kappa_a, kappa_b))
}

// =========================================================================
// Locator freshness (read-only)
// =========================================================================

/// Verify that a presented locator record is not stale.
///
/// Returns Ok if the presented epoch is equal to or higher than the stored
/// epoch, or if no stored record exists. Returns Err if the presented epoch
/// is lower.
pub fn verify_locator_freshness<S>(
    store: &S,
    presented: &kappa_types::identity::LocatorRecord,
) -> Result<(), StoreError>
where
    S: IdentityStore + ?Sized,
{
    match store.locator_get(&presented.anchor)? {
        Some(stored) => {
            if presented.locator_epoch < stored.locator_epoch {
                Err(StoreError::Rejected(format!(
                    "stale locator: presented epoch {} < stored epoch {}",
                    presented.locator_epoch, stored.locator_epoch,
                )))
            } else {
                Ok(())
            }
        }
        None => Ok(()),
    }
}

// =========================================================================
// Utility
// =========================================================================

pub fn derive_audience_label(subject: &str, audience_id: &str) -> String {
    let input = format!("{subject}:{audience_id}");
    let hash = blake3::hash(input.as_bytes());
    hex::encode(hash.as_bytes())
}
