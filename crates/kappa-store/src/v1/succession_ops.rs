//! Identity succession: admission of dual-signed succession records, the
//! old anchor's signed watermark that accompanies them, and resolution and
//! verification of succession chains.
//!
//! Mutating functions write through an execution; their records become
//! visible only when the caller publishes it. Read-only functions take an
//! `IdentityStore`.

use std::collections::HashSet;

use crate::execution::ExecutionWrites;
use crate::identity_ops::AnchorKeyResolver;
use crate::traits::identity::IdentityStore;
use kappa_types::clock::ClockMs;
use kappa_types::edge::{BuiltinRelation, EdgeInput, EdgeRelation};
use kappa_types::error::StoreError;
use kappa_types::identity::{
    SUCCESSION_CHAIN_MAX, Succession, SuccessionReason, Watermark, WatermarkReason,
};
use kappa_types::kappa::Kappa;

// =========================================================================
// VerifiedSuccession
// =========================================================================

/// Proof that both signatures on a succession have been verified.
///
/// Constructible only through `VerifiedSuccession::verify`: its fields are
/// private, and `inner` is a `kappa_crypto::Verified`, which only
/// kappa-crypto's admission functions create. Retains the old anchor's
/// public key, proven to derive that anchor, so the records the old anchor
/// signs alongside the succession (its watermark) verify against that key.
pub struct VerifiedSuccession {
    inner: kappa_crypto::Verified<Succession>,
    old_public_key: Vec<u8>,
}

impl VerifiedSuccession {
    pub fn verify(
        succession: Succession,
        old_algorithm: &str,
        old_public_key: &[u8],
        new_algorithm: &str,
        new_public_key: &[u8],
    ) -> Result<Self, StoreError> {
        let inner = kappa_crypto::signed_types::admit_succession(
            succession,
            old_algorithm,
            old_public_key,
            new_algorithm,
            new_public_key,
        )
        .map_err(|error| StoreError::Rejected(format!("succession verification: {error}")))?;

        Ok(Self {
            inner,
            old_public_key: old_public_key.to_vec(),
        })
    }

    pub fn inner(&self) -> &Succession {
        self.inner.get()
    }

    /// The old anchor's public key, verified to derive `old_anchor`.
    pub fn old_public_key(&self) -> &[u8] {
        &self.old_public_key
    }

    pub fn into_inner(self) -> Succession {
        self.inner.into_inner()
    }
}

// =========================================================================
// Succession (mutating: writes through an execution)
// =========================================================================

/// Store a verified succession record through an execution.
///
/// The signed record itself is published, not only the successor index:
/// epoch admission retrieves the record by its content identity.
pub fn succession_put<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    verified: &VerifiedSuccession,
) -> Result<Kappa, StoreError> {
    execution.succession_put(&verified.inner)
}

/// Compute the default watermark for a succession.
///
/// Three reasons, two behaviors:
/// - `KeyCompromise`: `invalidate_before` = `i64::MAX` (void ALL assertions
///   from the compromised key, retroactively and forward)
/// - Rotation: `invalidate_before` = `effective_at` (void only assertions
///   before the rotation timestamp)
/// - Administrative: same as Rotation (void before the admin action)
///
/// A handler that needs different behavior (e.g., Policy with a
/// predicate filter) constructs the Watermark directly.
pub fn default_watermark_for_succession(
    succession: &Succession,
    now: ClockMs,
    signer: &dyn kappa_crypto::Signer,
) -> Result<Watermark, StoreError> {
    let (invalidate_before, reason) = succession_watermark_policy(succession)?;

    let watermark = Watermark {
        asserter: succession.old_anchor.clone(),
        invalidate_before_ms: invalidate_before,
        reason,
        set_at_ms: now.as_i64(),
        cose_signature: kappa_types::SignedPayload::empty(),
    };
    kappa_crypto::signed_types::sign_watermark(watermark, signer)
        .map_err(|error| StoreError::Rejected(format!("watermark signing: {error}")))
}

fn succession_watermark_policy(
    succession: &Succession,
) -> Result<(i64, WatermarkReason), StoreError> {
    let policy = match succession.reason {
        SuccessionReason::KeyCompromise => (i64::MAX, WatermarkReason::KeyCompromise),
        SuccessionReason::Rotation => (succession.effective_at_ms, WatermarkReason::Rotation),
        SuccessionReason::Administrative => {
            (succession.effective_at_ms, WatermarkReason::Administrative)
        }
        _ => {
            return Err(StoreError::Rejected(
                "unsupported succession watermark policy".into(),
            ));
        }
    };
    Ok(policy)
}

/// Store a verified succession with its policy watermark through an
/// execution. The watermark must carry the succession's policy and be
/// signed by the old anchor's verified key.
pub fn succession_put_with_default_watermark<E: ExecutionWrites + ?Sized>(
    execution: &mut E,
    verified: &VerifiedSuccession,
    watermark: &Watermark,
) -> Result<Kappa, StoreError> {
    let succession = verified.inner();
    let (cutoff, reason) = succession_watermark_policy(succession)?;
    if watermark.asserter != succession.old_anchor
        || watermark.invalidate_before_ms != cutoff
        || watermark.reason != reason
    {
        return Err(StoreError::Rejected(
            "watermark does not match succession policy".into(),
        ));
    }
    let admitted =
        kappa_crypto::signed_types::admit_watermark(watermark.clone(), verified.old_public_key())
            .map_err(|error| StoreError::Rejected(format!("watermark verification: {error}")))?;
    let kappa = succession_put(execution, verified)?;
    let wm_kappa = execution.watermark_put(admitted.get())?;

    execution.edge_put(&EdgeInput {
        source: succession.old_anchor.clone(),
        target: wm_kappa,
        relation: EdgeRelation::Builtin(BuiltinRelation::Watermark),
        asserter: succession.old_anchor.clone(),
        created_at_ms: execution.now().as_i64(),
        metadata: None,
    })?;

    Ok(kappa)
}

// =========================================================================
// Succession (read-only)
// =========================================================================

/// Walk at most `SUCCESSION_CHAIN_MAX` links, rejecting any repeated anchor.
///
/// The adapter supplies a successor and its output value from one protected
/// view. Absence terminates the walk; storage errors propagate unchanged.
/// The origin is not an output link.
pub fn walk_chain<T>(
    anchor: &Kappa,
    mut successor: impl FnMut(&Kappa) -> Result<Option<(Kappa, T)>, StoreError>,
) -> Result<Vec<T>, StoreError> {
    let mut chain = Vec::new();
    let mut current = anchor.clone();
    let mut visited = HashSet::new();
    visited.insert(current.key_bytes());

    loop {
        match successor(&current)? {
            Some((next, value)) => {
                let next_key = next.key_bytes();
                if visited.contains(&next_key) {
                    return Err(StoreError::Rejected(format!(
                        "succession cycle detected at {next}"
                    )));
                }
                if chain.len() >= SUCCESSION_CHAIN_MAX {
                    return Err(StoreError::CapacityExceeded(format!(
                        "succession chain exceeds {SUCCESSION_CHAIN_MAX} links"
                    )));
                }
                visited.insert(next_key);
                chain.push(value);
                current = next;
            }
            None => return Ok(chain),
        }
    }
}

pub fn succession_resolve<S: IdentityStore + ?Sized>(
    store: &S,
    anchor: &Kappa,
) -> Result<Kappa, StoreError> {
    let chain = succession_chain(store, anchor)?;
    chain
        .into_iter()
        .last()
        .ok_or_else(|| StoreError::Internal("succession traversal omitted its origin".into()))
}

pub fn succession_chain<S: IdentityStore + ?Sized>(
    store: &S,
    anchor: &Kappa,
) -> Result<Vec<Kappa>, StoreError> {
    let mut chain = vec![anchor.clone()];
    chain.extend(walk_chain(anchor, |current| {
        crate::absent(store.succession_get(current))
            .map(|next| next.map(|next| (next.clone(), next)))
    })?);
    Ok(chain)
}

/// Verify a succession chain from an anchor to its head.
///
/// Loads all succession records from the store, verifies dual
/// signatures on each link, checks contiguity, and checks monotone
/// effective-time ordering. Returns a `SuccessionChain` on success.
///
/// The `key_resolver` maps an anchor to its (algorithm, public key),
/// typically backed by binding lookups or the crypto keystore.
pub fn verify_succession_chain<S>(
    store: &S,
    anchor: &Kappa,
    key_resolver: &AnchorKeyResolver<'_>,
) -> Result<kappa_types::identity::SuccessionChain, StoreError>
where
    S: IdentityStore + ?Sized,
{
    let links = store.succession_chain_get(anchor)?;

    if links.is_empty() {
        return Ok(kappa_types::identity::SuccessionChain::from_verified_links(
            anchor.clone(),
            vec![],
        ));
    }

    if links.len() > SUCCESSION_CHAIN_MAX {
        return Err(StoreError::CapacityExceeded(format!(
            "succession chain exceeds {SUCCESSION_CHAIN_MAX} links"
        )));
    }

    let mut prev_anchor = anchor.clone();
    let mut visited = HashSet::from([anchor.key_bytes()]);
    let mut previous_effective_at = None;
    for (i, link) in links.iter().enumerate() {
        if link.old_anchor != prev_anchor {
            return Err(StoreError::Rejected(format!(
                "succession chain link {} is not contiguous: expected old_anchor {}, got {}",
                i, prev_anchor, link.old_anchor,
            )));
        }

        if !visited.insert(link.new_anchor.key_bytes()) {
            return Err(StoreError::Rejected(format!(
                "succession chain link {i} repeats an anchor"
            )));
        }
        if previous_effective_at.is_some_and(|previous| link.effective_at_ms < previous) {
            return Err(StoreError::Rejected(format!(
                "succession chain link {i} regresses effective time"
            )));
        }

        let old_keys = key_resolver(&link.old_anchor).ok_or_else(|| {
            StoreError::Rejected(format!(
                "no key material for old_anchor {} at chain link {}",
                link.old_anchor, i,
            ))
        })?;

        let new_keys = key_resolver(&link.new_anchor).ok_or_else(|| {
            StoreError::Rejected(format!(
                "no key material for new_anchor {} at chain link {}",
                link.new_anchor, i,
            ))
        })?;

        VerifiedSuccession::verify(
            link.clone(),
            &old_keys.0,
            &old_keys.1,
            &new_keys.0,
            &new_keys.1,
        )?;

        prev_anchor = link.new_anchor.clone();
        previous_effective_at = Some(link.effective_at_ms);
    }

    Ok(kappa_types::identity::SuccessionChain::from_verified_links(
        anchor.clone(),
        links,
    ))
}

#[cfg(test)]
#[path = "succession_watermark_tests.rs"]
mod succession_watermark_tests;

#[cfg(test)]
mod traversal_tests {
    use super::*;

    #[test]
    fn tail_cycle_is_rejected() {
        let anchors: Vec<_> = (0u8..3).map(|n| Kappa::sha256(&[n])).collect();
        let result = walk_chain(&anchors[0], |current| {
            let next = if current == &anchors[0] {
                &anchors[1]
            } else if current == &anchors[1] {
                &anchors[2]
            } else {
                &anchors[1]
            };
            Ok(Some((next.clone(), ())))
        });
        assert!(matches!(result, Err(StoreError::Rejected(_))));
    }

    #[test]
    fn exact_limit_terminates_but_one_more_link_is_refused() -> Result<(), StoreError> {
        let anchors: Vec<_> = (0..SUCCESSION_CHAIN_MAX + 2)
            .map(|n| Kappa::sha256(&n.to_be_bytes()))
            .collect();
        for length in [SUCCESSION_CHAIN_MAX, SUCCESSION_CHAIN_MAX + 1] {
            let mut position = 0;
            let result = walk_chain(&anchors[0], |current| {
                assert_eq!(current, &anchors[position]);
                if position == length {
                    return Ok(None);
                }
                position += 1;
                Ok(Some((anchors[position].clone(), position)))
            });
            if length == SUCCESSION_CHAIN_MAX {
                assert_eq!(result?, (1..=length).collect::<Vec<_>>());
            } else {
                assert!(matches!(result, Err(StoreError::CapacityExceeded(_))));
            }
        }
        Ok(())
    }

    #[test]
    fn storage_failure_is_not_chain_termination() {
        let result = walk_chain::<()>(&Kappa::sha256(b"origin"), |_| {
            Err(StoreError::Unavailable("unreadable successor".into()))
        });
        assert!(matches!(result, Err(StoreError::Unavailable(_))));
    }
}
