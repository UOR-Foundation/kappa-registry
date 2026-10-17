//! Delegation chain verification: from a root authority to a delegate,
//! each link signed by its delegator, capabilities only narrowing.

use crate::identity_ops::AnchorKeyResolver;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;

pub type DelegationSignatureVerifier<'a> =
    dyn Fn(&Kappa, &[u8], &[u8]) -> Result<bool, StoreError> + 'a;

/// Verify a delegation chain from a root authority to a delegate.
///
/// Walks delegation edges from root to delegate. At each step:
/// 1. Verifies the delegator's signature on the `DelegationScope`
/// 2. Intersects capabilities with the parent's effective set
/// 3. Decrements `max_depth`
/// 4. Narrows the scope
///
/// Returns the `EffectiveAuthority` at the end of the chain.
pub fn verify_delegation_chain(
    scopes: &[kappa_types::delegation::DelegationScope],
    root_capabilities: &kappa_types::delegation::CapabilitySet,
    now_ms: i64,
    signature_verifier: &DelegationSignatureVerifier<'_>,
) -> Result<kappa_types::delegation::EffectiveAuthority, StoreError> {
    use kappa_types::delegation::{CapabilitySet, DELEGATION_CHAIN_MAX_DEPTH, EffectiveAuthority};

    if scopes.is_empty() {
        return Err(StoreError::Rejected("empty delegation chain".into()));
    }

    if scopes.len() as u64 > u64::from(DELEGATION_CHAIN_MAX_DEPTH) {
        return Err(StoreError::Rejected(format!(
            "delegation chain depth {} exceeds max {}",
            scopes.len(),
            DELEGATION_CHAIN_MAX_DEPTH,
        )));
    }

    let mut effective_caps = root_capabilities.clone();
    crate::delegation_policy::validate_chain(scopes, now_ms)?;
    let mut effective_scope: Vec<String> = vec!["*".into()];
    let mut remaining_depth = DELEGATION_CHAIN_MAX_DEPTH;

    for (i, scope) in scopes.iter().enumerate() {
        if scope.is_expired(now_ms) {
            return Err(StoreError::Rejected(format!("delegation link {i} expired")));
        }

        if scope.max_depth == 0 && i < scopes.len() - 1 {
            return Err(StoreError::Rejected(format!(
                "delegation link {i} has max_depth 0 but chain continues"
            )));
        }

        let signable = scope.signable_bytes();
        let valid =
            signature_verifier(&scope.delegator, &signable, scope.cose_signature.as_bytes())
                .map_err(|e| {
                    StoreError::Rejected(format!("delegation link {i} signature verification: {e}"))
                })?;
        if !valid {
            return Err(StoreError::Rejected(format!(
                "delegation link {i} signature invalid"
            )));
        }

        let granted = CapabilitySet::from_iter(scope.scope.iter().filter_map(|s| {
            match s.as_str() {
                "read" => Some(kappa_types::delegation::Capability::Read),
                "write" => Some(kappa_types::delegation::Capability::Write),
                "admin" => Some(kappa_types::delegation::Capability::Admin),
                other if other.starts_with("delegate:") => other
                    .strip_prefix("delegate:")
                    .and_then(|d| d.parse().ok())
                    .map(|depth| kappa_types::delegation::Capability::Delegate {
                        max_depth: depth,
                    }),
                other => Some(kappa_types::delegation::Capability::Custom {
                    name: other.to_string(),
                }),
            }
        }));
        effective_caps = effective_caps.intersection(&granted);

        if effective_caps.is_empty() {
            return Err(StoreError::Rejected(format!(
                "delegation link {i} intersection produced empty capability set, effectively revoked"
            )));
        }

        if let Some(ref ns) = scope.namespaces {
            effective_scope.clone_from(ns);
        }

        remaining_depth = scope.max_depth;
    }

    let last = &scopes[scopes.len() - 1];
    Ok(EffectiveAuthority {
        delegate: last.delegate.clone(),
        capabilities: effective_caps,
        scope: effective_scope,
        remaining_depth,
        chain_length: scopes.len(),
    })
}

/// Verify every COSE delegation signature against anchor-bound key material.
pub fn verify_authenticated_delegation_chain(
    scopes: &[kappa_types::DelegationScope],
    root_capabilities: &kappa_types::delegation::CapabilitySet,
    now_ms: i64,
    key_resolver: &AnchorKeyResolver<'_>,
) -> Result<kappa_types::delegation::EffectiveAuthority, StoreError> {
    verify_delegation_chain(
        scopes,
        root_capabilities,
        now_ms,
        &|anchor, payload, signature| {
            let (algorithm, key) = key_resolver(anchor).ok_or_else(|| {
                StoreError::Rejected("delegation signer key is unavailable".into())
            })?;
            if Kappa::from_key(&algorithm, &key)? != *anchor {
                return Err(StoreError::Rejected(
                    "delegation signer key does not match anchor".into(),
                ));
            }
            kappa_crypto::cose::verify(
                &kappa_types::SignedPayload::from_cose_bytes(signature.to_vec()),
                anchor,
                &key,
                kappa_types::signed::content_types::DELEGATION,
                payload,
            )
            .map_err(|error| StoreError::Rejected(format!("delegation signature: {error}")))?;
            Ok(true)
        },
    )
}
