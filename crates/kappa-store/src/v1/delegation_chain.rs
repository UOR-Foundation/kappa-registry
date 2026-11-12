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

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_types::{Capability, CapabilitySet, DelegationScope, SignedPayload};

    fn chain(length: u32) -> Vec<DelegationScope> {
        (0..length)
            .map(|index| DelegationScope {
                delegator: Kappa::sha256(&index.to_be_bytes()),
                delegate: Kappa::sha256(&(index + 1).to_be_bytes()),
                scope: vec!["read".into()],
                namespaces: Some(vec!["project/".into()]),
                valid_from_ms: 10,
                valid_until_ms: Some(100),
                max_depth: length - index - 1,
                nonce: index.to_be_bytes().to_vec(),
                cose_signature: SignedPayload::empty(),
            })
            .collect()
    }

    #[test]
    fn depth_256_verifies_every_link_and_depth_257_is_refused_before_signatures()
    -> Result<(), StoreError> {
        let capabilities = CapabilitySet::from_iter([Capability::Read]);
        let calls = std::cell::Cell::new(0usize);
        let verifier = |_: &Kappa, _: &[u8], _: &[u8]| {
            calls.set(calls.get() + 1);
            Ok(true)
        };
        let scopes = chain(256);
        let authority = verify_delegation_chain(&scopes, &capabilities, 50, &verifier)?;
        assert_eq!(calls.get(), 256);
        assert_eq!(authority.chain_length, 256);
        assert_eq!(authority.remaining_depth, 0);
        assert_eq!(authority.delegate, Kappa::sha256(&256u32.to_be_bytes()));
        assert_eq!(authority.capabilities, capabilities);
        assert_eq!(authority.scope, ["project/"]);
        calls.set(0);
        assert!(verify_delegation_chain(&chain(257), &capabilities, 50, &verifier).is_err());
        assert_eq!(calls.get(), 0);
        Ok(())
    }

    #[test]
    fn deep_chain_rejects_expiry_disconnection_cycles_and_exhausted_depth() {
        let capabilities = CapabilitySet::from_iter([Capability::Read]);
        let scopes = chain(256);
        assert!(verify_delegation_chain(&scopes, &capabilities, 100, &|_, _, _| Ok(true)).is_err());
        for index in [0, 127, 254] {
            let mut invalid = scopes.clone();
            invalid[index].max_depth = 0;
            assert!(
                verify_delegation_chain(&invalid, &capabilities, 50, &|_, _, _| Ok(true)).is_err()
            );
        }
        let mut invalid = scopes.clone();
        invalid[255].delegator = Kappa::sha256(b"unconnected");
        assert!(verify_delegation_chain(&invalid, &capabilities, 50, &|_, _, _| Ok(true)).is_err());
        invalid = scopes.clone();
        invalid[255].delegate = scopes[0].delegator.clone();
        assert!(verify_delegation_chain(&invalid, &capabilities, 50, &|_, _, _| Ok(true)).is_err());
        assert!(
            verify_delegation_chain(&scopes, &capabilities, 50, &|anchor, _, _| {
                Ok(*anchor != scopes[255].delegator)
            })
            .is_err()
        );
    }

    #[test]
    fn authenticated_depth_256_requires_every_anchor_bound_signature()
    -> Result<(), Box<dyn std::error::Error>> {
        use kappa_crypto::{Signer, ed25519::Ed25519Signer};
        let signers = (0u32..=256)
            .map(|index| {
                let mut seed = [0u8; 32];
                seed[..4].copy_from_slice(&index.to_be_bytes());
                Ed25519Signer::from_bytes(&seed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let anchors = signers
            .iter()
            .map(|signer| Kappa::from_key(signer.algorithm(), signer.public_key()))
            .collect::<Result<Vec<_>, _>>()?;
        let keys: std::collections::HashMap<_, _> = anchors
            .iter()
            .cloned()
            .zip(
                signers
                    .iter()
                    .map(|signer| (signer.algorithm().to_owned(), signer.public_key().to_vec())),
            )
            .collect();
        let mut scopes = chain(256);
        for (index, scope) in scopes.iter_mut().enumerate() {
            scope.delegator = anchors[index].clone();
            scope.delegate = anchors[index + 1].clone();
            *scope = kappa_crypto::signed_types::sign_delegation(scope.clone(), &signers[index])?;
        }
        let capabilities = CapabilitySet::from_iter([Capability::Read]);
        let resolve = |anchor: &Kappa| keys.get(anchor).cloned();
        let authority =
            verify_authenticated_delegation_chain(&scopes, &capabilities, 50, &resolve)?;
        assert_eq!(authority.delegate, anchors[256]);
        assert_eq!(authority.chain_length, 256);
        for index in [0, 127, 255] {
            let mut tampered = scopes.clone();
            tampered[index].nonce.push(1);
            assert!(
                verify_authenticated_delegation_chain(&tampered, &capabilities, 50, &resolve)
                    .is_err()
            );
        }
        assert!(
            verify_authenticated_delegation_chain(&scopes, &capabilities, 50, &|anchor| {
                if *anchor == anchors[255] {
                    None
                } else {
                    resolve(anchor)
                }
            })
            .is_err()
        );
        Ok(())
    }
}
