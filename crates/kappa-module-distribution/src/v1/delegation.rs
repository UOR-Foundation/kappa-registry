//! Admission of capability and delegation grants.
//!
//! A grant is admitted under the same evaluator that later honours it
//! (`kappa_handler::authority`), so a grant can never confer more than its
//! grantor holds at the moment it is published.

use kappa_handler::HandlerError;
use kappa_handler::auth::Operation;
use kappa_handler::authority::{self, Grant};
use kappa_store::delegation::{DELEGATION_CHAIN_MAX_DEPTH, DelegationScope};
use kappa_store::kappa::Kappa;
use kappa_store::{KappaStore, NamespaceRef};

/// Key material proving the delegator signed a delegation scope.
pub(crate) struct DelegatorKey {
    pub algorithm: String,
    pub public_key: Vec<u8>,
}

/// A requested delegation edge: its endpoints, its scope metadata, and the
/// delegator key that signed the scope.
pub(crate) struct DelegationRequest<'a> {
    pub delegator: &'a Kappa,
    pub delegate: &'a Kappa,
    pub metadata: Option<&'a [u8]>,
    pub key: &'a DelegatorKey,
}

/// Operations a delegation scope names. `*` grants every operation.
fn scope_operations(scope: &DelegationScope) -> Result<Vec<Operation>, HandlerError> {
    if scope.scope.is_empty() {
        return Err(HandlerError::bad_request("delegation grants no operations"));
    }
    let mut operations = Vec::new();
    for name in &scope.scope {
        match name.as_str() {
            "*" => operations.extend([Operation::Read, Operation::Write, Operation::Admin]),
            "read" => operations.push(Operation::Read),
            "write" => operations.push(Operation::Write),
            "admin" => operations.push(Operation::Admin),
            other => {
                return Err(HandlerError::bad_request(format!(
                    "delegation operation {other} is not one of read, write, admin, *"
                )));
            }
        }
    }
    Ok(operations)
}

/// Admit `request`, published by `caller` in `ns` at Unix time `now_ms`.
///
/// The scope must be signed by the delegator's key, name exactly this edge's
/// endpoints, be valid now, and be requested by the delegator. The
/// delegator must hold authority for every delegated operation; authority
/// that itself arrived by delegation passes on only with remaining depth,
/// and the new grant's depth must be below it.
pub(crate) fn admit_delegation(
    s: &dyn KappaStore,
    ns: &NamespaceRef,
    caller: &Kappa,
    request: &DelegationRequest<'_>,
    now_ms: i64,
) -> Result<(), HandlerError> {
    let DelegationRequest {
        delegator,
        delegate,
        metadata,
        key,
    } = *request;
    let meta_bytes = metadata.ok_or_else(|| {
        HandlerError::bad_request("delegation edges require a signed DelegationScope")
    })?;
    let scope: DelegationScope = serde_json::from_slice(meta_bytes).map_err(|error| {
        HandlerError::bad_request(format!(
            "delegation metadata is not a DelegationScope: {error}"
        ))
    })?;
    if scope.delegator != *delegator || scope.delegate != *delegate {
        return Err(HandlerError::bad_request(
            "delegation scope does not name this edge's delegator and delegate",
        ));
    }
    if caller != delegator {
        return Err(HandlerError::forbidden(
            "only the delegator may publish its delegation",
        ));
    }
    if Kappa::from_key(&key.algorithm, &key.public_key)? != scope.delegator {
        return Err(HandlerError::bad_request(
            "public key does not derive the delegator anchor",
        ));
    }
    kappa_crypto::signed_types::verify_delegation(&scope, &key.public_key).map_err(|error| {
        HandlerError::bad_request(format!("delegation signature invalid: {error}"))
    })?;
    if scope.valid_from_ms > now_ms
        || scope.is_expired(now_ms)
        || scope
            .valid_until_ms
            .is_some_and(|until| until <= scope.valid_from_ms)
    {
        return Err(HandlerError::bad_request(
            "delegation validity interval does not contain the present",
        ));
    }
    if scope.max_depth > DELEGATION_CHAIN_MAX_DEPTH {
        return Err(HandlerError::bad_request(format!(
            "delegation depth {} exceeds the chain bound {DELEGATION_CHAIN_MAX_DEPTH}",
            scope.max_depth
        )));
    }

    for op in scope_operations(&scope)? {
        match authority::authority(s, ns, delegator, op, now_ms)? {
            None => {
                return Err(HandlerError::forbidden(format!(
                    "delegator holds no {} authority to delegate",
                    authority::operation_name(op)
                )));
            }
            Some(Grant::Delegation) => {
                let remaining = authority::remaining_depth(s, ns, delegator, op, now_ms)?;
                if remaining == 0 {
                    return Err(HandlerError::forbidden(
                        "delegator has depth=0 and cannot re-delegate",
                    ));
                }
                if scope.max_depth >= remaining {
                    return Err(HandlerError::forbidden(format!(
                        "new depth {} exceeds delegator remaining depth {}",
                        scope.max_depth,
                        remaining - 1,
                    )));
                }
            }
            Some(_) => {}
        }
    }
    Ok(())
}

/// Admit a capability grant to `holder` in `ns`, requested by `caller`.
///
/// The grant's `ops` must be valid, and the caller must hold admin
/// authority over the namespace, or be creating it (`creates`), in which
/// case the caller becomes its owner in the same execution.
pub(crate) fn admit_capability(
    s: &dyn KappaStore,
    ns: &NamespaceRef,
    caller: &Kappa,
    metadata: Option<&[u8]>,
    creates: bool,
    now_ms: i64,
) -> Result<(), HandlerError> {
    authority::capability_ops(metadata)?;
    if creates {
        return Ok(());
    }
    if authority::authority(s, ns, caller, Operation::Admin, now_ms)?.is_none() {
        return Err(HandlerError::forbidden(
            "granting a capability requires admin authority over the namespace",
        ));
    }
    Ok(())
}
