//! Namespace authority: who may read, write, or administer a namespace.
//!
//! One evaluator serves the server's authorization layer and the edge
//! handlers that admit capability and delegation grants, so a grant is
//! admitted under exactly the rule that later honours it.
//!
//! Authority over a namespace comes from, in order:
//! 1. authority over `_root` (capability or delegation chain in `_root`);
//! 2. ownership of the namespace;
//! 3. a capability edge in the namespace whose `ops` permit the operation;
//! 4. a capability edge in a parent namespace (`a/b` for `a/b/c`);
//! 5. a delegation chain: a signed, currently valid delegation whose scope
//!    covers the namespace and operation, from a delegator that itself holds
//!    authority, re-checked at every access so revoking a link cuts off
//!    everything delegated through it.
//!
//! A capability edge runs from the holder (`source`) to the namespace's
//! identity (`target`, [`namespace_identity`]) and carries `{"ops": [...]}`
//! metadata. Every grant in a namespace therefore shares one target, which
//! makes "does this namespace grant anything" a single inbound query.

use std::collections::HashSet;

use kappa_store::delegation::{DELEGATION_CHAIN_MAX_DEPTH, DelegationScope};
use kappa_store::edge::{BuiltinRelation, Direction, Edge, EdgeQuery, EdgeRelation};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;
use kappa_store::traits::{EdgeStore, NamespaceStore};
use kappa_store::{PageRequest, StoreError};

use crate::auth::Operation;

/// The namespace holding registry-wide authority.
pub const ROOT_NAMESPACE: &str = "_root";

/// Identity a namespace's capability edges target.
pub fn namespace_identity(ns: &NamespaceRef) -> Kappa {
    Kappa::sha256(ns.id())
}

/// Wire name of an operation in capability `ops` and delegation scopes.
pub const fn operation_name(op: Operation) -> &'static str {
    match op {
        Operation::Read => "read",
        Operation::Write => "write",
        Operation::Admin | Operation::Delete => "admin",
    }
}

/// Operations a capability edge grants, from its `{"ops": [...]}` metadata.
///
/// # Errors
///
/// `Rejected` when the metadata is absent, not an object with an `ops`
/// array of known operation names, or grants nothing.
pub fn capability_ops(metadata: Option<&[u8]>) -> Result<Vec<String>, StoreError> {
    let bytes = metadata.ok_or_else(|| {
        StoreError::Rejected("capability edges require {\"ops\": [...]} metadata".into())
    })?;
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| StoreError::Rejected(format!("capability metadata: {error}")))?;
    let ops = value
        .get("ops")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| StoreError::Rejected("capability metadata lacks an ops array".into()))?;
    let names = ops
        .iter()
        .map(|op| match op.as_str() {
            Some(name @ ("read" | "write" | "admin")) => Ok(name.to_string()),
            _ => Err(StoreError::Rejected(format!(
                "capability op {op} is not one of read, write, admin"
            ))),
        })
        .collect::<Result<Vec<_>, _>>()?;
    if names.is_empty() {
        return Err(StoreError::Rejected("capability grants no ops".into()));
    }
    Ok(names)
}

/// How a caller holds authority over a namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Grant {
    Root,
    Owner,
    Capability,
    ParentCapability,
    Delegation,
}

/// Store view the evaluator reads.
pub trait AuthorityStore: EdgeStore + NamespaceStore {}
impl<T: EdgeStore + NamespaceStore + ?Sized> AuthorityStore for T {}

/// How `caller` holds authority for `op` over `ns` at `now_ms`, or `None`.
///
/// # Errors
///
/// Store failures and corrupt grant records; an unreadable grant is never
/// treated as absent.
pub fn authority<S: AuthorityStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    caller: &Kappa,
    op: Operation,
    now_ms: i64,
) -> Result<Option<Grant>, StoreError> {
    let mut visiting = HashSet::new();
    evaluate(store, ns, caller, op, now_ms, 0, &mut visiting)
}

/// Whether `ns` grants any capability. A namespace without grants and
/// without an owner is open.
///
/// # Errors
///
/// Store failures.
pub fn grants_any<S: AuthorityStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
) -> Result<bool, StoreError> {
    let query = EdgeQuery {
        anchor: namespace_identity(ns),
        direction: Direction::Inbound,
        relation: Some(EdgeRelation::Builtin(BuiltinRelation::Capability)),
        asserter: None,
    };
    let page = store.edge_query(ns, &query, &PageRequest::first(1))?;
    Ok(!page.items.is_empty())
}

fn evaluate<S: AuthorityStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    caller: &Kappa,
    op: Operation,
    now_ms: i64,
    depth: u32,
    visiting: &mut HashSet<(Kappa, [u8; 16])>,
) -> Result<Option<Grant>, StoreError> {
    if !visiting.insert((caller.clone(), *ns.id())) {
        return Ok(None);
    }
    let root = store.namespace_resolve(ROOT_NAMESPACE, None)?;
    let grant = if root.id() != ns.id()
        && evaluate(store, &root, caller, op, now_ms, depth, visiting)?.is_some()
    {
        Some(Grant::Root)
    } else if store.namespace_info(ns)?.owner_anchor.as_ref() == Some(caller) {
        Some(Grant::Owner)
    } else if holds_capability(store, ns, caller, op)? {
        Some(Grant::Capability)
    } else if parent_capability(store, ns, caller, op)? {
        Some(Grant::ParentCapability)
    } else if delegated(store, ns, caller, op, now_ms, depth, visiting)? {
        Some(Grant::Delegation)
    } else {
        None
    };
    visiting.remove(&(caller.clone(), *ns.id()));
    Ok(grant)
}

fn holds_capability<S: AuthorityStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    caller: &Kappa,
    op: Operation,
) -> Result<bool, StoreError> {
    let target = namespace_identity(ns);
    let query = EdgeQuery {
        anchor: caller.clone(),
        direction: Direction::Outbound,
        relation: Some(EdgeRelation::Builtin(BuiltinRelation::Capability)),
        asserter: None,
    };
    let wanted = operation_name(op);
    any_edge(store, ns, &query, |edge| {
        if edge.target() != &target {
            return Ok(false);
        }
        Ok(capability_ops(edge.metadata())
            .map_err(|error| StoreError::Internal(format!("stored capability corrupt: {error}")))?
            .iter()
            .any(|granted| granted == wanted))
    })
}

fn parent_capability<S: AuthorityStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    caller: &Kappa,
    op: Operation,
) -> Result<bool, StoreError> {
    let mut name = ns.display_name();
    while let Some(index) = name.rfind('/') {
        name = &name[..index];
        if let Some(parent) = kappa_store::absent(store.namespace_resolve(name, None))?
            && holds_capability(store, &parent, caller, op)?
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Whether a valid delegation to `caller` covering `op` on `ns` exists in
/// `ns` or `_root` from a delegator that itself holds authority, granted
/// with enough remaining depth to pass authority on.
fn delegated<S: AuthorityStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    caller: &Kappa,
    op: Operation,
    now_ms: i64,
    depth: u32,
    visiting: &mut HashSet<(Kappa, [u8; 16])>,
) -> Result<bool, StoreError> {
    if depth > DELEGATION_CHAIN_MAX_DEPTH {
        return Ok(false);
    }
    let root = store.namespace_resolve(ROOT_NAMESPACE, None)?;
    let query = EdgeQuery {
        anchor: caller.clone(),
        direction: Direction::Inbound,
        relation: Some(EdgeRelation::Builtin(BuiltinRelation::Delegation)),
        asserter: None,
    };
    let mut holders = vec![ns.clone()];
    if root.id() != ns.id() {
        holders.push(root);
    }
    for holder in &holders {
        let mut scopes = Vec::new();
        any_edge(store, holder, &query, |edge| {
            let scope = delegation_scope(edge)?;
            if scope.delegate == *caller
                && scope.delegator == *edge.source()
                && scope.valid_from_ms <= now_ms
                && !scope.is_expired(now_ms)
                && scope.permits_namespace(ns.display_name())
                && scope.permits_operation(operation_name(op))
            {
                scopes.push(scope);
            }
            Ok(false)
        })?;
        for scope in scopes {
            if delegator_authorized(store, ns, &scope, op, now_ms, depth, visiting)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// The delegator holds authority directly, or through its own delegation
/// granted with remaining depth of at least one.
fn delegator_authorized<S: AuthorityStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    scope: &DelegationScope,
    op: Operation,
    now_ms: i64,
    depth: u32,
    visiting: &mut HashSet<(Kappa, [u8; 16])>,
) -> Result<bool, StoreError> {
    match evaluate(store, ns, &scope.delegator, op, now_ms, depth + 1, visiting)? {
        None => Ok(false),
        Some(Grant::Delegation) => {
            remaining_depth(store, ns, &scope.delegator, op, now_ms).map(|left| left >= 1)
        }
        Some(_) => Ok(true),
    }
}

/// Largest `max_depth` among valid delegations to `delegate` covering `op`
/// on `ns`, held in `ns` or `_root`.
///
/// # Errors
///
/// Store failures and corrupt delegation records.
pub fn remaining_depth<S: AuthorityStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    delegate: &Kappa,
    op: Operation,
    now_ms: i64,
) -> Result<u32, StoreError> {
    let root = store.namespace_resolve(ROOT_NAMESPACE, None)?;
    let query = EdgeQuery {
        anchor: delegate.clone(),
        direction: Direction::Inbound,
        relation: Some(EdgeRelation::Builtin(BuiltinRelation::Delegation)),
        asserter: None,
    };
    let mut holders = vec![ns.clone()];
    if root.id() != ns.id() {
        holders.push(root);
    }
    let mut depth = 0;
    for holder in holders {
        any_edge(store, &holder, &query, |edge| {
            let scope = delegation_scope(edge)?;
            if scope.delegate == *delegate
                && scope.valid_from_ms <= now_ms
                && !scope.is_expired(now_ms)
                && scope.permits_namespace(ns.display_name())
                && scope.permits_operation(operation_name(op))
            {
                depth = depth.max(scope.max_depth);
            }
            Ok(false)
        })?;
    }
    Ok(depth)
}

/// The signed scope a stored delegation edge carries. Admission verified the
/// signature; an unsigned or undecodable record here is corruption.
///
/// # Errors
///
/// `Internal` for a stored delegation without a decodable, signed scope.
pub fn delegation_scope(edge: &Edge) -> Result<DelegationScope, StoreError> {
    let bytes = edge.metadata().ok_or_else(|| {
        StoreError::Internal(format!("stored delegation {} has no scope", edge.kappa))
    })?;
    let scope: DelegationScope = serde_json::from_slice(bytes).map_err(|error| {
        StoreError::Internal(format!("stored delegation {} scope: {error}", edge.kappa))
    })?;
    if !scope.cose_signature.is_signed() {
        return Err(StoreError::Internal(format!(
            "stored delegation {} is unsigned",
            edge.kappa
        )));
    }
    Ok(scope)
}

/// Visit every edge matching `query` in `ns` until `visit` returns true.
/// A namespace the store does not know holds no edges.
fn any_edge<S: AuthorityStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    query: &EdgeQuery,
    mut visit: impl FnMut(&Edge) -> Result<bool, StoreError>,
) -> Result<bool, StoreError> {
    let mut request = PageRequest::first(256);
    loop {
        let Some(page) = kappa_store::absent(store.edge_query(ns, query, &request))? else {
            return Ok(false);
        };
        for edge in &page.items {
            if visit(edge)? {
                return Ok(true);
            }
        }
        let Some(next) = page.next_after else {
            return Ok(false);
        };
        if request
            .after
            .as_ref()
            .is_some_and(|previous| previous >= &next)
        {
            return Err(StoreError::Internal(
                "edge pagination did not advance".into(),
            ));
        }
        request.after = Some(next);
    }
}
