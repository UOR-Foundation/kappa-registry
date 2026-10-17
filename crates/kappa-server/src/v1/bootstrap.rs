//! Startup and rotation state, written through executions so every
//! mutation publishes in a signed epoch federation peers can verify.
//!
//! Every record naming the node's anchor or carrying its signature is
//! produced under one [`AuthorityView`], so a concurrent rotation cannot
//! pair one key's anchor with another's algorithm or signature. Callers
//! obtain the view from [`NodeIdentity::with_authority`] for the live
//! authority, or, inside a rotation, from the incoming authority the
//! transition is installing, so publication never re-enters the identity
//! lock the transition holds.
//!
//! The node's published authority state has two parts, reported separately
//! because they guarantee different things: [`publish_current`] publishes
//! the live authority's identity, `_root` capability and root delegation
//! (what the current authority and its delegate are authorized by), and
//! [`revoke_retired`] removes every retired authority's capability and
//! delegations (what no retired authority may still authorize). Each step
//! publishes nothing when already done, so startup and every rotation run
//! both, and an interrupted run is completed by the next.

use kappa_crypto::CryptoError;
use kappa_crypto::node::{AuthorityView, NodeIdentity};
use kappa_store::axis::Axis;
use kappa_store::edge::{BuiltinRelation, Edge, EdgeInput, EdgeRelation};
use kappa_store::kappa::Kappa;
use kappa_store::namespace::{NamespaceRef, ProtocolId};
use kappa_store::tag::TagUpdate;
use kappa_store::time::Clock;
use kappa_store::traits::KappaStore;
use kappa_store::{StoreError, VerifiedContent, namespace_ensure, publish_if_changed};

/// Create system namespaces required before any other operation.
///
/// Owner is None -- system namespaces have no identity owner. The protocol
/// modules do not need to exist for their namespaces to exist; the
/// namespace exists for the protocol module to find when it starts. Each
/// missing namespace is created in its own published epoch.
pub fn create_system_namespaces<S: KappaStore + ?Sized>(
    store: &S,
    clock: &dyn Clock,
) -> Result<Vec<NamespaceRef>, StoreError> {
    let nix_protocol = ProtocolId::new("nix")
        .map_err(|error| StoreError::Internal(format!("nix protocol id: {error}")))?;
    let system_ns: [(&str, Option<&ProtocolId>); 7] = [
        ("_root", None),
        ("_nix", Some(&nix_protocol)),
        ("_system", None),
        ("_admin", None),
        ("_aliases", None),
        ("_handles", None),
        (crate::identity_directory::DIRECTORY_NAMESPACE, None),
    ];
    system_ns
        .iter()
        .map(|(name, protocol)| {
            let ns = namespace_ensure(store, name, None, *protocol, clock)?;
            tracing::debug!(namespace = name, uuid = %ns.uuid_hex(), "system namespace ready");
            Ok(ns)
        })
        .collect()
}

/// A live-identity failure as a store error. An unavailable authority keeps
/// its typed state, so the HTTP boundary reports it as temporarily
/// unavailable rather than as an internal failure.
pub fn identity_error(error: CryptoError) -> StoreError {
    match error {
        CryptoError::AuthorityUnresolved { last } => {
            StoreError::AuthorityUnresolved { outgoing: last }
        }
        CryptoError::AuthorityInterrupted => StoreError::AuthorityInterrupted,
        CryptoError::AuthorityDiverged { live, committed } => {
            StoreError::AuthorityDiverged { live, committed }
        }
        other => StoreError::Internal(format!("node identity: {other}")),
    }
}

/// Publish `live`'s identity and `_root` capability and, when configured,
/// its `_root` delegation to `root_delegate`.
///
/// # Errors
///
/// The first failing step; the steps before it remain published and the
/// next call completes the rest.
pub fn publish_current<S: KappaStore + ?Sized>(
    store: &S,
    live: AuthorityView<'_>,
    root_delegate: Option<&Kappa>,
    clock: &dyn Clock,
) -> Result<(), StoreError> {
    write_node_identity(store, live, clock)?;
    if let Some(delegate) = root_delegate {
        create_root_delegation(store, live, delegate, clock)?;
    }
    Ok(())
}

/// Remove what every authority in `retired` held in `_root`. `live` must
/// not be among them.
///
/// # Errors
///
/// `Internal` when `live` is listed as retired; otherwise the first
/// failing removal, with earlier removals published.
pub fn revoke_retired<S: KappaStore + ?Sized>(
    store: &S,
    live: &Kappa,
    retired: &[Kappa],
    clock: &dyn Clock,
) -> Result<(), StoreError> {
    if retired.contains(live) {
        return Err(StoreError::Internal(format!(
            "live authority {live} is listed as retired"
        )));
    }
    for anchor in retired {
        retire_authority(store, anchor, clock)?;
    }
    Ok(())
}

/// [`publish_current`] under the live authority of `identity`.
///
/// # Errors
///
/// As [`publish_current`]; [`identity_error`] when the authority is
/// unavailable.
pub fn publish_live<S: KappaStore + ?Sized>(
    store: &S,
    identity: &NodeIdentity,
    root_delegate: Option<&Kappa>,
    clock: &dyn Clock,
) -> Result<(), StoreError> {
    identity
        .with_authority(|live| publish_current(store, live, root_delegate, clock))
        .map_err(identity_error)?
}

/// The `_root` capability the node's anchor holds.
fn capability(anchor: &Kappa, root_ns: &NamespaceRef) -> Result<EdgeInput, StoreError> {
    let metadata = serde_json::to_vec(&serde_json::json!({ "ops": ["read", "write", "admin"] }))
        .map_err(|error| StoreError::Internal(format!("capability metadata: {error}")))?;
    Ok(EdgeInput {
        source: anchor.clone(),
        target: kappa_handler::authority::namespace_identity(root_ns),
        relation: EdgeRelation::Builtin(BuiltinRelation::Capability),
        asserter: anchor.clone(),
        created_at_ms: 0,
        metadata: Some(metadata),
    })
}

/// Write the node's self-assertions and its `_root` capability edge, for
/// the authority `live`.
///
/// Stores the node's anchor, algorithm, version, and trust position as
/// content-addressed values tagged in the node's namespace, and a
/// Capability edge from the node anchor to `_root` granting
/// read/write/admin. Unchanged self-assertions publish nothing, so calling
/// it again after a failure completes the publication.
pub fn write_node_identity<S: KappaStore + ?Sized>(
    store: &S,
    live: AuthorityView<'_>,
    clock: &dyn Clock,
) -> Result<NamespaceRef, StoreError> {
    let anchor = live.anchor().clone();
    let algorithm = live.signer().algorithm();
    let anchor_str = anchor.to_string();

    let ns = namespace_ensure(store, &anchor_str, Some(&anchor), None, clock)?;
    let self_assertions: [(&str, &str); 4] = [
        ("node/anchor", &anchor_str),
        ("node/algorithm", algorithm),
        ("node/version", env!("CARGO_PKG_VERSION")),
        ("trust/position", "unprobed"),
    ];
    publish_if_changed(store, &ns, clock, |execution| {
        let mut changed = false;
        for (key, value) in &self_assertions {
            let content = VerifiedContent::compute(Axis::Sha256, value.as_bytes())?;
            let kappa = content.kappa().clone();
            if execution
                .tag_get_raw(key)?
                .is_some_and(|entry| entry.kappa == kappa && entry.symref.is_none())
            {
                continue;
            }
            execution.blob_put(&content)?;
            execution.tag_put(key, &TagUpdate::Set { kappa })?;
            changed = true;
        }
        Ok(changed)
    })?;

    let root_ns = store.namespace_resolve(kappa_handler::authority::ROOT_NAMESPACE, None)?;
    let capability = capability(&anchor, &root_ns)?;
    let present = !edges_from(
        store,
        &root_ns,
        &capability.source,
        &capability.relation,
        |edge| is_same(edge, &capability),
    )?
    .is_empty();
    publish_if_changed(store, &root_ns, clock, |execution| {
        if present {
            return Ok(false);
        }
        execution.edge_put(&capability)?;
        Ok(true)
    })?;

    tracing::info!(anchor = %anchor, algorithm, "node identity published");
    Ok(ns)
}

/// Remove everything `retired` holds in `_root` as a node authority: its
/// capability and every delegation it issued, in one epoch. A retired
/// authority signs nothing further, so it must keep neither administrative
/// reach nor grants issued under it; the live authority reissues the root
/// delegation. Removing nothing publishes nothing.
pub fn retire_authority<S: KappaStore + ?Sized>(
    store: &S,
    retired: &Kappa,
    clock: &dyn Clock,
) -> Result<(), StoreError> {
    let root_ns = store.namespace_resolve(kappa_handler::authority::ROOT_NAMESPACE, None)?;
    let capability = capability(retired, &root_ns)?;
    let mut held = edges_from(store, &root_ns, retired, &capability.relation, |edge| {
        is_same(edge, &capability)
    })?;
    let delegation = EdgeRelation::Builtin(BuiltinRelation::Delegation);
    held.extend(edges_from(store, &root_ns, retired, &delegation, |_| true)?);
    publish_if_changed(store, &root_ns, clock, |execution| {
        for edge in &held {
            execution.edge_delete(&edge.kappa)?;
        }
        Ok(!held.is_empty())
    })?;
    tracing::info!(retired = %retired, removed = held.len(), "retired node authority");
    Ok(())
}

/// Delegate `_root` authority from `live` to `delegate_anchor`.
///
/// The delegation is a `DelegationScope` signed by the node key, published
/// as a delegation edge in `_root`. Its fields are a function of the node
/// anchor and the delegate alone (unbounded validity from the epoch, nonce
/// derived from both anchors), so a restart reproduces the identical signed
/// record and an existing grant publishes nothing; after a rotation the
/// grant is issued again by the incoming authority and the retired
/// authority's grant is removed by [`retire_authority`].
pub fn create_root_delegation<S: KappaStore + ?Sized>(
    store: &S,
    live: AuthorityView<'_>,
    delegate_anchor: &Kappa,
    clock: &dyn Clock,
) -> Result<NamespaceRef, StoreError> {
    let root_ns = store.namespace_resolve(kappa_handler::authority::ROOT_NAMESPACE, None)?;
    let edge = delegation_edge(live, delegate_anchor)?;
    let present = !edges_from(store, &root_ns, &edge.source, &edge.relation, |existing| {
        is_same(existing, &edge)
    })?
    .is_empty();
    publish_if_changed(store, &root_ns, clock, |execution| {
        if present {
            return Ok(false);
        }
        execution.edge_put(&edge)?;
        Ok(true)
    })?;
    tracing::info!(delegate = %delegate_anchor, delegator = %edge.source, "delegated _root authority");
    Ok(root_ns)
}

/// The signed `_root` delegation from `live` to `delegate_anchor`.
fn delegation_edge(
    live: AuthorityView<'_>,
    delegate_anchor: &Kappa,
) -> Result<EdgeInput, StoreError> {
    let node_anchor = live.anchor();
    let mut nonce_input = b"kappa-root-delegation\0".to_vec();
    nonce_input.extend_from_slice(&node_anchor.key_bytes());
    nonce_input.extend_from_slice(&delegate_anchor.key_bytes());
    let scope = kappa_store::delegation::DelegationScope {
        delegator: node_anchor.clone(),
        delegate: delegate_anchor.clone(),
        scope: vec!["*".into()],
        namespaces: None,
        valid_from_ms: 0,
        valid_until_ms: None,
        max_depth: kappa_store::delegation::DELEGATION_CHAIN_MAX_DEPTH,
        nonce: kappa_store::kappa::sha256_raw(&nonce_input)[..16].to_vec(),
        cose_signature: kappa_store::SignedPayload::empty(),
    };
    let scope = kappa_crypto::signed_types::sign_delegation(scope, live.signer())
        .map_err(|error| StoreError::Internal(format!("root delegation signing: {error}")))?;
    let metadata = serde_json::to_vec(&scope)
        .map_err(|error| StoreError::Internal(format!("delegation scope: {error}")))?;
    Ok(EdgeInput {
        source: node_anchor.clone(),
        target: delegate_anchor.clone(),
        relation: EdgeRelation::Builtin(BuiltinRelation::Delegation),
        asserter: node_anchor.clone(),
        created_at_ms: 0,
        metadata: Some(metadata),
    })
}

/// Whether `existing` has the target and metadata of `edge`.
fn is_same(existing: &Edge, edge: &EdgeInput) -> bool {
    existing.target() == &edge.target && existing.metadata() == edge.metadata.as_deref()
}

/// Every edge in `ns` that `anchor` asserted from itself with `relation`
/// and that `keep` selects, across all pages.
fn edges_from<S: KappaStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    anchor: &Kappa,
    relation: &EdgeRelation,
    keep: impl Fn(&Edge) -> bool,
) -> Result<Vec<Edge>, StoreError> {
    let query = kappa_store::edge::EdgeQuery {
        anchor: anchor.clone(),
        direction: kappa_store::edge::Direction::Outbound,
        relation: Some(relation.clone()),
        asserter: Some(anchor.clone()),
    };
    let mut request = kappa_store::PageRequest::first(256);
    let mut matching = Vec::new();
    loop {
        let page = store.edge_query(ns, &query, &request)?;
        matching.extend(page.items.into_iter().filter(|existing| keep(existing)));
        let Some(next) = page.next_after else {
            return Ok(matching);
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
