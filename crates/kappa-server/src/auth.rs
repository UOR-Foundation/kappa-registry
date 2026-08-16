//! Authorization and trust policy.
//!
//! Authorization: capability-edge queries on reserved namespaces (D-2).
//! Reserved namespaces are closed by default -- all operations including
//! reads require a capability edge. Open namespaces stay open.
//!
//! Trust: reader-local, non-propagating assertion filter. Determines
//! which asserters a reader believes and how grouped assertions are
//! presented. Applied at read time. NOT stored, NOT propagated, NOT
//! part of the Merkle commitment. This is the seam where WASM policy
//! modules will substitute later.

use std::collections::BTreeSet;
use std::sync::RwLock;

use kappa_core::identity::assertion::IdentityAssertion;
use kappa_core::store::KappaStore;
use kappa_core::types::{DelegationScope, Direction, Edge, EdgeQuery, EdgeRelation, NamespaceRef, ResolvedNamespace, StoreError};

use crate::ratelimit::OpClass;

// -- Authorization ----------------------------------------------------------

/// Reserved namespace prefixes. All operations on these require a
/// capability edge -- reads included. Protocol module bytecode,
/// identity assertions, VRF key paths, runtime images, OS images,
/// and recovery share locations are not public by default.
pub const RESERVED_PREFIXES: &[&str] = &[
    "kappa/protocols",
    "kappa/runtimes",
    "kappa/os",
    "kappa/identity",
    "nix",
    "sesame",
];

/// Check if a namespace is reserved.
pub fn is_reserved(ns: &str) -> bool {
    RESERVED_PREFIXES.iter().any(|r| ns.starts_with(r))
}

#[derive(Debug, Clone)]
pub enum AuthDecision {
    Allowed,
    AllowCreateNew,
    AllowedViaDelegation,
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("forbidden: {reason}")]
    Forbidden { reason: String },
    #[error("not found")]
    NotFound,
    #[error("store error during auth check: {0}")]
    Store(#[from] StoreError),
}

/// Authorize an operation on a namespace.
///
/// Takes the already-resolved namespace from the interceptor layer.
/// The _root authority check resolves _root internally (it's the
/// authority namespace, not the request namespace).
///
/// Returns AuthDecision::AllowCreateNew when a write targets a
/// non-reserved namespace that doesn't exist yet (first-writer-claims).
/// The handler creates the namespace; the auth layer never does.
pub fn authorize(
    store: &dyn KappaStore,
    ns: &ResolvedNamespace,
    op: OpClass,
    asserter: &str,
) -> Result<AuthDecision, AuthError> {
    if matches!(op, OpClass::Exempt) {
        return Ok(AuthDecision::Allowed);
    }

    // Step 1: _root check (always, regardless of namespace state).
    // The _root namespace is bootstrapped at server start and always exists.
    if let Ok(root_ns) = store.namespace_resolve("_root", None) {
        let admin_query = EdgeQuery {
            anchor: asserter.to_string(),
            direction: Direction::Outbound,
            relation: Some(EdgeRelation::Capability),
            asserter: Some(asserter.to_string()),
        };
        if let Ok(edges) = store.edge_query(&root_ns, &admin_query) {
            if edges.iter().any(|e| cap_permits(e, op)) {
                return Ok(AuthDecision::Allowed);
            }
        }
        // Delegation chain walk on _root
        if check_delegation(store, &root_ns, op, asserter, 0)? {
            return Ok(AuthDecision::Allowed);
        }
    }

    match ns {
        ResolvedNamespace::Exists(ns_ref) => {
            let ns_name = ns_ref.as_str();

            // Step 2: owner check
            if let Ok(info) = store.namespace_info(ns_name, None) {
                if info.owner == asserter {
                    return Ok(AuthDecision::Allowed);
                }
            }

            // Step 3: non-reserved unclaimed namespace check
            if !is_reserved(ns_name) {
                let any_caps_query = EdgeQuery {
                    anchor: String::new(),
                    direction: Direction::Outbound,
                    relation: Some(EdgeRelation::Capability),
                    asserter: None,
                };
                match store.edge_query(ns_ref, &any_caps_query) {
                    Ok(caps) if caps.is_empty() => return Ok(AuthDecision::Allowed),
                    Ok(_) => {}
                    Err(_) => return Ok(AuthDecision::Allowed),
                }
            }

            // Step 4: direct capability check on target namespace
            let query = EdgeQuery {
                anchor: asserter.to_string(),
                direction: Direction::Outbound,
                relation: Some(EdgeRelation::Capability),
                asserter: Some(asserter.to_string()),
            };
            if let Ok(edges) = store.edge_query(ns_ref, &query) {
                if edges.iter().any(|e| cap_permits(e, op)) {
                    return Ok(AuthDecision::Allowed);
                }
            }

            // Step 5: namespace hierarchy walk
            let mut check_ns_str = ns_name;
            while let Some(pos) = check_ns_str.rfind('/') {
                check_ns_str = &check_ns_str[..pos];
                if let Ok(parent_ns) = store.namespace_resolve(check_ns_str, None) {
                    let parent_query = EdgeQuery {
                        anchor: asserter.to_string(),
                        direction: Direction::Outbound,
                        relation: Some(EdgeRelation::Capability),
                        asserter: Some(asserter.to_string()),
                    };
                    if let Ok(edges) = store.edge_query(&parent_ns, &parent_query) {
                        if edges.iter().any(|e| cap_permits(e, op)) {
                            return Ok(AuthDecision::Allowed);
                        }
                    }
                }
            }

            // Step 6: two-hop role check
            let role_query = EdgeQuery {
                anchor: asserter.to_string(),
                direction: Direction::Outbound,
                relation: Some(EdgeRelation::Capability),
                asserter: None,
            };
            if let Ok(role_edges) = store.edge_query(ns_ref, &role_query) {
                for role_edge in &role_edges {
                    if let Some(ref meta) = role_edge.metadata {
                        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(meta) {
                            if parsed.get("type").and_then(|v| v.as_str()) == Some("holds-role") {
                                let role_anchor = &role_edge.target;
                                let role_cap_query = EdgeQuery {
                                    anchor: role_anchor.clone(),
                                    direction: Direction::Outbound,
                                    relation: Some(EdgeRelation::Capability),
                                    asserter: Some(role_anchor.clone()),
                                };
                                if let Ok(role_caps) = store.edge_query(ns_ref, &role_cap_query) {
                                    if role_caps.iter().any(|e| cap_permits(e, op)) {
                                        return Ok(AuthDecision::Allowed);
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Step 7: delegation chain walk on target namespace
            if check_delegation(store, ns_ref, op, asserter, 0)? {
                return Ok(AuthDecision::AllowedViaDelegation);
            }

            Err(AuthError::Forbidden {
                reason: "access denied".to_owned(),
            })
        }
        ResolvedNamespace::NotFound { name, .. } => {
            if is_reserved(name) {
                Err(AuthError::Forbidden {
                    reason: format!("reserved namespace '{}' requires _root authority", name),
                })
            } else if op.is_write() {
                Ok(AuthDecision::AllowCreateNew)
            } else {
                Err(AuthError::NotFound)
            }
        }
        ResolvedNamespace::NoNamespace => {
            Ok(AuthDecision::Allowed)
        }
    }
}

/// Check if `target` is authorized via delegation chain.
/// Returns `Ok(Some(delegation_depth))` if authorized (the depth from
/// the edge that authorized `target`), `Ok(None)` if not.
/// `hop` tracks recursion depth (max 5 hops).
fn check_delegation(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    op: OpClass,
    target: &str,
    hop: u32,
) -> Result<bool, AuthError> {
    check_delegation_inner(store, ns, op, target, hop)
        .map(|r| r.is_some())
}

/// Inner delegation check returning the delegation_depth of the
/// authorizing edge, or None if not authorized.
fn check_delegation_inner(
    store: &dyn KappaStore,
    ns: &NamespaceRef,
    op: OpClass,
    target: &str,
    hop: u32,
) -> Result<Option<u32>, AuthError> {
    if hop > 5 {
        return Ok(None);
    }

    let op_str = match op {
        OpClass::Read => "read",
        OpClass::Write => "write",
        OpClass::Admin => "admin",
        OpClass::Exempt => return Ok(Some(u32::MAX)),
    };

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let root_ns = store.namespace_resolve("_root", None)
        .map_err(|e| AuthError::Store(e))?;
    let namespaces_to_check = [ns.clone(), root_ns];

    let query = EdgeQuery {
        anchor: target.to_string(),
        direction: Direction::Inbound,
        relation: Some(EdgeRelation::Delegation),
        asserter: None,
    };

    for check_ns in &namespaces_to_check {
        let edges = match store.edge_query(check_ns, &query) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for edge in &edges {
            let Some(ref meta) = edge.metadata else { continue };
            let Ok(scope) = serde_json::from_slice::<DelegationScope>(meta) else { continue };

            if !scope.namespaces.is_empty()
                && !scope.namespaces.iter().any(|n| ns.as_str().starts_with(n.as_str()))
            {
                continue;
            }

            if !scope.operations.iter().any(|o| o == op_str) {
                continue;
            }

            if let Some(expires) = scope.expires_at_ms {
                if now_ms > expires {
                    continue;
                }
            }

            let delegator = &edge.source;

            // Check delegator's direct capability
            let delegator_query = EdgeQuery {
                anchor: delegator.clone(),
                direction: Direction::Outbound,
                relation: Some(EdgeRelation::Capability),
                asserter: Some(delegator.clone()),
            };
            for cap_ns in &namespaces_to_check {
                if let Ok(cap_edges) = store.edge_query(cap_ns, &delegator_query) {
                    if cap_edges.iter().any(|e| cap_permits(e, op)) {
                        return Ok(Some(scope.delegation_depth));
                    }
                }
            }

            // Delegator has no direct capability. Recurse to check
            // if the delegator is authorized via its own delegation.
            if let Some(parent_depth) = check_delegation_inner(store, ns, op, delegator, hop + 1)? {
                // The parent delegation authorized the delegator with
                // parent_depth. The delegator can re-delegate only if
                // parent_depth >= 1.
                if parent_depth >= 1 {
                    return Ok(Some(scope.delegation_depth));
                }
            }
        }
    }

    Ok(None)
}

/// Check if a capability edge permits the requested operation class.
///
/// The edge's metadata bytes are parsed as JSON to find an "ops" array.
/// Each element of the array is a string: "read", "write", or "admin".
/// The requested op class must appear in the array.
fn cap_permits(edge: &Edge, op: OpClass) -> bool {
    let op_str = match op {
        OpClass::Read => "read",
        OpClass::Write => "write",
        OpClass::Admin => "admin",
        OpClass::Exempt => return true,
    };
    let meta_bytes = match &edge.metadata {
        Some(b) => b,
        None => return false,
    };
    let parsed: serde_json::Value = match serde_json::from_slice(meta_bytes) {
        Ok(v) => v,
        Err(_) => return false,
    };
    if let Some(ops) = parsed.get("ops").and_then(|v| v.as_array()) {
        return ops.iter().any(|v| v.as_str() == Some(op_str));
    }
    false
}

// -- Bearer token authentication --------------------------------------------

/// Bearer token authentication middleware.
///
/// Checks the Authorization header for a valid Bearer token.
/// Exempt paths (/_status, /v2/, /v2/_health/*) bypass auth.
/// When auth_required is false or the token list is empty, all
/// requests pass (permissive default for backward compatibility).
///
/// Every token maps to an asserter anchor. The auth layer uses the
/// anchor as the asserter identity for authorization decisions on
/// reserved namespaces, delegation chains, and capability checks.
pub struct BearerAuth {
    /// token -> anchor.
    tokens: std::collections::HashMap<String, String>,
    required: bool,
}

/// Result of a successful bearer auth check.
pub struct AuthIdentity {
    /// The asserter anchor for this request. "anonymous" if no
    /// anchor is bound to the token.
    pub asserter: String,
}

impl BearerAuth {
    pub fn new(tokens: Vec<(String, String)>, required: bool) -> Self {
        Self {
            tokens: tokens.into_iter().collect(),
            required,
        }
    }

    /// Check if a request is authorized.
    /// Returns Ok(AuthIdentity) if allowed, Err(Response) with 401 if not.
    /// The AuthIdentity carries the resolved asserter anchor for downstream
    /// authorization decisions.
    #[allow(clippy::result_large_err)]
    pub fn check(
        &self,
        path: &str,
        headers: &topcoat::router::HeaderMap,
    ) -> Result<AuthIdentity, topcoat::router::response::Response> {
        if !self.required || self.tokens.is_empty() {
            return Ok(AuthIdentity { asserter: "anonymous".to_string() });
        }
        // Exempt paths: health, status, version check
        if path == "/_status"
            || path == "/v2/"
            || path == "/v2"
            || path.starts_with("/v2/_health/")
        {
            return Ok(AuthIdentity { asserter: "anonymous".to_string() });
        }
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match token {
            Some(t) => match self.tokens.get(t) {
                Some(anchor) => Ok(AuthIdentity { asserter: anchor.clone() }),
                None => Self::unauthorized(),
            }
            None => Self::unauthorized(),
        }
    }

    fn unauthorized<T>() -> Result<T, topcoat::router::response::Response> {
        let body = r#"{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}"#;
        let mut resp =
            topcoat::router::response::Response::new(topcoat::router::Body::from(body));
        *resp.status_mut() = topcoat::router::StatusCode::UNAUTHORIZED;
        resp.headers_mut().insert(
            "www-authenticate",
            r#"Bearer realm="kappa-registry""#.parse().unwrap(),
        );
        resp.headers_mut()
            .insert("content-type", "application/json".parse().unwrap());
        Err(resp)
    }
}

// -- Authz result cache -----------------------------------------------------

/// Cache of authorization results keyed on (asserter, namespace, op_class).
///
/// Invalidated when any epoch advances. Uses DashMap for lock-free
/// concurrent reads on the hot path (every request checks authz).
/// Epoch-keyed invalidation: the cache stores results only for the
/// current epoch. When epoch_advance fires, the cache is cleared.
pub struct AuthzCache {
    cache: dashmap::DashMap<(String, String, u8), bool>,
    epoch: std::sync::atomic::AtomicU64,
}

impl AuthzCache {
    pub fn new() -> Self {
        Self {
            cache: dashmap::DashMap::new(),
            epoch: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Check cache for a prior authorization result. Returns None on miss.
    pub fn check(&self, asserter: &str, ns: &str, op: OpClass) -> Option<bool> {
        let key = (asserter.to_string(), ns.to_string(), op as u8);
        self.cache.get(&key).map(|v| *v)
    }

    /// Insert an authorization result.
    pub fn insert(&self, asserter: &str, ns: &str, op: OpClass, allowed: bool) {
        let key = (asserter.to_string(), ns.to_string(), op as u8);
        self.cache.insert(key, allowed);
    }

    /// Invalidate all cached results. Called on epoch advance.
    pub fn invalidate(&self) {
        self.cache.clear();
        self.epoch
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Number of cached entries (for diagnostics).
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Whether the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for AuthzCache {
    fn default() -> Self {
        Self::new()
    }
}

// -- Trust policy -----------------------------------------------------------

/// Trust policy applied to assertion resolution.
///
/// Registered in app_context. resolve_all's caller applies it to filter
/// and fuse assertions from multiple asserters.
pub trait TrustPolicy: Send + Sync {
    /// Whether this reader trusts assertions from `asserter` on `facet`.
    fn believes(&self, asserter: &str, facet: &str) -> bool;

    /// Filter and reorder grouped assertions. MUST NOT merge across
    /// asserter groups. MAY remove entire groups. MAY reorder within
    /// or across groups. MUST NOT collapse two asserter groups into one.
    ///
    /// The input is grouped by asserter (each tuple is one asserter's
    /// assertions). The output must maintain this grouping.
    fn fuse(
        &self,
        grouped: Vec<(String, Vec<IdentityAssertion>)>,
    ) -> Vec<(String, Vec<IdentityAssertion>)> {
        // Default: filter by believes(), keep all assertions from trusted asserters.
        grouped
            .into_iter()
            .filter(|(asserter, assertions)| {
                assertions
                    .first()
                    .map(|a| self.believes(asserter, &a.facet))
                    .unwrap_or(false)
            })
            .collect()
    }
}

/// Simple allowlist trust policy.
///
/// Trusts only asserters whose anchor kappas are in the `trusted` set.
/// If the set is empty, trusts all asserters (permissive default for
/// bootstrapping).
///
/// The fuse() method on TrustPolicy is the seam where WASM policy modules
/// substitute later. The AllowList implementation uses the default fuse()
/// which filters by believes().
pub struct AllowList {
    trusted: RwLock<Option<BTreeSet<String>>>,
}

impl AllowList {
    /// Create an allowlist that trusts all asserters.
    pub fn allow_all() -> Self {
        Self {
            trusted: RwLock::new(None),
        }
    }

    /// Create an allowlist that trusts only the specified asserters.
    pub fn from_set(trusted: BTreeSet<String>) -> Self {
        Self {
            trusted: RwLock::new(Some(trusted)),
        }
    }

    /// Permanently disable filtering. After fuse(), all asserters are
    /// trusted. Used for emergency lockout recovery.
    pub fn fuse_open(&self) {
        let mut guard = self.trusted.write().expect("trust policy lock poisoned");
        *guard = None;
    }

    /// Whether the allowlist has been fused open.
    pub fn is_fused_open(&self) -> bool {
        self.trusted
            .read()
            .expect("trust policy lock poisoned")
            .is_none()
    }
}

impl TrustPolicy for AllowList {
    fn believes(&self, asserter: &str, _facet: &str) -> bool {
        let guard = self.trusted.read().expect("trust policy lock poisoned");
        match &*guard {
            None => true, // fused open or empty set: trust all
            Some(set) => {
                if set.is_empty() {
                    true // empty set: permissive default for bootstrapping
                } else {
                    set.contains(asserter)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Authorization tests --

    #[test]
    fn reserved_prefixes() {
        assert!(is_reserved("kappa/protocols/git"));
        assert!(is_reserved("kappa/runtimes/wasm"));
        assert!(is_reserved("kappa/os/nixos"));
        assert!(is_reserved("kappa/identity/anchors"));
        assert!(is_reserved("nix/nixpkgs"));
        assert!(is_reserved("sesame/profiles"));
        assert!(!is_reserved("myorg/myrepo"));
        assert!(!is_reserved("docker.io/library/nginx"));
        assert!(!is_reserved("conformance/test"));
    }

    // -- Trust policy tests --

    #[test]
    fn allow_all_trusts_everything() {
        let policy = AllowList::allow_all();
        assert!(policy.believes("sha256:abc", "key/signing"));
        assert!(policy.believes("sha256:def", "name/display"));
    }

    #[test]
    fn explicit_set_filters() {
        let mut trusted = BTreeSet::new();
        trusted.insert("sha256:abc".to_owned());
        let policy = AllowList::from_set(trusted);
        assert!(policy.believes("sha256:abc", "key/signing"));
        assert!(!policy.believes("sha256:def", "key/signing"));
    }

    #[test]
    fn empty_set_trusts_all() {
        let policy = AllowList::from_set(BTreeSet::new());
        assert!(policy.believes("sha256:anything", "any/facet"));
    }

    #[test]
    fn fuse_open_permanently_allows() {
        let mut trusted = BTreeSet::new();
        trusted.insert("sha256:abc".to_owned());
        let policy = AllowList::from_set(trusted);
        assert!(!policy.believes("sha256:def", "key/signing"));
        policy.fuse_open();
        assert!(policy.believes("sha256:def", "key/signing"));
        assert!(policy.is_fused_open());
    }

    #[test]
    fn fuse_filters_untrusted_assertions() {
        let mut trusted = BTreeSet::new();
        trusted.insert("sha256:alice".to_owned());
        let policy = AllowList::from_set(trusted);

        let assertion = |asserter: &str| IdentityAssertion {
            asserter: asserter.to_owned(),
            subject: "sha256:bob".to_owned(),
            facet: "key/signing".to_owned(),
            value: b"key-bytes".to_vec(),
            basis: "self-asserted".to_owned(),
            valid_from_ms: 1,
            valid_until_ms: None,
            signature: vec![0u8; 64],
        };

        let grouped = vec![
            ("sha256:alice".to_owned(), vec![assertion("sha256:alice")]),
            ("sha256:eve".to_owned(), vec![assertion("sha256:eve")]),
        ];

        let fused = policy.fuse(grouped);
        assert_eq!(fused.len(), 1);
        assert_eq!(fused[0].0, "sha256:alice");
    }

    #[test]
    fn fuse_preserves_grouping() {
        let policy = AllowList::allow_all();

        let assertion = |asserter: &str, val: &[u8]| IdentityAssertion {
            asserter: asserter.to_owned(),
            subject: "sha256:bob".to_owned(),
            facet: "key/signing".to_owned(),
            value: val.to_vec(),
            basis: "self-asserted".to_owned(),
            valid_from_ms: 1,
            valid_until_ms: None,
            signature: vec![0u8; 64],
        };

        let grouped = vec![
            (
                "sha256:alice".to_owned(),
                vec![assertion("sha256:alice", b"key-a")],
            ),
            (
                "sha256:carol".to_owned(),
                vec![assertion("sha256:carol", b"key-c")],
            ),
        ];

        let fused = policy.fuse(grouped);
        assert_eq!(fused.len(), 2);
        assert_ne!(fused[0].0, fused[1].0);
    }
}
