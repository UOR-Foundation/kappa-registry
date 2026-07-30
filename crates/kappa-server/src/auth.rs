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
use kappa_core::types::{Direction, Edge, EdgeQuery, EdgeRelation, StoreError};

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

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("forbidden: {reason}")]
    Forbidden { reason: String },
    #[error("store error during auth check: {0}")]
    Store(#[from] StoreError),
}

/// Authorize an operation on a namespace.
///
/// - Exempt operations always pass (health checks, version).
/// - Non-reserved namespaces always pass (open by default).
/// - Reserved namespaces require a capability edge from the namespace
///   authority granting the asserter the requested op class. This
///   includes reads -- reserved content is not public.
pub fn authorize(
    store: &dyn KappaStore,
    ns: &str,
    op: OpClass,
    asserter: &str,
) -> Result<(), AuthError> {
    if matches!(op, OpClass::Exempt) {
        return Ok(());
    }
    if !is_reserved(ns) {
        return Ok(());
    }

    // Query edges where the asserter is the source, looking for
    // Capability relation edges in this namespace.
    let query = EdgeQuery {
        anchor: asserter.to_string(),
        direction: Direction::Outbound,
        relation: Some(EdgeRelation::Capability),
        asserter: Some(asserter.to_string()),
    };
    let edges = store.edge_query(ns, &query)?;

    if edges.iter().any(|e| cap_permits(e, op)) {
        Ok(())
    } else {
        Err(AuthError::Forbidden {
            reason: "no capability edge for this operation on reserved namespace".to_owned(),
        })
    }
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
pub struct BearerAuth {
    tokens: std::collections::HashSet<String>,
    required: bool,
}

impl BearerAuth {
    pub fn new(tokens: Vec<String>, required: bool) -> Self {
        Self {
            tokens: tokens.into_iter().collect(),
            required,
        }
    }

    /// Check if a request is authorized.
    /// Returns Ok(()) if allowed, Err(Response) with 401 if not.
    #[allow(clippy::result_large_err)] // Response constructed once per 401, not a hot path
    pub fn check(
        &self,
        path: &str,
        headers: &topcoat::router::HeaderMap,
    ) -> Result<(), topcoat::router::Response> {
        if !self.required || self.tokens.is_empty() {
            return Ok(());
        }
        // Exempt paths: health, status, version check
        if path == "/_status"
            || path == "/v2/"
            || path == "/v2"
            || path.starts_with("/v2/_health/")
        {
            return Ok(());
        }
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match token {
            Some(t) if self.tokens.contains(t) => Ok(()),
            _ => {
                let body = r#"{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}"#;
                let mut resp =
                    topcoat::router::Response::new(topcoat::router::Body::from(body));
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
