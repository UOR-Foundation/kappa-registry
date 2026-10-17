//! Bearer authentication and namespace authorization.
//!
//! Authentication maps a bearer token to the caller's anchor. Authorization
//! decides whether that caller may perform an operation on the request's
//! namespace, using the shared evaluator in `kappa_handler::authority`.
//!
//! Namespace classes:
//! - closed: every operation needs authority (`_root`, `_admin`, and the
//!   reserved prefixes `kappa/protocols`, `kappa/runtimes`, `kappa/os`,
//!   `kappa/identity`, `nix`, `sesame`);
//! - system: readable by anyone, written only with authority (`_system`,
//!   `_aliases`, `_handles`, `_identity`);
//! - open: everything else. A namespace with no owner and no capability
//!   grants accepts every caller; an owned or granted namespace is readable
//!   by anyone and written only with authority.

use std::collections::HashMap;

use kappa_handler::ResolvedNamespace;
use kappa_handler::auth::Operation;
use kappa_handler::authority::{self, AuthorityStore, Grant};
use kappa_store::error::StoreError;
use kappa_store::kappa::Kappa;
use kappa_store::namespace::NamespaceRef;

use crate::ratelimit::OpClass;

/// The authenticated caller's identity. None = anonymous.
#[derive(Debug, Clone)]
pub struct AuthIdentity {
    pub asserter: Option<Kappa>,
}

pub struct BearerAuth {
    tokens: HashMap<String, Kappa>,
    required: bool,
}

impl BearerAuth {
    pub fn new(token_pairs: Vec<(String, Kappa)>, required: bool) -> Self {
        Self {
            tokens: token_pairs.into_iter().collect(),
            required,
        }
    }

    /// Whether requests must present a known token. Requiring tokens with
    /// none configured cannot authenticate anyone; the server then runs
    /// open rather than refusing every request with no recovery path.
    fn enforced(&self) -> bool {
        self.required && !self.tokens.is_empty()
    }

    /// Resolve the request's bearer token. A known token always yields its
    /// anchor; an unknown or missing token is rejected only when tokens are
    /// enforced, and is anonymous otherwise.
    pub fn check(
        &self,
        path: &str,
        headers: &http::HeaderMap,
    ) -> Result<AuthIdentity, Box<http::Response<bytes::Bytes>>> {
        if is_exempt(path) {
            return Ok(AuthIdentity { asserter: None });
        }
        let token = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        match token.and_then(|t| self.tokens.get(t)) {
            Some(anchor) => Ok(AuthIdentity {
                asserter: Some(anchor.clone()),
            }),
            None if self.enforced() => Err(Box::new(unauthorized())),
            None => Ok(AuthIdentity { asserter: None }),
        }
    }
}

fn is_exempt(path: &str) -> bool {
    path == "/_status" || path == "/v2/" || path == "/v2" || path.starts_with("/v2/_health/")
}

fn unauthorized() -> http::Response<bytes::Bytes> {
    http::Response::builder()
        .status(401)
        .header("www-authenticate", "Bearer realm=\"kappa-registry\"")
        .header("content-type", "application/json")
        .body(bytes::Bytes::from(
            r#"{"errors":[{"code":"UNAUTHORIZED","message":"authentication required"}]}"#,
        ))
        .expect("static response construction is infallible")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthDecision {
    Allowed,
    AllowCreateNew,
    AllowedViaDelegation,
}

#[derive(Debug)]
pub enum AuthError {
    Forbidden(String),
    NotFound,
    Store(StoreError),
}

impl From<StoreError> for AuthError {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

/// Namespaces where every operation needs authority.
const CLOSED: &[&str] = &[
    "_root",
    "_admin",
    "kappa/protocols",
    "kappa/runtimes",
    "kappa/os",
    "kappa/identity",
    "nix",
    "sesame",
];

/// Namespaces anyone may read and only authority holders may write.
const SYSTEM: &[&str] = &["_system", "_aliases", "_handles", "_identity"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Closed,
    System,
    Open,
}

/// Prefix match on whole path segments: `nix` covers `nix` and `nix/x`,
/// never `nixos`.
fn under(name: &str, prefix: &str) -> bool {
    name == prefix
        || name
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

fn classify(name: &str) -> Class {
    if CLOSED.iter().any(|prefix| under(name, prefix)) {
        Class::Closed
    } else if SYSTEM.iter().any(|prefix| under(name, prefix)) {
        Class::System
    } else {
        Class::Open
    }
}

const fn operation(op: OpClass) -> Option<Operation> {
    match op {
        OpClass::Exempt => None,
        OpClass::Read => Some(Operation::Read),
        OpClass::Write => Some(Operation::Write),
        OpClass::Admin => Some(Operation::Admin),
    }
}

/// Authorize `op` by `asserter` (None for anonymous) on the resolved
/// namespace at `now_ms`.
///
/// # Errors
///
/// `Forbidden` and `NotFound` are decisions; `Store` is a failure to read
/// the authority records, never treated as a denial or a grant.
pub fn authorize<S: AuthorityStore + ?Sized>(
    store: &S,
    resolved: &ResolvedNamespace,
    op: OpClass,
    asserter: Option<&Kappa>,
    now_ms: i64,
) -> Result<AuthDecision, AuthError> {
    let Some(operation) = operation(op) else {
        return Ok(AuthDecision::Allowed);
    };
    match resolved {
        ResolvedNamespace::NoNamespace => Ok(AuthDecision::Allowed),
        ResolvedNamespace::NotFound { name, .. } => {
            if let Some(caller) = asserter {
                let root = store.namespace_resolve(authority::ROOT_NAMESPACE, None)?;
                if authority::authority(store, &root, caller, operation, now_ms)?.is_some() {
                    return Ok(AuthDecision::AllowCreateNew);
                }
            }
            if classify(name) != Class::Open {
                return Err(AuthError::Forbidden(format!(
                    "reserved namespace '{name}' requires authority"
                )));
            }
            if op.is_write() {
                Ok(AuthDecision::AllowCreateNew)
            } else {
                Err(AuthError::NotFound)
            }
        }
        ResolvedNamespace::Exists(ns) => authorize_existing(store, ns, operation, asserter, now_ms),
    }
}

fn authorize_existing<S: AuthorityStore + ?Sized>(
    store: &S,
    ns: &NamespaceRef,
    op: Operation,
    asserter: Option<&Kappa>,
    now_ms: i64,
) -> Result<AuthDecision, AuthError> {
    let class = classify(ns.display_name());
    if class == Class::Open
        && store.namespace_info(ns)?.owner_anchor.is_none()
        && !authority::grants_any(store, ns)?
    {
        return Ok(AuthDecision::Allowed);
    }
    if class != Class::Closed && op == Operation::Read {
        return Ok(AuthDecision::Allowed);
    }
    let Some(caller) = asserter else {
        return Err(AuthError::Forbidden(format!(
            "{} on namespace '{}' requires authentication",
            authority::operation_name(op),
            ns.display_name()
        )));
    };
    match authority::authority(store, ns, caller, op, now_ms)? {
        Some(Grant::Delegation) => Ok(AuthDecision::AllowedViaDelegation),
        Some(_) => Ok(AuthDecision::Allowed),
        None => Err(AuthError::Forbidden(format!(
            "{} on namespace '{}' denied for {caller}",
            authority::operation_name(op),
            ns.display_name()
        ))),
    }
}

/// Trust policy for assertion resolution.
/// Stores allowed asserter Kappas. Empty = allow all.
pub struct AllowList {
    allowed: Vec<Kappa>,
}

impl AllowList {
    pub fn allow_all() -> Self {
        Self {
            allowed: Vec::new(),
        }
    }

    pub fn with_allowed(allowed: Vec<Kappa>) -> Self {
        Self { allowed }
    }

    pub fn believes(&self, asserter: &Kappa) -> bool {
        self.allowed.is_empty() || self.allowed.iter().any(|a| a == asserter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_match_whole_segments() {
        assert_eq!(classify("_root"), Class::Closed);
        assert_eq!(classify("kappa/protocols/git"), Class::Closed);
        assert_eq!(classify("nix/nixpkgs"), Class::Closed);
        assert_eq!(classify("nixos"), Class::Open);
        assert_eq!(classify("_nix"), Class::Open);
        assert_eq!(classify("_system"), Class::System);
        assert_eq!(classify("_identity/directory"), Class::System);
        assert_eq!(classify("myorg/myrepo"), Class::Open);
        assert_eq!(classify("sesamex"), Class::Open);
    }

    #[test]
    fn tokens_enforced_only_when_required_and_configured() {
        let anchor = Kappa::sha256(b"holder");
        let headers = http::HeaderMap::new();
        let open = BearerAuth::new(Vec::new(), true);
        assert!(open.check("/v2/x/tags/list", &headers).is_ok());
        let enforced = BearerAuth::new(vec![("t".into(), anchor.clone())], true);
        assert!(enforced.check("/v2/x/tags/list", &headers).is_err());
        assert!(enforced.check("/_status", &headers).is_ok());
        let mut with_token = http::HeaderMap::new();
        with_token.insert("authorization", http::HeaderValue::from_static("Bearer t"));
        let identity = enforced
            .check("/v2/x/tags/list", &with_token)
            .map_err(|_| "known token rejected")
            .map(|identity| identity.asserter);
        assert_eq!(identity, Ok(Some(anchor)));
    }
}
