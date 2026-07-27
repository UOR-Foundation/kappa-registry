//! Authorization via capability edge queries (D-2).
//!
//! Reserved namespaces are closed by default -- all operations including
//! reads require a capability edge. Open namespaces stay open.
//! Authorization is a capability-edge lookup in the namespace being
//! accessed. No policy engine, no Cedar -- one prefix scan on a table
//! that exists.

use crate::ratelimit::OpClass;
use crate::store::{EdgeRecord, KappaStore, StoreError};

/// Reserved namespace prefixes. All operations on these require a
/// capability edge -- reads included. Protocol module bytecode,
/// identity assertions, VRF key paths, and recovery share locations
/// are not public by default.
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

/// Authorize an operation on a namespace.
///
/// - Exempt operations always pass (health checks, version).
/// - Non-reserved namespaces always pass (open by default).
/// - Reserved namespaces require a capability edge from the namespace
///   authority granting the asserter the requested op class. This
///   includes reads -- reserved content is not public.
///
/// # Errors
///
/// Returns `StoreError::Conflict` with "forbidden:" prefix if the
/// capability check fails. The HttpErrorResponse impl maps
/// "forbidden:" prefix to HTTP 403.
pub fn authorize(
    store: &dyn KappaStore,
    ns: &str,
    op: OpClass,
    asserter: &str,
) -> Result<(), StoreError> {
    if matches!(op, OpClass::Exempt) {
        return Ok(());
    }
    if !is_reserved(ns) {
        return Ok(());
    }
    let caps = store.edge_query_by_asserter(ns, asserter, None, Some("capability"))?;
    if caps.iter().any(|e| cap_permits(e, op)) {
        Ok(())
    } else {
        Err(StoreError::Conflict(
            "forbidden: no capability edge for this operation on reserved namespace".to_owned(),
        ))
    }
}

fn cap_permits(edge: &EdgeRecord, op: OpClass) -> bool {
    let op_str = match op {
        OpClass::Read => "read",
        OpClass::Write => "write",
        OpClass::Admin => "admin",
        OpClass::Exempt => return true,
    };
    if let Some(obj) = edge.metadata.as_object() {
        if let Some(ops) = obj.get("ops").and_then(|v| v.as_array()) {
            return ops.iter().any(|v| v.as_str() == Some(op_str));
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_prefixes() {
        assert!(is_reserved("kappa/protocols/git"));
        assert!(is_reserved("kappa/identity/anchors"));
        assert!(is_reserved("nix/nixpkgs"));
        assert!(is_reserved("sesame/profiles"));
        assert!(!is_reserved("myorg/myrepo"));
        assert!(!is_reserved("docker.io/library/nginx"));
    }
}
