use crate::kappa::Kappa;
use crate::signed::SignedPayload;

/// Constrained authority transfer from one anchor to another.
///
/// Signed by the delegator via `COSE_Sign1`. The delegate cannot
/// modify the scope after creation. Narrowing invariant:
/// redelegation may only narrow scope, shorten TTL, and
/// decrement depth. Enforced at edge creation time.
///
/// CBOR key assignments (PERMANENT): 0-8
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DelegationScope {
    pub delegator: Kappa,
    pub delegate: Kappa,
    pub scope: Vec<String>,
    pub namespaces: Option<Vec<String>>,
    pub valid_from_ms: i64,
    pub valid_until_ms: Option<i64>,
    pub max_depth: u32,
    pub nonce: Vec<u8>,
    pub cose_signature: SignedPayload,
}

crate::wire_map::wire_map!(DelegationScope {
    delegator: value = 0,
    delegate: value = 1,
    scope: value = 2,
    namespaces: optional = 3,
    valid_from_ms: value = 4,
    valid_until_ms: optional = 5,
    max_depth: value = 6,
    nonce: bytes = 7,
    cose_signature: value = 8,
});

/// The unsigned portion of a `DelegationScope` for signing.
/// Keys 0-7 match the full struct. The signer signs the
/// canonical dCBOR of this struct.
#[derive(Clone)]
pub struct DelegationScopeSignable {
    pub delegator: Kappa,
    pub delegate: Kappa,
    pub scope: Vec<String>,
    pub namespaces: Option<Vec<String>>,
    pub valid_from_ms: i64,
    pub valid_until_ms: Option<i64>,
    pub max_depth: u32,
    pub nonce: Vec<u8>,
}

crate::wire_map::wire_map!(DelegationScopeSignable {
    delegator: value = 0,
    delegate: value = 1,
    scope: value = 2,
    namespaces: optional = 3,
    valid_from_ms: value = 4,
    valid_until_ms: optional = 5,
    max_depth: value = 6,
    nonce: bytes = 7,
});

impl DelegationScope {
    /// Canonical dCBOR bytes of the unsigned fields (keys 0-7).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let signable = DelegationScopeSignable {
            delegator: self.delegator.clone(),
            delegate: self.delegate.clone(),
            scope: self.scope.clone(),
            namespaces: self.namespaces.clone(),
            valid_from_ms: self.valid_from_ms,
            valid_until_ms: self.valid_until_ms,
            max_depth: self.max_depth,
            nonce: self.nonce.clone(),
        };
        crate::canonical::canonical_bytes(&signable)
    }

    /// Whether this delegation has expired relative to a given time.
    pub const fn is_expired(&self, now_ms: i64) -> bool {
        match self.valid_until_ms {
            Some(until) => now_ms >= until,
            None => false,
        }
    }

    /// Whether a given operation is permitted by this scope.
    pub fn permits_operation(&self, op: &str) -> bool {
        self.scope.iter().any(|s| s == "*" || s == op)
    }

    /// Whether a given namespace is covered by this scope.
    pub fn permits_namespace(&self, ns_name: &str) -> bool {
        self.namespaces
            .as_ref()
            .is_none_or(|nss| nss.iter().any(|n| ns_name.starts_with(n.as_str())))
    }
}

// ---------------------------------------------------------------------------
// Capability + CapabilitySet
// ---------------------------------------------------------------------------

/// Named operation capability for typed delegation.
///
/// Delegation grants carry a `CapabilitySet`. Each redelegation narrows
/// the set via intersection. An empty set is a revocation.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum Capability {
    Read,
    Write,
    Admin,
    Delegate { max_depth: u32 },
    Custom { name: String },
}

impl Capability {
    pub const fn as_str(&self) -> &str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Admin => "admin",
            Self::Delegate { .. } => "delegate",
            Self::Custom { name } => name.as_str(),
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => write!(f, "read"),
            Self::Write => write!(f, "write"),
            Self::Admin => write!(f, "admin"),
            Self::Delegate { max_depth } => write!(f, "delegate:{max_depth}"),
            Self::Custom { name } => write!(f, "custom:{name}"),
        }
    }
}

/// A set of capabilities with lattice operations.
///
/// Intersection narrows. Union widens. Subset checks containment.
/// An empty set represents revocation. `BTreeSet` ensures deterministic
/// iteration order for wire encoding.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CapabilitySet {
    inner: std::collections::BTreeSet<Capability>,
}

impl CapabilitySet {
    pub const fn new() -> Self {
        Self {
            inner: std::collections::BTreeSet::new(),
        }
    }

    pub fn insert(&mut self, cap: Capability) {
        self.inner.insert(cap);
    }

    pub fn contains(&self, cap: &Capability) -> bool {
        self.inner.contains(cap)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Intersection: capabilities present in both sets.
    /// Redelegation uses this to narrow the granted capabilities.
    #[must_use]
    pub fn intersection(&self, other: &Self) -> Self {
        Self {
            inner: self.inner.intersection(&other.inner).cloned().collect(),
        }
    }

    /// Union: capabilities present in either set.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        Self {
            inner: self.inner.union(&other.inner).cloned().collect(),
        }
    }

    /// Whether self is a subset of other.
    /// A redelegation is valid only if the granted set is a subset
    /// of the delegator's effective set.
    pub fn is_subset(&self, other: &Self) -> bool {
        self.inner.is_subset(&other.inner)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Capability> {
        self.inner.iter()
    }
}

impl Default for CapabilitySet {
    fn default() -> Self {
        Self::new()
    }
}

impl FromIterator<Capability> for CapabilitySet {
    fn from_iter<T: IntoIterator<Item = Capability>>(iter: T) -> Self {
        Self {
            inner: iter.into_iter().collect(),
        }
    }
}

/// Maximum delegation chain depth. A delegation with depth 0 cannot
/// redelegate. Each redelegation decrements the depth. A chain longer
/// than this is invalid.
pub const DELEGATION_CHAIN_MAX_DEPTH: u32 = 4;

// ---------------------------------------------------------------------------
// Delegation Chain Verification Result
// ---------------------------------------------------------------------------

/// A verified delegation chain from a root authority to a delegate.
///
/// Constructed by `verify_delegation_chain` in kappa-store's
/// `delegation_chain`.
/// Not a wire type. Runtime verification result.
#[derive(Debug, Clone)]
pub struct EffectiveAuthority {
    /// The final delegate at the end of the chain.
    pub delegate: Kappa,
    /// The effective capability set after intersection at each step.
    pub capabilities: CapabilitySet,
    /// The effective scope after narrowing at each step.
    pub scope: Vec<String>,
    /// The depth remaining for further redelegation.
    pub remaining_depth: u32,
    /// Number of links in the chain.
    pub chain_length: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delegation_nonce_has_identical_byte_string_encoding_in_signed_payload()
    -> Result<(), dcbor::Error> {
        let delegation = DelegationScope {
            delegator: test_kappa(b"a"),
            delegate: test_kappa(b"b"),
            scope: vec!["read".into()],
            namespaces: None,
            valid_from_ms: 1,
            valid_until_ms: None,
            max_depth: 1,
            nonce: vec![1, 2],
            cose_signature: SignedPayload::empty(),
        };
        for bytes in [
            crate::canonical::canonical_bytes(&delegation),
            delegation.signable_bytes(),
        ] {
            let dcbor::CBORCase::Map(map) = dcbor::CBOR::try_from_data(bytes)?.into_case() else {
                panic!("delegation must be a map");
            };
            let nonce: dcbor::CBOR = map.extract(7u64)?;
            assert_eq!(nonce.to_cbor_data(), [0x42, 1, 2]);
        }
        Ok(())
    }

    fn test_kappa(seed: &[u8]) -> Kappa {
        Kappa::sha256(seed)
    }

    #[test]
    fn expired_check() {
        let d = DelegationScope {
            delegator: test_kappa(b"a"),
            delegate: test_kappa(b"b"),
            scope: vec!["*".into()],
            namespaces: None,
            valid_from_ms: 0,
            valid_until_ms: Some(1000),
            max_depth: 1,
            nonce: vec![0; 16],
            cose_signature: SignedPayload::empty(),
        };
        assert!(!d.is_expired(999));
        assert!(d.is_expired(1000));
        assert!(d.is_expired(1001));
    }

    #[test]
    fn no_expiry_never_expired() {
        let d = DelegationScope {
            delegator: test_kappa(b"a"),
            delegate: test_kappa(b"b"),
            scope: vec![],
            namespaces: None,
            valid_from_ms: 0,
            valid_until_ms: None,
            max_depth: 0,
            nonce: vec![0; 16],
            cose_signature: SignedPayload::empty(),
        };
        assert!(!d.is_expired(i64::MAX));
    }

    #[test]
    fn permits_wildcard() {
        let d = DelegationScope {
            delegator: test_kappa(b"a"),
            delegate: test_kappa(b"b"),
            scope: vec!["*".into()],
            namespaces: None,
            valid_from_ms: 0,
            valid_until_ms: None,
            max_depth: 0,
            nonce: vec![],
            cose_signature: SignedPayload::empty(),
        };
        assert!(d.permits_operation("tag:write"));
        assert!(d.permits_operation("anything"));
    }

    #[test]
    fn permits_specific_op() {
        let d = DelegationScope {
            delegator: test_kappa(b"a"),
            delegate: test_kappa(b"b"),
            scope: vec!["tag:read".into(), "tag:write".into()],
            namespaces: None,
            valid_from_ms: 0,
            valid_until_ms: None,
            max_depth: 0,
            nonce: vec![],
            cose_signature: SignedPayload::empty(),
        };
        assert!(d.permits_operation("tag:read"));
        assert!(!d.permits_operation("edge:write"));
    }

    #[test]
    fn namespace_filter() {
        let d = DelegationScope {
            delegator: test_kappa(b"a"),
            delegate: test_kappa(b"b"),
            scope: vec!["*".into()],
            namespaces: Some(vec!["myorg/".into()]),
            valid_from_ms: 0,
            valid_until_ms: None,
            max_depth: 0,
            nonce: vec![],
            cose_signature: SignedPayload::empty(),
        };
        assert!(d.permits_namespace("myorg/repo1"));
        assert!(!d.permits_namespace("other/repo"));
    }

    #[test]
    fn null_namespaces_permits_all() {
        let d = DelegationScope {
            delegator: test_kappa(b"a"),
            delegate: test_kappa(b"b"),
            scope: vec![],
            namespaces: None,
            valid_from_ms: 0,
            valid_until_ms: None,
            max_depth: 0,
            nonce: vec![],
            cose_signature: SignedPayload::empty(),
        };
        assert!(d.permits_namespace("anything"));
    }

    // -- Capability + CapabilitySet tests --

    #[test]
    fn capability_display() {
        assert_eq!(Capability::Read.to_string(), "read");
        assert_eq!(Capability::Write.to_string(), "write");
        assert_eq!(Capability::Admin.to_string(), "admin");
        assert_eq!(
            Capability::Delegate { max_depth: 2 }.to_string(),
            "delegate:2"
        );
        assert_eq!(
            Capability::Custom {
                name: "tag:write".into()
            }
            .to_string(),
            "custom:tag:write"
        );
    }

    #[test]
    fn capability_set_intersection_narrows() {
        let a = CapabilitySet::from_iter([Capability::Read, Capability::Write, Capability::Admin]);
        let b = CapabilitySet::from_iter([Capability::Read, Capability::Write]);
        let c = a.intersection(&b);
        assert_eq!(c.len(), 2);
        assert!(c.contains(&Capability::Read));
        assert!(c.contains(&Capability::Write));
        assert!(!c.contains(&Capability::Admin));
    }

    #[test]
    fn capability_set_union_widens() {
        let a = CapabilitySet::from_iter([Capability::Read]);
        let b = CapabilitySet::from_iter([Capability::Write]);
        let c = a.union(&b);
        assert_eq!(c.len(), 2);
        assert!(c.contains(&Capability::Read));
        assert!(c.contains(&Capability::Write));
    }

    #[test]
    fn capability_set_subset() {
        let a = CapabilitySet::from_iter([Capability::Read]);
        let b = CapabilitySet::from_iter([Capability::Read, Capability::Write]);
        assert!(a.is_subset(&b));
        assert!(!b.is_subset(&a));
    }

    #[test]
    fn capability_set_empty_is_revocation() {
        let a = CapabilitySet::from_iter([Capability::Read]);
        let b = CapabilitySet::from_iter([Capability::Write]);
        let c = a.intersection(&b);
        assert!(c.is_empty());
    }

    #[test]
    fn capability_set_deterministic_order() {
        let a = CapabilitySet::from_iter([Capability::Write, Capability::Read, Capability::Admin]);
        let names: Vec<&str> = a.iter().map(Capability::as_str).collect();
        assert_eq!(names, &["read", "write", "admin"]);
    }
}
