//! Identity bindings: tie protocol-specific identifiers to asserter anchors.
//!
//! A binding declares "this asserter owns this namespace/identifier."
//! Stored as tagged assertions with facet "identity/binding". The binding
//! carries the external identifier, verification method, and trust level.
//! Bindings participate in epoch advancement and the assertion inbound index.

use dcbor::prelude::*;

/// An identity binding ties an external identifier to an asserter anchor.
///
/// CBOR key assignments (PERMANENT):
///   0: source (the external identifier -- email, domain, namespace)
///   1: target (the asserter anchor this identifier is bound to)
///   2: method (how ownership was verified)
///   3: trust_level (0=unverified, 1=self-asserted, 2=peer-verified, 3=threshold-attested)
///   4: verified_at_ms (when the verification was performed)
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct IdentityBinding {
    #[cbor(n = 0)]
    pub source: String,
    #[cbor(n = 1)]
    pub target: String,
    #[cbor(n = 2)]
    pub method: String,
    #[cbor(n = 3)]
    pub trust_level: u64,
    #[cbor(n = 4)]
    pub verified_at_ms: u64,
}
