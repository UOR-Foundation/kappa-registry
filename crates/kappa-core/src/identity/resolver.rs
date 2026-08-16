//! External identifier resolver trait.
//!
//! Maps external identifiers (email, GitHub handle, domain, DID) to
//! asserter anchors. Concrete implementations perform protocol-specific
//! verification (DNS TXT, email link, GitHub API, DID resolution).
//! The trait is object-safe for dynamic dispatch in handler layers.

/// Result of resolving an external identifier to an asserter anchor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedIdentity {
    /// The asserter anchor this identifier maps to.
    pub anchor: String,
    /// The public key bytes of the asserter.
    pub public_key: Vec<u8>,
    /// The signing algorithm ("ed25519", "p256", "k256").
    pub algorithm: String,
    /// Optional service endpoint URL.
    pub service_endpoint: Option<String>,
    /// The external handle/identifier as the resolver knows it.
    pub handle: String,
    /// Evidence of verification (proof blob, DNS record, etc).
    pub evidence: Option<Vec<u8>>,
}

/// Trait for resolving external identifiers to asserter anchors.
///
/// Implementations are protocol-specific: DNS, email, DID, GitHub, etc.
/// The resolver may cache results with a configurable TTL.
pub trait ExternalIdentifierResolver: Send + Sync {
    /// The identifier type this resolver handles ("email", "dns", "did", "github").
    fn id_type(&self) -> &str;

    /// Resolve an external identifier to an asserter anchor.
    /// Returns None if the identifier is not found or verification fails.
    fn resolve(&self, identifier: &str) -> Result<Option<ResolvedIdentity>, String>;

    /// Cache TTL in seconds. 0 = no caching.
    fn cache_ttl_secs(&self) -> u64 {
        300
    }
}
