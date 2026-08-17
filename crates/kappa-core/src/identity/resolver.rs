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
///
/// `accepts` gates dispatch: the registry calls `resolve` only on the
/// first resolver whose `accepts` returns true. Resolvers that cannot
/// handle an identifier format return false from `accepts` and are
/// never called.
///
/// `resolve` is async because resolvers make network calls (HTTP to
/// PLC directory, WebFinger, Rekor). Sync resolvers (NixKeyResolver)
/// return immediately from the async fn at zero cost.
#[async_trait::async_trait]
pub trait ExternalIdentifierResolver: Send + Sync {
    /// The identifier type this resolver handles ("nix-key", "did:plc", "webfinger", "fulcio").
    fn id_type(&self) -> &str;

    /// Whether this resolver handles the given identifier format.
    /// Called before `resolve` -- if false, the registry skips this resolver.
    fn accepts(&self, identifier: &str) -> bool;

    /// Resolve an external identifier to an asserter anchor.
    /// Returns None if the identifier is not found or verification fails.
    async fn resolve(&self, identifier: &str) -> Result<Option<ResolvedIdentity>, String>;

    /// Cache TTL in seconds. 0 = no caching.
    fn cache_ttl_secs(&self) -> u64 {
        300
    }
}

/// Registry of identity resolvers with format-based dispatch.
///
/// Registration order matters: most specific resolver first.
/// The first resolver whose `accepts` returns true handles the identifier.
/// No iteration through all resolvers -- one dispatch per resolution.
pub struct ResolverRegistry {
    resolvers: Vec<std::sync::Arc<dyn ExternalIdentifierResolver>>,
}

impl ResolverRegistry {
    pub fn new() -> Self {
        Self {
            resolvers: Vec::new(),
        }
    }

    pub fn add(&mut self, resolver: std::sync::Arc<dyn ExternalIdentifierResolver>) {
        self.resolvers.push(resolver);
    }

    /// Resolve an identifier by dispatching to the first resolver that accepts it.
    pub async fn resolve(&self, identifier: &str) -> Result<Option<ResolvedIdentity>, String> {
        match self.resolvers.iter().find(|r| r.accepts(identifier)) {
            Some(r) => r.resolve(identifier).await,
            None => Ok(None),
        }
    }

    /// The number of registered resolvers.
    pub fn len(&self) -> usize {
        self.resolvers.len()
    }

    /// Whether the registry has no resolvers.
    pub fn is_empty(&self) -> bool {
        self.resolvers.is_empty()
    }
}

impl Default for ResolverRegistry {
    fn default() -> Self {
        Self::new()
    }
}
