use std::sync::{Arc, RwLock};

use kappa_store::kappa::Kappa;

/// Result of resolving an external identifier to an asserter anchor.
#[derive(Debug, Clone)]
pub struct ResolvedIdentity {
    pub anchor: Kappa,
    pub public_key: Vec<u8>,
    pub algorithm: String,
    pub service_endpoint: Option<String>,
    pub handle: Option<String>,
    pub evidence: Option<Vec<u8>>,
}

/// Errors from identity resolution.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResolveError {
    #[error("network: {resolver}: {reason}")]
    Network { resolver: String, reason: String },

    #[error("parse: {resolver}: {reason}")]
    Parse { resolver: String, reason: String },

    #[error("invalid key: {resolver}: {reason}")]
    InvalidKey { resolver: String, reason: String },

    #[error("timeout: {resolver}: {reason}")]
    Timeout { resolver: String, reason: String },

    #[error("internal: {resolver}: {reason}")]
    Internal { resolver: String, reason: String },
}

/// Resolver trait for mapping external identifiers to asserter anchors.
///
/// Implementations are protocol-specific (DNS, email, DID, GitHub).
/// `accepts` gates dispatch. `resolve` is async for network resolvers.
#[async_trait::async_trait]
pub trait ExternalIdentifierResolver: Send + Sync {
    fn id_type(&self) -> &str;
    fn accepts(&self, identifier: &str) -> bool;
    async fn resolve(&self, identifier: &str) -> Result<Option<ResolvedIdentity>, ResolveError>;
    fn cache_ttl_secs(&self) -> u64 {
        300
    }
}

/// Registry of identity resolvers with format-based dispatch.
///
/// Interior mutability via `RwLock` so resolvers can be added to an
/// Arc'd registry after construction. Solves the circular reference:
/// `WebFingerResolver` holds an Arc to the registry it is registered in.
pub struct ResolverRegistry {
    resolvers: RwLock<Vec<Arc<dyn ExternalIdentifierResolver>>>,
}

impl ResolverRegistry {
    pub fn new() -> Self {
        Self {
            resolvers: RwLock::new(Vec::new()),
        }
    }

    /// Add a resolver. Takes &self so resolvers can be added to an
    /// Arc'd registry.
    pub fn add(&self, resolver: Arc<dyn ExternalIdentifierResolver>) {
        self.resolvers
            .write()
            // The only write is Vec::push; unwinding preserves a valid vector.
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(resolver);
    }

    /// Resolve an identifier by dispatching to the first resolver
    /// whose `accepts` returns true.
    pub async fn resolve(
        &self,
        identifier: &str,
    ) -> Result<Option<ResolvedIdentity>, ResolveError> {
        let candidates = {
            let resolvers = self
                .resolvers
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            resolvers.clone()
        };
        let resolver = candidates.into_iter().find(|r| r.accepts(identifier));
        match resolver {
            Some(r) => r.resolve(identifier).await,
            None => Ok(None),
        }
    }

    pub fn len(&self) -> usize {
        self.resolvers
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for ResolverRegistry {
    fn default() -> Self {
        Self::new()
    }
}
