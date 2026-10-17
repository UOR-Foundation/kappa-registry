use kappa_store::namespace::{NamespaceRef, ProtocolId};

/// Namespace resolution result stored in request context by the
/// interceptor layer before handlers run.
#[derive(Debug, Clone)]
pub enum ResolvedNamespace {
    Exists(NamespaceRef),
    NotFound {
        name: String,
        protocol: Option<ProtocolId>,
    },
    NoNamespace,
}
