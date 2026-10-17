pub mod fulcio;
pub mod nix;
pub mod plc;
pub mod webfinger;

use std::sync::Arc;

use kappa_handler::{ExternalIdentifierResolver, ResolverRegistry};

/// Build a ResolverRegistry with all configured resolvers.
///
/// One Arc'd registry. All resolvers added to the same instance.
/// WebFingerResolver holds an Arc clone of the same registry for
/// two-phase handle -> DID -> anchor resolution. No Weak refs,
/// no intermediate registries, no dangling pointers.
pub fn build_registry(
    dns: Arc<hickory_resolver::TokioResolver>,
    plc_directory_url: &str,
    rekor_url: &str,
    nix_ttl: u64,
    plc_ttl: u64,
    fulcio_ttl: u64,
    webfinger_ttl: u64,
) -> Arc<ResolverRegistry> {
    let registry = Arc::new(ResolverRegistry::new());

    match nix::NixKeyResolver::from_env(nix_ttl) {
        Ok(Some(r)) => {
            tracing::info!("registered Nix key resolver");
            registry.add(Arc::new(r) as Arc<dyn ExternalIdentifierResolver>);
        }
        Ok(None) => {
            tracing::debug!("no KAPPA_NIX_TRUSTED_KEYS configured");
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to parse KAPPA_NIX_TRUSTED_KEYS");
        }
    }

    match plc::PlcResolver::new(plc_directory_url, plc_ttl) {
        Ok(r) => {
            tracing::info!(url = plc_directory_url, "registered PLC resolver",);
            registry.add(Arc::new(r) as Arc<dyn ExternalIdentifierResolver>);
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to build PLC resolver HTTP client");
        }
    }

    match fulcio::FulcioResolver::new(rekor_url, fulcio_ttl) {
        Ok(r) => {
            tracing::info!(url = rekor_url, "registered Fulcio resolver",);
            registry.add(Arc::new(r) as Arc<dyn ExternalIdentifierResolver>);
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to build Fulcio resolver HTTP client");
        }
    }

    match webfinger::WebFingerResolver::new(Arc::clone(&registry), dns, webfinger_ttl) {
        Ok(wf) => {
            tracing::info!("registered WebFinger resolver");
            registry.add(Arc::new(wf) as Arc<dyn ExternalIdentifierResolver>);
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to build WebFinger resolver HTTP client");
        }
    }

    registry
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_registry_returns_non_empty() {
        let dns = Arc::new(
            hickory_resolver::TokioResolver::builder_tokio()
                .expect("dns")
                .build()
                .expect("dns resolver"),
        );
        let registry = build_registry(
            dns,
            "https://plc.directory",
            "https://rekor.sigstore.dev",
            300,
            3600,
            60,
            300,
        );
        // At minimum PLC + WebFinger should register (no Nix keys in test env)
        assert!(
            registry.len() >= 2,
            "expected at least PLC + WebFinger, got {}",
            registry.len()
        );
    }
}
