//! Passkey key records for prism/identity/1.
//!
//! A Prism account is a passkey. This module stores the public half,
//! content addressed, after checking the WebAuthn ceremony that made it, and
//! serves it to anyone. It cannot forge an account: every reader checks the
//! key ID against the key and every signature for itself.
//!
//! Endpoints:
//!   POST /passkey/challenge                 - issue a single-use challenge
//!   POST /passkey/register                  - register a passkey (new account or bound device)
//!   GET  /passkey/credential/{credential}   - the key record for a credential
//!   GET  /passkey/account/{account}         - every key record of an account
//!   POST /passkey/revoke                    - revoke a key on a signed request
//!
//! The contract is identity/PROTOCOL.md in UOR-Foundation/template.

pub mod config;
pub mod error;
pub mod records;
mod routes;
pub mod service;
pub mod webauthn;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
mod tests;

use kappa_core::store::KappaStore;
use kappa_core::types::NamespaceRef;

pub use config::{IdentityOrigin, PasskeyConfig};
pub use error::PasskeyError;
pub use routes::{register, PATHS};

/// The namespace holding key records. Under the reserved `kappa/identity`
/// prefix, so only these routes, not the generic `/v2/` API, write it.
pub const PASSKEY_NAMESPACE: &str = "kappa/identity/passkey";

/// Everything the routes share: accepted origins, outstanding challenges
/// and the resolved namespace.
pub struct PasskeyState {
    pub config: PasskeyConfig,
    pub challenges: service::Challenges,
    pub namespace: NamespaceRef,
}

impl PasskeyState {
    /// Resolve (creating on first start) the passkey namespace, owned by
    /// `owner`, the node's anchor. The owner must not be "anonymous": with
    /// bearer auth off every caller is "anonymous", and an owner match would
    /// open the namespace to the generic routes.
    pub fn new(
        config: PasskeyConfig,
        store: &dyn KappaStore,
        owner: &str,
    ) -> Result<Self, PasskeyError> {
        if owner == "anonymous" {
            return Err(PasskeyError::Request(
                "the passkey namespace needs a node anchor as its owner".into(),
            ));
        }
        let namespace = store.namespace_resolve_or_create(PASSKEY_NAMESPACE, owner, None)?;
        Ok(Self {
            config,
            challenges: service::Challenges::default(),
            namespace,
        })
    }
}
