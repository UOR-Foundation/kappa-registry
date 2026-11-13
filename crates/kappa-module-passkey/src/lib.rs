//! Passkey and recovery key records for prism/identity/2, and the Prism
//! mailbox for prism/identity/3.
//!
//! A Prism account is a set of keys: passkeys on devices, and recovery keys
//! the owner keeps outside them. This module stores the public halves,
//! content addressed, after checking the WebAuthn ceremony that made it, and
//! serves it to anyone. It cannot forge an account: every reader checks the
//! key ID against the key and every signature for itself.
//!
//! Endpoints:
//!   POST /passkey/challenge                 - issue a single-use challenge
//!   POST /passkey/register                  - register a passkey (new account or bound device)
//!   POST /passkey/recovery                  - add a recovery key to an account
//!   GET  /passkey/credential/{credential}   - the key record for a credential
//!   GET  /passkey/account/{account}         - every key record of an account
//!   POST /passkey/revoke                    - revoke a key on a signed request
//!   POST /prism/topic/{topic}               - keep an opaque message under a topic
//!   GET  /prism/topic/{topic}               - the newest messages of a topic
//!
//! prism/identity/3 (stitch's Prism id) keeps no record here: its devices
//! use only the mailbox (see `mailbox`).
//! The contract is identity/PROTOCOL.md in UOR-Foundation/template.

pub mod config;
pub mod error;
pub mod mailbox;
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
/// and the resolved namespaces.
pub struct PasskeyState {
    pub config: PasskeyConfig,
    pub challenges: service::Challenges,
    pub namespace: NamespaceRef,
    /// The Prism mailbox's indexes (`mailbox::MAILBOX_NAMESPACE`).
    pub mailbox: NamespaceRef,
}

impl PasskeyState {
    /// Resolve (creating on first start) the passkey and mailbox namespaces, owned by
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
        let mailbox = store.namespace_resolve_or_create(mailbox::MAILBOX_NAMESPACE, owner, None)?;
        Ok(Self {
            config,
            challenges: service::Challenges::default(),
            namespace,
            mailbox,
        })
    }
}
