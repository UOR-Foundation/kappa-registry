//! What a committed rotation or a startup reconciliation promises beyond
//! the committed authority itself, and whether each promise holds.
//!
//! The four guarantees are reported separately because an operator acts
//! on them differently:
//!
//! - **custody**: the key store durably selects the committed key, so a
//!   restart signs with it.
//! - **key removal**: no retired or abandoned node private key remains in
//!   the key store.
//! - **authorization**: the current authority's identity, `_root`
//!   capability and root delegation are published, so the current
//!   authority and the root-token delegate are authorized.
//! - **revocation**: no retired authority's `_root` capability or issued
//!   delegation remains published, so nothing a retired key granted still
//!   authorizes.
//! - **activation**: every committed authority transition, with its
//!   witnesses, is published in the control namespace's epoch history.
//!
//! [`crate::node_authority::NodeAuthority`] records the latest outcome of
//! each, readiness requires all five, and every reconciliation retries the
//! incomplete ones.

use kappa_crypto::CryptoError;
use kappa_store::StoreError;

/// The outcome of each follow-up guarantee, with its cause on failure.
#[derive(Debug)]
pub struct FollowUp {
    pub custody: Result<(), CryptoError>,
    pub key_removal: Result<(), CryptoError>,
    pub authorization: Result<(), StoreError>,
    pub revocation: Result<(), StoreError>,
    pub activation: Result<(), StoreError>,
}

impl FollowUp {
    /// Which guarantees hold; the causes stay with `self` for the log.
    pub const fn completion(&self) -> Completion {
        Completion {
            custody: self.custody.is_ok(),
            key_removal: self.key_removal.is_ok(),
            authorization: self.authorization.is_ok(),
            revocation: self.revocation.is_ok(),
            activation: self.activation.is_ok(),
        }
    }

    /// Each failed guarantee by its stable name, with its full cause chain,
    /// for the server log.
    pub fn failures(&self) -> Vec<(&'static str, String)> {
        let mut failures = Vec::new();
        if let Err(error) = &self.custody {
            failures.push(("custody", chain(error)));
        }
        if let Err(error) = &self.key_removal {
            failures.push(("key_removal", chain(error)));
        }
        if let Err(error) = &self.authorization {
            failures.push(("authorization", chain(error)));
        }
        if let Err(error) = &self.revocation {
            failures.push(("revocation", chain(error)));
        }
        if let Err(error) = &self.activation {
            failures.push(("activation", chain(error)));
        }
        failures
    }
}

/// Whether each follow-up guarantee holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Completion {
    pub custody: bool,
    pub key_removal: bool,
    pub authorization: bool,
    pub revocation: bool,
    pub activation: bool,
}

impl Completion {
    /// Before any reconciliation has run: nothing is established.
    pub const NONE: Self = Self {
        custody: false,
        key_removal: false,
        authorization: false,
        revocation: false,
        activation: false,
    };

    pub const fn is_complete(self) -> bool {
        self.custody && self.key_removal && self.authorization && self.revocation && self.activation
    }
}

/// `error` and every source beneath it.
pub fn chain(error: &dyn std::error::Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}
