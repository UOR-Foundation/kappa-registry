//! The scope of an `AnchorOrigin` ledger mutation.
//!
//! `MutationOp::AnchorOrigin` names the identity an identity record is
//! about (an anchor, or the content identity of a watermark or succession
//! record); the mutation's `context` names which record of that identity
//! changed, so a projection of the ledger (the registry's cross-namespace
//! identity indexes) re-reads exactly that row and nothing else. The
//! context is part of the signed ledger: every backend records the same
//! encoding, and a ledger carrying an unknown context is refused rather
//! than projected around.

use kappa_types::error::StoreError;

/// Which identity record an `AnchorOrigin` mutation changed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorScope {
    /// The bindings of `source` in the publishing namespace; the mutation's
    /// kappa is the bound target.
    Binding { source: String },
    /// The handle record under `key` (`{protocol}:{handle}`); the kappa is
    /// the handle's anchor.
    Handle { key: String },
    /// The device bindings of the anchor the kappa names.
    Device,
    /// The prekey bindings of the anchor the kappa names.
    Prekey,
    /// The locator record of the anchor the kappa names.
    Locator,
    /// The revocation commitment of the anchor the kappa names.
    Commitment,
    /// The watermark whose content identity the kappa names.
    Watermark,
    /// The succession record whose content identity the kappa names.
    Succession,
    /// The session under the identifier `id` (`session_id` of its access
    /// token, never the token itself: the ledger is evidence of the
    /// transition, not a copy of the bearer capability); the kappa is the
    /// content identity of the published
    /// `kappa_types::authorization::SessionTransition`, which binds the
    /// epoch to exactly that transition (set or deleted, deadline,
    /// metadata digest). `id` is exactly 64 lowercase hex characters;
    /// `parse` refuses anything else.
    Session { id: String },
    /// The credential under `id`; the kappa is the content identity of the
    /// published `CredentialTransition` (secret commitment, grace, or
    /// deletion). `id` is non-empty.
    Credential { id: String },
    /// The node's trust position; the kappa is the content identity of
    /// the position record.
    Trust,
}

const BINDING: &str = "binding:";
const HANDLE: &str = "handle:";
const SESSION: &str = "session:";
const CREDENTIAL: &str = "credential:";
const DEVICE: &str = "device";
const PREKEY: &str = "prekey";
const LOCATOR: &str = "locator";
const COMMITMENT: &str = "commitment";
const WATERMARK: &str = "watermark";
const SUCCESSION: &str = "succession";
const TRUST: &str = "trust";
const SESSION_ID_DOMAIN: &str = "kappa session identifier v1";

/// The identifier a session is recorded under: a domain-separated BLAKE3
/// derivation of the access token, with no application secret.
///
/// Anyone holding a candidate token can derive its identifier, so the
/// identifier hides the token only as far as the token's own entropy
/// does; what it establishes is that the ledger, the indexes and the error
/// paths carry the identifier and never the bearer capability. Every
/// backend keys its session rows by this, so a lookup by token derives
/// the key.
#[must_use]
pub fn session_id(token: &str) -> String {
    hex::encode(blake3::derive_key(SESSION_ID_DOMAIN, token.as_bytes()))
}

/// Whether `id` has the exact form `session_id` produces.
fn is_session_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

impl AnchorScope {
    /// The ledger context string.
    #[must_use]
    pub fn to_context(&self) -> String {
        match self {
            Self::Binding { source } => format!("{BINDING}{source}"),
            Self::Handle { key } => format!("{HANDLE}{key}"),
            Self::Device => DEVICE.to_string(),
            Self::Prekey => PREKEY.to_string(),
            Self::Locator => LOCATOR.to_string(),
            Self::Commitment => COMMITMENT.to_string(),
            Self::Watermark => WATERMARK.to_string(),
            Self::Succession => SUCCESSION.to_string(),
            Self::Session { id } => format!("{SESSION}{id}"),
            Self::Credential { id } => format!("{CREDENTIAL}{id}"),
            Self::Trust => TRUST.to_string(),
        }
    }

    /// Decode a ledger context; an absent or unknown context is refused.
    pub fn parse(context: Option<&str>) -> Result<Self, StoreError> {
        let Some(context) = context else {
            return Err(StoreError::Rejected(
                "anchor origin mutation carries no scope".into(),
            ));
        };
        if let Some(source) = context.strip_prefix(BINDING) {
            return Ok(Self::Binding {
                source: source.to_string(),
            });
        }
        if let Some(key) = context.strip_prefix(HANDLE) {
            return Ok(Self::Handle {
                key: key.to_string(),
            });
        }
        if let Some(id) = context.strip_prefix(SESSION) {
            if !is_session_id(id) {
                return Err(StoreError::Rejected(
                    "anchor origin session scope is not a derived session identifier".into(),
                ));
            }
            return Ok(Self::Session { id: id.to_string() });
        }
        if let Some(id) = context.strip_prefix(CREDENTIAL) {
            if id.is_empty() {
                return Err(StoreError::Rejected(
                    "anchor origin credential scope names no credential".into(),
                ));
            }
            return Ok(Self::Credential { id: id.to_string() });
        }
        match context {
            DEVICE => Ok(Self::Device),
            PREKEY => Ok(Self::Prekey),
            LOCATOR => Ok(Self::Locator),
            COMMITMENT => Ok(Self::Commitment),
            WATERMARK => Ok(Self::Watermark),
            SUCCESSION => Ok(Self::Succession),
            TRUST => Ok(Self::Trust),
            other => Err(StoreError::Rejected(format!(
                "anchor origin mutation carries unknown scope {other:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_scope_roundtrips_and_unknown_is_refused() -> Result<(), StoreError> {
        let scopes = [
            AnchorScope::Binding {
                source: "did:web:example".into(),
            },
            AnchorScope::Handle {
                key: "atproto:alice".into(),
            },
            AnchorScope::Device,
            AnchorScope::Prekey,
            AnchorScope::Locator,
            AnchorScope::Commitment,
            AnchorScope::Watermark,
            AnchorScope::Succession,
            AnchorScope::Session {
                id: session_id("tok:en"),
            },
            AnchorScope::Credential {
                id: "KAPPA0123".into(),
            },
            AnchorScope::Trust,
        ];
        for scope in scopes {
            assert_eq!(AnchorScope::parse(Some(&scope.to_context()))?, scope);
        }
        assert!(AnchorScope::parse(None).is_err());
        assert!(AnchorScope::parse(Some("tag:x")).is_err());
        assert!(AnchorScope::parse(Some("session:raw-token")).is_err());
        assert!(AnchorScope::parse(Some("session:")).is_err());
        assert!(AnchorScope::parse(Some("credential:")).is_err());
        Ok(())
    }

    #[test]
    fn session_identifier_never_carries_the_token() {
        let id = session_id("secret-bearer-token");
        assert_eq!(id.len(), 64);
        assert!(!id.contains("secret"));
        assert_ne!(id, session_id("secret-bearer-token2"));
        assert_eq!(id, session_id("secret-bearer-token"));
    }
}
