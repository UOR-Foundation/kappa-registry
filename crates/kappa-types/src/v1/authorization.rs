//! Evidence of authorization transitions: the records a publication
//! commits when a session or a credential is created, replaced, rotated
//! or deleted.
//!
//! A session or credential row is mutable, so a ledger entry naming the
//! row alone does not establish what the epoch admitted: the row may have
//! changed, or gone, by the time the ledger is projected. Each transition
//! therefore publishes one of these records as content; the ledger names
//! the record's content identity, which binds the epoch to exactly that
//! transition. The records carry no secret: a session is named by its
//! derived identifier and its metadata by digest, a credential's secret
//! hash and grace secret by their digests (`Kappa::sha256`).

use dcbor::prelude::*;

use crate::kappa::Kappa;

/// Whether the transition set the row or deleted it.
/// CBOR discriminants (PERMANENT): 0-1
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
#[non_exhaustive]
pub enum TransitionKind {
    #[cbor(n = 0)]
    Set,
    #[cbor(n = 1)]
    Deleted,
}

/// One session transition.
/// CBOR key assignments (PERMANENT): 0-4
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct SessionTransition {
    /// The session's derived identifier (never the token).
    #[cbor(n = 0)]
    pub id: String,
    #[cbor(n = 1)]
    pub kind: TransitionKind,
    #[cbor(n = 2)]
    pub anchor: Kappa,
    /// Encoded `ClockMs` deadline; 0 for a deletion.
    #[cbor(n = 3)]
    pub expires_at_ms: i64,
    /// `Kappa::sha256` of the session metadata; of nothing for a deletion.
    #[cbor(n = 4)]
    pub metadata_digest: Kappa,
}

/// One credential transition.
/// CBOR key assignments (PERMANENT): 0-5
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct CredentialTransition {
    #[cbor(n = 0)]
    pub id: String,
    #[cbor(n = 1)]
    pub kind: TransitionKind,
    #[cbor(n = 2)]
    pub anchor: Kappa,
    /// `Kappa::sha256` of the current secret hash; of nothing for a
    /// deletion.
    #[cbor(n = 3)]
    pub secret_commitment: Kappa,
    /// `Kappa::sha256` of the grace secret hash, while a rotation grace is
    /// in force.
    #[cbor(n = 4)]
    pub grace_commitment: Option<Kappa>,
    /// Encoded `ClockMs` deadline of the grace, while in force.
    #[cbor(n = 5)]
    pub grace_expires_ms: Option<i64>,
}

impl SessionTransition {
    pub fn set(id: String, anchor: Kappa, expires_at_ms: i64, metadata: &[u8]) -> Self {
        Self {
            id,
            kind: TransitionKind::Set,
            anchor,
            expires_at_ms,
            metadata_digest: Kappa::sha256(metadata),
        }
    }

    pub fn deleted(id: String, anchor: Kappa) -> Self {
        Self {
            id,
            kind: TransitionKind::Deleted,
            anchor,
            expires_at_ms: 0,
            metadata_digest: Kappa::sha256(&[]),
        }
    }
}

impl CredentialTransition {
    pub fn set(id: String, anchor: Kappa, secret_hash: &[u8], grace: Option<(&[u8], i64)>) -> Self {
        Self {
            id,
            kind: TransitionKind::Set,
            anchor,
            secret_commitment: Kappa::sha256(secret_hash),
            grace_commitment: grace.map(|(old, _)| Kappa::sha256(old)),
            grace_expires_ms: grace.map(|(_, expires)| expires),
        }
    }

    pub fn deleted(id: String, anchor: Kappa) -> Self {
        Self {
            id,
            kind: TransitionKind::Deleted,
            anchor,
            secret_commitment: Kappa::sha256(&[]),
            grace_commitment: None,
            grace_expires_ms: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_roundtrip_and_carry_no_secret() -> Result<(), dcbor::Error> {
        let session = SessionTransition::set("id".into(), Kappa::sha256(b"a"), 5, b"meta");
        let bytes = crate::canonical::canonical_bytes(&session);
        assert_eq!(
            SessionTransition::try_from(CBOR::try_from_data(&bytes)?)?,
            session
        );
        let credential = CredentialTransition::set(
            "cred".into(),
            Kappa::sha256(b"a"),
            b"secret-hash",
            Some((b"old-hash", 9)),
        );
        let bytes = crate::canonical::canonical_bytes(&credential);
        assert_eq!(
            CredentialTransition::try_from(CBOR::try_from_data(&bytes)?)?,
            credential
        );
        assert!(!bytes.windows(11).any(|window| window == b"secret-hash"));
        assert!(!bytes.windows(8).any(|window| window == b"old-hash"));
        Ok(())
    }
}
