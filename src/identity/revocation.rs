//! Revocation -- monotone grow-only set, irreversible, no clock.
//!
//! A revocation is a signed negative assertion. It is stored alongside
//! the original assertion in the asserter's namespace. Nothing is deleted.
//! Readers check for revocation assertions at read time.
//!
//! Revocation is irreversible: a revocation issued in error is answered
//! with a fresh assertion carrying a new nonce, not retraction.
//!
//! Reason codes partition who may author which revocation, following
//! X.509's model where privilegeWithdrawn is reserved to the CA.

use serde::{Deserialize, Serialize};

use crate::kappa::KappaLabel;

/// A signed revocation of a prior assertion.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Revocation {
    /// Who revokes (anchor kappa -- must be authorized per reason code).
    pub revoker: String,
    /// What is revoked (kappa of the target assertion).
    pub target: String,
    /// Why (partitions who may author this revocation).
    pub reason: RevocationReason,
    /// Revoker's epoch at time of revocation.
    pub epoch: u64,
    /// Revoker's signature over canonical form.
    pub signature: Vec<u8>,
}

/// Reason codes for revocation, partitioning authorship authority.
///
/// Superseded: asserter only.
/// KeyCompromise: asserter or subject.
/// PrivilegeWithdrawn: upstream delegator only.
/// Erroneous: asserter only.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RevocationReason {
    Superseded,
    KeyCompromise,
    PrivilegeWithdrawn,
    Erroneous,
}

impl Revocation {
    /// Canonical bytes for signing/verification (excludes signature).
    ///
    /// Fields are concatenated in a fixed order with length prefixes.
    /// This format MUST be frozen before any revocation is created
    /// in production.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let reason_tag: u8 = match self.reason {
            RevocationReason::Superseded => 0x01,
            RevocationReason::KeyCompromise => 0x02,
            RevocationReason::PrivilegeWithdrawn => 0x03,
            RevocationReason::Erroneous => 0x04,
        };
        let mut buf = Vec::with_capacity(2 + self.revoker.len() + 2 + self.target.len() + 1 + 8);
        buf.extend_from_slice(&(self.revoker.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.revoker.as_bytes());
        buf.extend_from_slice(&(self.target.len() as u16).to_be_bytes());
        buf.extend_from_slice(self.target.as_bytes());
        buf.push(reason_tag);
        buf.extend_from_slice(&self.epoch.to_be_bytes());
        buf
    }

    /// Compute the kappa-label for this revocation.
    pub fn kappa(&self) -> String {
        let mut buf = self.canonical_bytes();
        buf.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        buf.extend_from_slice(&self.signature);
        KappaLabel::sha256(&buf).as_str().to_owned()
    }

    /// Check whether a given revoker is authorized for the given reason
    /// relative to the target assertion's asserter and subject.
    pub fn is_authorized(
        reason: RevocationReason,
        revoker: &str,
        asserter: &str,
        subject: &str,
        delegators: &[&str],
    ) -> bool {
        match reason {
            RevocationReason::Superseded => revoker == asserter,
            RevocationReason::KeyCompromise => revoker == asserter || revoker == subject,
            RevocationReason::PrivilegeWithdrawn => delegators.contains(&revoker),
            RevocationReason::Erroneous => revoker == asserter,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_revocation() -> Revocation {
        Revocation {
            revoker: "sha256:revoker".to_owned(),
            target: "sha256:target_assertion".to_owned(),
            reason: RevocationReason::Superseded,
            epoch: 5,
            signature: vec![0u8; 64],
        }
    }

    #[test]
    fn canonical_bytes_deterministic() {
        let r = test_revocation();
        assert_eq!(r.canonical_bytes(), r.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_excludes_signature() {
        let mut r = test_revocation();
        let b1 = r.canonical_bytes();
        r.signature = vec![0xFF; 64];
        assert_eq!(b1, r.canonical_bytes());
    }

    #[test]
    fn kappa_deterministic() {
        let r = test_revocation();
        assert_eq!(r.kappa(), r.kappa());
        assert!(r.kappa().starts_with("sha256:"));
    }

    #[test]
    fn superseded_only_by_asserter() {
        assert!(Revocation::is_authorized(
            RevocationReason::Superseded,
            "alice",
            "alice",
            "bob",
            &[]
        ));
        assert!(!Revocation::is_authorized(
            RevocationReason::Superseded,
            "charlie",
            "alice",
            "bob",
            &[]
        ));
    }

    #[test]
    fn key_compromise_by_asserter_or_subject() {
        assert!(Revocation::is_authorized(
            RevocationReason::KeyCompromise,
            "alice",
            "alice",
            "bob",
            &[]
        ));
        assert!(Revocation::is_authorized(
            RevocationReason::KeyCompromise,
            "bob",
            "alice",
            "bob",
            &[]
        ));
        assert!(!Revocation::is_authorized(
            RevocationReason::KeyCompromise,
            "charlie",
            "alice",
            "bob",
            &[]
        ));
    }

    #[test]
    fn privilege_withdrawn_by_delegator() {
        assert!(Revocation::is_authorized(
            RevocationReason::PrivilegeWithdrawn,
            "authority",
            "alice",
            "bob",
            &["authority"]
        ));
        assert!(!Revocation::is_authorized(
            RevocationReason::PrivilegeWithdrawn,
            "alice",
            "alice",
            "bob",
            &["authority"]
        ));
    }

    #[test]
    fn erroneous_only_by_asserter() {
        assert!(Revocation::is_authorized(
            RevocationReason::Erroneous,
            "alice",
            "alice",
            "bob",
            &[]
        ));
        assert!(!Revocation::is_authorized(
            RevocationReason::Erroneous,
            "bob",
            "alice",
            "bob",
            &[]
        ));
    }
}
