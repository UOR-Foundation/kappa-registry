//! Revocations: grow-only set of voided assertions.
//!
//! CBOR key assignments (PERMANENT):
//!   0: asserter (text)
//!   1: assertion_kappa (text, the kappa-label of the revoked assertion)
//!   2: reason (RevocationReason enum)
//!   3: revoked_at_ms (unsigned)
//!   4: signature (bytes)

use dcbor::prelude::*;

#[derive(Debug, Clone, CBORCodable)]
pub struct Revocation {
    #[cbor(n = 0)]
    pub asserter: String,
    #[cbor(n = 1)]
    pub assertion_kappa: String,
    #[cbor(n = 2)]
    pub reason: RevocationReason,
    #[cbor(n = 3)]
    pub revoked_at_ms: u64,
    #[cbor(n = 4)]
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
pub enum RevocationReason {
    #[cbor(n = 0)]
    KeyCompromise,
    #[cbor(n = 1)]
    Superseded,
    #[cbor(n = 2)]
    Erroneous,
    #[cbor(n = 3)]
    PrivilegeWithdrawn,
    #[cbor(n = 4)]
    CessationOfOperation,
}

impl RevocationReason {
    pub fn as_str(&self) -> &'static str {
        match self {
            RevocationReason::KeyCompromise => "key-compromise",
            RevocationReason::Superseded => "superseded",
            RevocationReason::Erroneous => "erroneous",
            RevocationReason::PrivilegeWithdrawn => "privilege-withdrawn",
            RevocationReason::CessationOfOperation => "cessation-of-operation",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    #[test]
    fn revocation_roundtrip() {
        let r = Revocation {
            asserter: "anchor-1".into(),
            assertion_kappa: "sha256:abc".into(),
            reason: RevocationReason::KeyCompromise,
            revoked_at_ms: 5000,
            signature: vec![9, 8, 7],
        };
        let bytes = canonical_bytes(&r);
        let decoded: Revocation = from_canonical(&bytes).unwrap();
        assert_eq!(decoded.asserter, r.asserter);
        assert_eq!(decoded.assertion_kappa, r.assertion_kappa);
        assert_eq!(decoded.reason, r.reason);
    }

    #[test]
    fn reason_roundtrip() {
        for reason in [
            RevocationReason::KeyCompromise,
            RevocationReason::Superseded,
            RevocationReason::Erroneous,
            RevocationReason::PrivilegeWithdrawn,
            RevocationReason::CessationOfOperation,
        ] {
            let bytes = canonical_bytes(&reason);
            let decoded: RevocationReason = from_canonical(&bytes).unwrap();
            assert_eq!(decoded, reason);
        }
    }

    #[test]
    fn reason_as_str() {
        assert_eq!(RevocationReason::KeyCompromise.as_str(), "key-compromise");
        assert_eq!(RevocationReason::Superseded.as_str(), "superseded");
    }
}
