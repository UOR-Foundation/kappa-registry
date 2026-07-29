//! Identity assertions: signed claims by an asserter about a subject.
//!
//! CBOR key assignments (PERMANENT):
//!   0: asserter (text, anchor of the claiming identity)
//!   1: subject (text, anchor or identifier of the subject)
//!   2: facet (text, what aspect this claim addresses)
//!   3: value (bytes, the claim content)
//!   4: basis (text, how the asserter knows this -- "self-asserted",
//!      "peer-verified", "threshold-attested")
//!   5: valid_from_ms (unsigned, milliseconds since Unix epoch)
//!   6: valid_until_ms (optional unsigned, expiration)
//!   7: signature (bytes, asserter's signature over fields 0-6)

use dcbor::prelude::*;

#[derive(Debug, Clone, CBORCodable)]
pub struct IdentityAssertion {
    #[cbor(n = 0)]
    pub asserter: String,
    #[cbor(n = 1)]
    pub subject: String,
    #[cbor(n = 2)]
    pub facet: String,
    #[cbor(n = 3)]
    pub value: Vec<u8>,
    #[cbor(n = 4)]
    pub basis: String,
    #[cbor(n = 5)]
    pub valid_from_ms: u64,
    #[cbor(n = 6)]
    pub valid_until_ms: Option<u64>,
    #[cbor(n = 7)]
    pub signature: Vec<u8>,
}

impl IdentityAssertion {
    /// The canonical bytes that are signed (fields 0-6, no signature).
    ///
    /// The signature field is excluded from the signed content to avoid
    /// circular dependency. The signer computes canonical_bytes of a
    /// SignableAssertion, signs that, then attaches the signature.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let signable = SignableAssertion {
            asserter: self.asserter.clone(),
            subject: self.subject.clone(),
            facet: self.facet.clone(),
            value: self.value.clone(),
            basis: self.basis.clone(),
            valid_from_ms: self.valid_from_ms,
            valid_until_ms: self.valid_until_ms,
        };
        crate::canonical::canonical_bytes(&signable)
    }
}

/// The subset of assertion fields that are signed.
#[derive(Clone, CBORCodable)]
struct SignableAssertion {
    #[cbor(n = 0)]
    asserter: String,
    #[cbor(n = 1)]
    subject: String,
    #[cbor(n = 2)]
    facet: String,
    #[cbor(n = 3)]
    value: Vec<u8>,
    #[cbor(n = 4)]
    basis: String,
    #[cbor(n = 5)]
    valid_from_ms: u64,
    #[cbor(n = 6)]
    valid_until_ms: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    #[test]
    fn assertion_roundtrip() {
        let a = IdentityAssertion {
            asserter: "anchor-1".into(),
            subject: "anchor-2".into(),
            facet: "node/version".into(),
            value: b"1.0.0".to_vec(),
            basis: "self-asserted".into(),
            valid_from_ms: 1000,
            valid_until_ms: None,
            signature: vec![1, 2, 3],
        };
        let bytes = canonical_bytes(&a);
        let decoded: IdentityAssertion = from_canonical(&bytes).unwrap();
        assert_eq!(decoded.asserter, a.asserter);
        assert_eq!(decoded.facet, a.facet);
        assert_eq!(decoded.value, a.value);
        assert_eq!(decoded.signature, a.signature);
    }

    #[test]
    fn signable_bytes_exclude_signature() {
        let a1 = IdentityAssertion {
            asserter: "a".into(),
            subject: "s".into(),
            facet: "f".into(),
            value: vec![],
            basis: "self-asserted".into(),
            valid_from_ms: 0,
            valid_until_ms: None,
            signature: vec![1, 2, 3],
        };
        let a2 = IdentityAssertion {
            asserter: "a".into(),
            subject: "s".into(),
            facet: "f".into(),
            value: vec![],
            basis: "self-asserted".into(),
            valid_from_ms: 0,
            valid_until_ms: None,
            signature: vec![99, 99, 99],
        };
        assert_eq!(a1.signable_bytes(), a2.signable_bytes());
    }

    #[test]
    fn signable_bytes_deterministic() {
        let a = IdentityAssertion {
            asserter: "a".into(),
            subject: "s".into(),
            facet: "f".into(),
            value: b"v".to_vec(),
            basis: "peer-verified".into(),
            valid_from_ms: 42,
            valid_until_ms: Some(100),
            signature: vec![],
        };
        assert_eq!(a.signable_bytes(), a.signable_bytes());
    }
}
