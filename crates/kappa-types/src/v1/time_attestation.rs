use dcbor::prelude::*;

use crate::identity::TimeSourceProtocol;
use crate::kappa::Kappa;
use crate::signed::SignedPayload;

/// Third-party temporal witness: a trusted time source attests
/// that it observed a specific kappa at a specific time.
///
/// Content-addressed: yes.
/// Signed: yes (`COSE_Sign1` by the time authority).
///
/// CBOR key assignments (PERMANENT): 0-7
#[derive(Debug, Clone, CBORCodable)]
pub struct TimeAttestation {
    /// Anchor kappa of the time source.
    #[cbor(n = 0)]
    pub authority: Kappa,
    /// The kappa being timestamped.
    #[cbor(n = 1)]
    pub observed_kappa: Kappa,
    /// Milliseconds since Unix epoch (authority's clock).
    #[cbor(n = 2)]
    pub timestamp_ms: i64,
    /// Bounded uncertainty of the clock in milliseconds.
    #[cbor(n = 3)]
    pub uncertainty_ms: u64,
    /// Client-provided nonce for freshness.
    #[cbor(n = 4)]
    pub nonce: ByteString,
    /// Time source protocol discriminant.
    #[cbor(n = 5)]
    pub source_protocol: TimeSourceProtocol,
    /// Protocol-specific receipt (Roughtime, NTS, etc.) or empty.
    #[cbor(n = 6)]
    pub raw_receipt: Option<ByteString>,
    /// `COSE_Sign1` signing canonical(keys 0-6).
    #[cbor(n = 7)]
    pub cose_signature: SignedPayload,
}

/// The unsigned portion for signing.
#[derive(Clone, CBORCodable)]
struct TimeAttestationSignable {
    #[cbor(n = 0)]
    authority: Kappa,
    #[cbor(n = 1)]
    observed_kappa: Kappa,
    #[cbor(n = 2)]
    timestamp_ms: i64,
    #[cbor(n = 3)]
    uncertainty_ms: u64,
    #[cbor(n = 4)]
    nonce: ByteString,
    #[cbor(n = 5)]
    source_protocol: TimeSourceProtocol,
    #[cbor(n = 6)]
    raw_receipt: Option<ByteString>,
}

impl TimeAttestation {
    /// Decode claimed bounds without conferring cryptographic or UTC authority.
    pub fn claimed_interval(&self) -> Result<crate::clock::TimeInterval, crate::clock::TimeError> {
        crate::clock::TimeInterval::around(
            crate::clock::UnixTimeMs::from_millis(self.timestamp_ms),
            self.uncertainty_ms,
        )
    }

    /// Canonical dCBOR bytes of the unsigned fields (keys 0-6).
    pub fn signable_bytes(&self) -> Vec<u8> {
        let signable = TimeAttestationSignable {
            authority: self.authority.clone(),
            observed_kappa: self.observed_kappa.clone(),
            timestamp_ms: self.timestamp_ms,
            uncertainty_ms: self.uncertainty_ms,
            nonce: self.nonce.clone(),
            source_protocol: self.source_protocol,
            raw_receipt: self.raw_receipt.clone(),
        };
        crate::canonical::canonical_bytes(&signable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    #[test]
    fn receipt_and_nonce_use_byte_strings_in_signed_and_unsigned_forms() -> Result<(), dcbor::Error>
    {
        let attestation = TimeAttestation {
            authority: Kappa::sha256(b"authority"),
            observed_kappa: Kappa::sha256(b"object"),
            timestamp_ms: 1,
            uncertainty_ms: 0,
            nonce: vec![1, 2].into(),
            source_protocol: TimeSourceProtocol::Local,
            raw_receipt: Some(vec![3, 4].into()),
            cose_signature: SignedPayload::from_cose_bytes(vec![5, 6]),
        };
        for bytes in [canonical_bytes(&attestation), attestation.signable_bytes()] {
            let CBORCase::Map(map) = CBOR::try_from_data(bytes)?.into_case() else {
                panic!("time attestation must be a map");
            };
            for (key, expected) in [(4u64, [0x42, 1, 2]), (6, [0x42, 3, 4])] {
                let value: CBOR = map.extract(key)?;
                assert_eq!(value.to_cbor_data(), expected);
            }
        }
        Ok(())
    }

    #[test]
    fn roundtrip() -> Result<(), crate::canonical::CanonicalError> {
        let attestation = TimeAttestation {
            authority: Kappa::sha256(b"time-server"),
            observed_kappa: Kappa::sha256(b"epoch-root"),
            timestamp_ms: 1_724_537_600_000,
            uncertainty_ms: 1000,
            nonce: vec![42; 32].into(),
            source_protocol: TimeSourceProtocol::Roughtime,
            raw_receipt: Some(vec![1, 2, 3].into()),
            cose_signature: SignedPayload::from_cose_bytes(vec![99]),
        };
        let bytes = canonical_bytes(&attestation);
        let recovered: TimeAttestation = from_canonical(&bytes)?;
        assert_eq!(recovered.authority, attestation.authority);
        assert_eq!(recovered.observed_kappa, attestation.observed_kappa);
        assert_eq!(recovered.timestamp_ms, 1_724_537_600_000);
        assert_eq!(recovered.uncertainty_ms, 1000);
        assert!(recovered.cose_signature.is_signed());
        Ok(())
    }

    #[test]
    fn signable_bytes_deterministic() {
        let a = TimeAttestation {
            authority: Kappa::sha256(b"ts"),
            observed_kappa: Kappa::sha256(b"obj"),
            timestamp_ms: 1000,
            uncertainty_ms: 50,
            nonce: vec![0; 32].into(),
            source_protocol: TimeSourceProtocol::Local,
            raw_receipt: None,
            cose_signature: SignedPayload::empty(),
        };
        let b = TimeAttestation {
            authority: Kappa::sha256(b"ts"),
            observed_kappa: Kappa::sha256(b"obj"),
            timestamp_ms: 1000,
            uncertainty_ms: 50,
            nonce: vec![0; 32].into(),
            source_protocol: TimeSourceProtocol::Local,
            raw_receipt: None,
            cose_signature: SignedPayload::from_cose_bytes(vec![1, 2, 3]),
        };
        assert_eq!(a.signable_bytes(), b.signable_bytes());
    }

    #[test]
    fn no_receipt() -> Result<(), crate::canonical::CanonicalError> {
        let attestation = TimeAttestation {
            authority: Kappa::sha256(b"local"),
            observed_kappa: Kappa::sha256(b"epoch"),
            timestamp_ms: 5000,
            uncertainty_ms: u64::MAX,
            nonce: ByteString::default(),
            source_protocol: TimeSourceProtocol::Local,
            raw_receipt: None,
            cose_signature: SignedPayload::empty(),
        };
        let bytes = canonical_bytes(&attestation);
        let recovered: TimeAttestation = from_canonical(&bytes)?;
        assert!(recovered.raw_receipt.is_none());
        assert!(!recovered.cose_signature.is_signed());
        Ok(())
    }
}
