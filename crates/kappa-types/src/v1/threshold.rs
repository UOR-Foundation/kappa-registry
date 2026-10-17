use dcbor::prelude::*;

use crate::kappa::Kappa;

/// Multi-party signing round state for FROST ceremonies.
///
/// Transmitted between co-signers during threshold signing
/// of epoch roots, assertions, or successions. Ephemeral,
/// per-ceremony. Not content-addressed. Authenticated by
/// the Noise transport between co-signers.
///
/// CBOR key assignments (PERMANENT): 0-8
#[derive(Debug, Clone)]
pub struct ThresholdRound {
    /// UUID identifying this ceremony.
    pub ceremony_id: Vec<u8>,
    /// Round number: 1 (commitments) or 2 (shares).
    pub round: u64,
    /// Anchor kappa of this participant.
    pub participant: Kappa,
    /// Group verifying key (public).
    pub group_key: Vec<u8>,
    /// Minimum signers (t in t-of-n).
    pub threshold: u64,
    /// Total participants (n in t-of-n).
    pub total: u64,
    /// Round 1: hiding + binding commitment. Null in round 2.
    pub commitment: Option<Vec<u8>>,
    /// Round 2: signature share. Null in round 1.
    pub share: Option<Vec<u8>>,
    /// COSE algorithm identifier for the group signature.
    pub algorithm: i64,
}

impl From<ThresholdRound> for CBOR {
    fn from(value: ThresholdRound) -> Self {
        let mut map = Map::new();
        map.insert(0u64, ByteString::from(value.ceremony_id));
        map.insert(1u64, value.round);
        map.insert(2u64, value.participant);
        map.insert(3u64, ByteString::from(value.group_key));
        map.insert(4u64, value.threshold);
        map.insert(5u64, value.total);
        map.insert(
            6u64,
            value
                .commitment
                .map_or_else(Self::null, |v| ByteString::from(v).into()),
        );
        map.insert(
            7u64,
            value
                .share
                .map_or_else(Self::null, |v| ByteString::from(v).into()),
        );
        map.insert(8u64, value.algorithm);
        map.into()
    }
}

impl TryFrom<CBOR> for ThresholdRound {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let CBORCase::Map(map) = cbor.into_case() else {
            return Err(dcbor::Error::WrongType);
        };
        let ceremony: ByteString = map.extract(0u64)?;
        let group_key: ByteString = map.extract(3u64)?;
        let optional_bytes = |key: u64| -> Result<Option<Vec<u8>>, dcbor::Error> {
            let value: CBOR = map.extract(key)?;
            if value.is_null() {
                Ok(None)
            } else {
                let bytes: ByteString = value.try_into()?;
                Ok(Some(bytes.into()))
            }
        };
        Ok(Self {
            ceremony_id: ceremony.into(),
            round: map.extract(1u64)?,
            participant: map.extract(2u64)?,
            group_key: group_key.into(),
            threshold: map.extract(4u64)?,
            total: map.extract(5u64)?,
            commitment: optional_bytes(6)?,
            share: optional_bytes(7)?,
            algorithm: map.extract(8u64)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    #[test]
    fn byte_fields_and_null_round_payload_have_exact_wire_encoding() -> Result<(), dcbor::Error> {
        let round = ThresholdRound {
            ceremony_id: vec![1, 2],
            round: 1,
            participant: Kappa::sha256(b"participant"),
            group_key: vec![3, 4],
            threshold: 2,
            total: 3,
            commitment: Some(vec![5, 6]),
            share: None,
            algorithm: -8,
        };
        let CBORCase::Map(map) = CBOR::from(round).into_case() else {
            panic!("threshold round must be a map");
        };
        for (key, expected) in [
            (0u64, vec![0x42, 1, 2]),
            (3, vec![0x42, 3, 4]),
            (6, vec![0x42, 5, 6]),
            (7, vec![0xf6]),
        ] {
            let value: CBOR = map.extract(key)?;
            assert_eq!(value.to_cbor_data(), expected);
        }
        Ok(())
    }

    #[test]
    fn round1_roundtrip() -> Result<(), crate::canonical::CanonicalError> {
        let round = ThresholdRound {
            ceremony_id: vec![1; 16],
            round: 1,
            participant: Kappa::sha256(b"participant-1"),
            group_key: vec![2; 32],
            threshold: 2,
            total: 3,
            commitment: Some(vec![3; 64]),
            share: None,
            algorithm: -8, // EdDSA
        };
        let bytes = canonical_bytes(&round);
        let recovered: ThresholdRound = from_canonical(&bytes)?;
        assert_eq!(recovered.round, 1);
        assert!(recovered.commitment.is_some());
        assert!(recovered.share.is_none());
        assert_eq!(recovered.threshold, 2);
        assert_eq!(recovered.total, 3);
        Ok(())
    }

    #[test]
    fn round2_roundtrip() -> Result<(), crate::canonical::CanonicalError> {
        let round = ThresholdRound {
            ceremony_id: vec![1; 16],
            round: 2,
            participant: Kappa::sha256(b"participant-1"),
            group_key: vec![2; 32],
            threshold: 2,
            total: 3,
            commitment: None,
            share: Some(vec![4; 32]),
            algorithm: -7, // ES256
        };
        let bytes = canonical_bytes(&round);
        let recovered: ThresholdRound = from_canonical(&bytes)?;
        assert_eq!(recovered.round, 2);
        assert!(recovered.commitment.is_none());
        assert!(recovered.share.is_some());
        Ok(())
    }
}
