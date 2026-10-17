/// `COSE_Sign1` envelope wrapper for all signed wire types.
///
/// Every signed type in the substrate (`EpochRoot`, Assertion,
/// Succession, Revocation, Watermark, `DelegationScope`,
/// `TimeAttestation`) carries `signature: SignedPayload` instead
/// of raw `Vec<u8>` signature bytes.
///
/// `SignedPayload` wraps the coset/ciborium-serialized `COSE_Sign1`
/// bytes. The dCBOR envelope at the wire type level treats
/// this as an opaque bstr at its CBOR key. The `COSE_Sign1`
/// structure inside carries:
///   - protected headers: alg (COSE algorithm ID), kid (signer
///     anchor kappa as UTF-8 bytes), `content_type` (wire type
///     media type string)
///   - unprotected headers: empty map
///   - payload: the canonical dCBOR bytes of the unsigned fields
///   - signature: the raw cryptographic signature bytes
///
/// Construction and verification live in kappa-crypto, which
/// depends on coset + aws-lc-rs. kappa-types carries only the
/// bytes and the empty/present check. No crypto dependency at
/// level 0.
///
/// Algorithm agility: the COSE protected header's `alg` field
/// identifies Ed25519, P-256, K-256, ML-DSA-65, or FROST
/// variants. The verifier reads `alg` from the protected header
/// and dispatches to the correct verification function. No
/// out-of-band algorithm negotiation.
///
/// Dual signatures (Succession): the type carries two
/// `SignedPayload` fields (`old_signature`, `new_signature`). Both
/// sign the same payload with different keys. Both are
/// independently verifiable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPayload(Vec<u8>);

impl SignedPayload {
    /// Wrap pre-built `COSE_Sign1` bytes.
    /// Called by kappa-crypto after coset builds and serializes
    /// the `COSE_Sign1` structure.
    pub const fn from_cose_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Empty signature (unsigned). Used during construction
    /// before signing, and for types that are optionally signed.
    pub const fn empty() -> Self {
        Self(Vec::new())
    }

    /// The raw `COSE_Sign1` bytes for serialization into the
    /// dCBOR envelope's bstr field.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume and return the inner bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }

    /// Whether this payload has been signed.
    pub const fn is_signed(&self) -> bool {
        !self.0.is_empty()
    }

    /// Whether this payload is unsigned (empty).
    pub const fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Byte length of the `COSE_Sign1` envelope.
    pub const fn len(&self) -> usize {
        self.0.len()
    }
}

impl Default for SignedPayload {
    fn default() -> Self {
        Self::empty()
    }
}

impl AsRef<[u8]> for SignedPayload {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// dCBOR serialization: SignedPayload encodes as a bstr (byte string).
// The COSE_Sign1 structure inside is opaque to the dCBOR layer.
impl From<SignedPayload> for dcbor::prelude::CBOR {
    fn from(sp: SignedPayload) -> Self {
        Self::from(dcbor::prelude::ByteString::from(sp.0))
    }
}

impl From<&SignedPayload> for dcbor::prelude::CBOR {
    fn from(sp: &SignedPayload) -> Self {
        Self::from(dcbor::prelude::ByteString::from(sp.0.as_slice()))
    }
}

impl TryFrom<dcbor::prelude::CBOR> for SignedPayload {
    type Error = dcbor::Error;

    fn try_from(cbor: dcbor::prelude::CBOR) -> Result<Self, Self::Error> {
        let bytes: dcbor::prelude::ByteString = cbor.try_into()?;
        Ok(Self(bytes.into()))
    }
}

impl serde::Serialize for SignedPayload {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for SignedPayload {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PayloadVisitor;

        impl<'de> serde::de::Visitor<'de> for PayloadVisitor {
            type Value = SignedPayload;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("COSE envelope bytes")
            }

            fn visit_bytes<E: serde::de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                Ok(SignedPayload::from_cose_bytes(bytes.to_vec()))
            }

            fn visit_byte_buf<E: serde::de::Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
                Ok(SignedPayload::from_cose_bytes(bytes))
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = Vec::new();
                while let Some(byte) = sequence.next_element::<u8>()? {
                    bytes.push(byte);
                }
                Ok(SignedPayload::from_cose_bytes(bytes))
            }
        }

        deserializer.deserialize_byte_buf(PayloadVisitor)
    }
}

/// Well-known COSE `content_type` values for kappa-distribution wire types.
///
/// Used in the `COSE_Sign1` protected header to identify the wire type
/// so a verifier can determine the payload format before parsing.
pub mod content_types {
    pub const EPOCH: &str = "application/vnd.kappa.epoch.v1+cbor";
    pub const ASSERTION: &str = "application/vnd.kappa.assertion.v1+cbor";
    pub const SUCCESSION: &str = "application/vnd.kappa.succession.v1+cbor";
    pub const REVOCATION: &str = "application/vnd.kappa.revocation.v1+cbor";
    pub const WATERMARK: &str = "application/vnd.kappa.watermark.v1+cbor";
    pub const DELEGATION: &str = "application/vnd.kappa.delegation.v1+cbor";
    pub const TIME_ATTESTATION: &str = "application/vnd.kappa.time-attestation.v1+cbor";
    pub const IDENTITY_TOMBSTONE: &str = "application/vnd.kappa.identity-tombstone.v1+cbor";
    pub const REVOCATION_COMMITMENT: &str = "application/vnd.kappa.revocation-commitment.v1+cbor";
    pub const SCOPED_PROJECTION: &str = "application/vnd.kappa.scoped-projection.v1+cbor";
    pub const DEVICE_BINDING: &str = "application/vnd.kappa.device-binding.v1+cbor";
    pub const PREKEY_BINDING: &str = "application/vnd.kappa.prekey-binding.v1+cbor";
    pub const LOCATOR_RECORD: &str = "application/vnd.kappa.locator-record.v1+cbor";
    pub const RETIREMENT_REQUEST: &str = "application/vnd.kappa.retirement-request.v1+cbor";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_unsigned() {
        let sp = SignedPayload::empty();
        assert!(!sp.is_signed());
        assert!(sp.is_empty());
        assert_eq!(sp.len(), 0);
    }

    #[test]
    fn from_bytes_is_signed() {
        let sp = SignedPayload::from_cose_bytes(vec![1, 2, 3]);
        assert!(sp.is_signed());
        assert!(!sp.is_empty());
        assert_eq!(sp.len(), 3);
        assert_eq!(sp.as_bytes(), &[1, 2, 3]);
    }

    #[test]
    fn into_bytes_roundtrip() {
        let original = vec![10, 20, 30, 40];
        let sp = SignedPayload::from_cose_bytes(original.clone());
        assert_eq!(sp.into_bytes(), original);
    }

    #[test]
    fn default_is_empty() {
        let sp = SignedPayload::default();
        assert!(sp.is_empty());
    }

    #[test]
    fn serde_accepts_native_bytes_and_json_sequences() -> Result<(), Box<dyn std::error::Error>> {
        use serde::Deserialize;

        let native =
            serde::de::value::BytesDeserializer::<serde::de::value::Error>::new(&[5, 6, 7]);
        let sp = SignedPayload::deserialize(native)?;
        assert_eq!(sp.as_bytes(), &[5, 6, 7]);
        let json = serde_json::to_vec(&sp)?;
        let recovered: SignedPayload = serde_json::from_slice(&json)?;
        assert_eq!(recovered, sp);
        assert!(serde_json::from_str::<SignedPayload>("[256]").is_err());
        Ok(())
    }

    #[test]
    fn cose_envelope_encodes_as_byte_string() {
        let payload = SignedPayload::from_cose_bytes(vec![0x01, 0x18, 0xff]);
        let borrowed = dcbor::prelude::CBOR::from(&payload).to_cbor_data();
        let owned = dcbor::prelude::CBOR::from(payload).to_cbor_data();
        assert_eq!(borrowed, [0x43, 0x01, 0x18, 0xff]);
        assert_eq!(owned, borrowed);
        assert_eq!(
            dcbor::prelude::CBOR::from(SignedPayload::empty()).to_cbor_data(),
            [0x40]
        );
    }

    #[test]
    fn cose_envelope_decodes_only_byte_strings() -> Result<(), dcbor::Error> {
        let cbor = dcbor::prelude::CBOR::to_byte_string([0x01, 0x18, 0xff]);
        let payload = SignedPayload::try_from(cbor)?;
        assert_eq!(payload.as_bytes(), &[0x01, 0x18, 0xff]);
        let array = dcbor::prelude::CBOR::from(vec![1u8, 2]);
        assert_eq!(array.to_cbor_data(), [0x82, 0x01, 0x02]);
        assert!(SignedPayload::try_from(array).is_err());
        assert!(SignedPayload::try_from(dcbor::prelude::CBOR::from("signature")).is_err());
        Ok(())
    }

    #[test]
    fn content_type_constants_are_distinct() {
        let types = [
            content_types::EPOCH,
            content_types::ASSERTION,
            content_types::SUCCESSION,
            content_types::REVOCATION,
            content_types::WATERMARK,
            content_types::DELEGATION,
            content_types::TIME_ATTESTATION,
            content_types::IDENTITY_TOMBSTONE,
            content_types::REVOCATION_COMMITMENT,
            content_types::SCOPED_PROJECTION,
            content_types::DEVICE_BINDING,
            content_types::PREKEY_BINDING,
            content_types::LOCATOR_RECORD,
            content_types::RETIREMENT_REQUEST,
        ];
        for (i, a) in types.iter().enumerate() {
            for (j, b) in types.iter().enumerate() {
                if i != j {
                    assert_ne!(a, b, "content types at {i} and {j} collide");
                }
            }
        }
    }
}
