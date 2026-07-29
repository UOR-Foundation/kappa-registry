//! Canonical serialization anti-seam.
//!
//! dCBOR (draft-mcnally-deterministic-cbor) guarantees:
//! - Integers use shortest encoding
//! - Floats use shortest encoding with numeric reduction (2.0 -> 2)
//! - All NaN canonicalized to 0xf97e00
//! - Map keys sorted bytewise lexicographic
//! - Text strings in Unicode NFC
//! - Decoders reject non-conforming input

use dcbor::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    #[error("canonical decode error: {0}")]
    Decode(dcbor::Error),
    #[error("canonical conversion error: {0}")]
    Conversion(dcbor::Error),
}

/// Encode a value to canonical dCBOR bytes.
pub(crate) fn canonical_bytes<T: Into<CBOR> + Clone>(value: &T) -> Vec<u8> {
    value.clone().into().to_cbor_data()
}

/// Decode canonical dCBOR bytes back to a value.
/// Rejects non-canonical input.
pub(crate) fn from_canonical<T>(bytes: &[u8]) -> Result<T, CanonicalError>
where
    T: TryFrom<CBOR, Error = dcbor::Error>,
{
    let cbor = CBOR::try_from_data(bytes).map_err(CanonicalError::Decode)?;
    T::try_from(cbor).map_err(CanonicalError::Conversion)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_integer() {
        let value: u64 = 42;
        let bytes = canonical_bytes(&value);
        let cbor = CBOR::try_from_data(&bytes).unwrap();
        let decoded: u64 = cbor.try_into().unwrap();
        assert_eq!(decoded, 42);
    }

    #[test]
    fn roundtrip_string() {
        let value = "hello".to_string();
        let bytes = canonical_bytes(&value);
        let cbor = CBOR::try_from_data(&bytes).unwrap();
        let decoded: String = cbor.try_into().unwrap();
        assert_eq!(decoded, "hello");
    }

    #[test]
    fn deterministic_encoding() {
        let v1 = "deterministic".to_string();
        let v2 = "deterministic".to_string();
        assert_eq!(canonical_bytes(&v1), canonical_bytes(&v2));
    }

    #[test]
    fn rejects_non_canonical() {
        let non_canonical: &[u8] = &[0x19, 0x00, 0xff];
        let result = CBOR::try_from_data(non_canonical);
        assert!(result.is_err());
    }

    #[test]
    fn empty_bytes_rejected() {
        let result: Result<u64, CanonicalError> = from_canonical(&[]);
        assert!(result.is_err());
    }
}
