use dcbor::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    #[error("canonical decode error: {0}")]
    Decode(dcbor::Error),
    #[error("canonical conversion error: {0}")]
    Conversion(dcbor::Error),
}

/// Encode a value to canonical dCBOR bytes.
pub fn canonical_bytes<T: Into<CBOR> + Clone>(value: &T) -> Vec<u8> {
    value.clone().into().to_cbor_data()
}

/// Decode canonical dCBOR bytes back to a value.
/// Rejects non-canonical input.
pub fn from_canonical<T>(bytes: &[u8]) -> Result<T, CanonicalError>
where
    T: TryFrom<CBOR, Error = dcbor::Error>,
{
    let cbor = CBOR::try_from_data(bytes).map_err(CanonicalError::Decode)?;
    T::try_from(cbor).map_err(CanonicalError::Conversion)
}
