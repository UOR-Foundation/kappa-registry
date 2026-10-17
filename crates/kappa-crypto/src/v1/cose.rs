//! COSE_Sign1 envelopes with protected algorithm, media type, and anchor.

use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, iana};
use kappa_types::{Kappa, SignedPayload};

use crate::{CryptoError, Signer, verifier_for};

const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
enum CoseError {
    #[error("invalid COSE envelope: {0}")]
    Decode(#[from] coset::CoseError),
    #[error("COSE profile violation: {0}")]
    Profile(&'static str),
}

impl From<CoseError> for CryptoError {
    fn from(error: CoseError) -> Self {
        Self::Deserialization {
            context: "COSE_Sign1".into(),
            reason: error.to_string(),
        }
    }
}

fn algorithm(name: &str) -> Result<iana::Algorithm, CryptoError> {
    match name {
        "ed25519" => Ok(iana::Algorithm::EdDSA),
        "p256" => Ok(iana::Algorithm::ES256),
        "k256" => Ok(iana::Algorithm::ES256K),
        "ml-dsa-65" => Ok(iana::Algorithm::ML_DSA_65),
        _ => Err(CryptoError::UnsupportedAlgorithm {
            algorithm: name.into(),
        }),
    }
}

/// Sign an attached payload. All identity-defining headers are protected.
pub fn sign(
    signer: &dyn Signer,
    anchor: &Kappa,
    media_type: &str,
    payload: &[u8],
) -> Result<SignedPayload, CryptoError> {
    if Kappa::from_key(signer.algorithm(), signer.public_key())? != *anchor {
        return Err(CryptoError::InvalidKey {
            reason: "COSE signer does not match anchor".into(),
        });
    }
    if payload.len() > MAX_ENVELOPE_BYTES / 2 {
        return Err(CoseError::Profile("payload exceeds envelope budget").into());
    }
    let header = HeaderBuilder::new()
        .algorithm(algorithm(signer.algorithm())?)
        .content_type(media_type.into())
        .key_id(anchor.format().as_str().as_bytes().to_vec())
        .build();
    let envelope = CoseSign1Builder::new()
        .protected(header)
        .payload(payload.to_vec())
        .try_create_signature(&[], |message| signer.sign(message))?
        .build();
    let bytes = envelope.to_vec().map_err(CoseError::from)?;
    Ok(SignedPayload::from_cose_bytes(bytes))
}

/// Verify against the expected wire type, anchor, public key, and canonical
/// unsigned fields. A valid signature over a different payload is rejected.
pub fn verify(
    signature: &SignedPayload,
    anchor: &Kappa,
    public_key: &[u8],
    media_type: &str,
    expected_payload: &[u8],
) -> Result<(), CryptoError> {
    if signature.is_empty() || signature.len() > MAX_ENVELOPE_BYTES {
        return Err(CoseError::Profile("missing or oversized envelope").into());
    }
    let envelope = CoseSign1::from_slice(signature.as_bytes()).map_err(CoseError::from)?;
    if !envelope.unprotected.is_empty() {
        return Err(CoseError::Profile("unprotected headers must be empty").into());
    }
    let header = &envelope.protected.header;
    if !header.crit.is_empty()
        || !header.rest.is_empty()
        || !header.iv.is_empty()
        || !header.partial_iv.is_empty()
        || !header.counter_signatures.is_empty()
    {
        return Err(CoseError::Profile("unsupported protected headers").into());
    }
    let name = match &header.alg {
        Some(coset::Algorithm::Assigned(iana::Algorithm::EdDSA)) => "ed25519",
        Some(coset::Algorithm::Assigned(iana::Algorithm::ES256)) => "p256",
        Some(coset::Algorithm::Assigned(iana::Algorithm::ES256K)) => "k256",
        Some(coset::Algorithm::Assigned(iana::Algorithm::ML_DSA_65)) => "ml-dsa-65",
        _ => return Err(CoseError::Profile("unsupported or missing protected algorithm").into()),
    };
    if header.content_type != Some(coset::ContentType::Text(media_type.into())) {
        return Err(CoseError::Profile("protected media type mismatch").into());
    }
    if header.key_id != anchor.format().as_str().as_bytes()
        || Kappa::from_key(name, public_key)? != *anchor
    {
        return Err(CryptoError::InvalidKey {
            reason: "COSE anchor or public key mismatch".into(),
        });
    }
    if envelope.payload.as_deref() != Some(expected_payload) {
        return Err(CoseError::Profile("attached payload does not match unsigned fields").into());
    }
    let verifier = verifier_for(name)?;
    envelope.verify_signature(&[], |signature, message| {
        if verifier.verify(public_key, message, signature)? {
            Ok(())
        } else {
            Err(CryptoError::InvalidSignature)
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::Ed25519Signer;
    use kappa_types::signed::content_types;

    #[test]
    fn envelope_binds_unsigned_fields_type_and_anchor() -> Result<(), Box<dyn std::error::Error>> {
        let signer = Ed25519Signer::from_bytes(&[7; 32])?;
        let anchor = Kappa::from_key(signer.algorithm(), signer.public_key())?;
        let payload = b"canonical payload";
        let signature = sign(&signer, &anchor, content_types::ASSERTION, payload)?;
        verify(
            &signature,
            &anchor,
            signer.public_key(),
            content_types::ASSERTION,
            payload,
        )?;
        assert!(
            verify(
                &signature,
                &anchor,
                signer.public_key(),
                content_types::REVOCATION,
                payload
            )
            .is_err()
        );
        assert!(
            verify(
                &signature,
                &anchor,
                signer.public_key(),
                content_types::ASSERTION,
                b"changed"
            )
            .is_err()
        );
        assert!(
            verify(
                &signature,
                &Kappa::sha256(b"wrong"),
                signer.public_key(),
                content_types::ASSERTION,
                payload
            )
            .is_err()
        );
        let mut envelope = CoseSign1::from_slice(signature.as_bytes())?;
        envelope.unprotected = HeaderBuilder::new().key_id(vec![1]).build();
        let changed = SignedPayload::from_cose_bytes(envelope.to_vec()?);
        assert!(
            verify(
                &changed,
                &anchor,
                signer.public_key(),
                content_types::ASSERTION,
                payload
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn malformed_and_unsigned_envelopes_fail() {
        let anchor = Kappa::sha256(b"anchor");
        for bytes in [vec![], vec![0xff], vec![0x80], vec![0; 64]] {
            assert!(
                verify(
                    &SignedPayload::from_cose_bytes(bytes),
                    &anchor,
                    &[0; 32],
                    content_types::EPOCH,
                    b""
                )
                .is_err()
            );
        }
    }

    #[test]
    fn ml_dsa_envelope_uses_registered_algorithm_and_binds_payload()
    -> Result<(), Box<dyn std::error::Error>> {
        let signer = crate::ml_dsa::MlDsa65Signer::from_seed(&[9; 32]);
        let anchor = Kappa::from_key(signer.algorithm(), signer.public_key())?;
        let signature = sign(&signer, &anchor, content_types::ASSERTION, b"payload")?;
        let envelope = CoseSign1::from_slice(signature.as_bytes())?;
        assert_eq!(
            envelope.protected.header.alg,
            Some(coset::Algorithm::Assigned(iana::Algorithm::ML_DSA_65))
        );
        verify(
            &signature,
            &anchor,
            signer.public_key(),
            content_types::ASSERTION,
            b"payload",
        )?;
        assert!(
            verify(
                &signature,
                &anchor,
                signer.public_key(),
                content_types::ASSERTION,
                b"changed"
            )
            .is_err()
        );
        Ok(())
    }
}
