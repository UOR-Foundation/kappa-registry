//! COSE_Sign1 envelopes with protected algorithm, media type, and anchor.

use coset::{CborSerializable, CoseSign1, CoseSign1Builder, HeaderBuilder, iana};
use kappa_types::{Kappa, SignedPayload};

use crate::{CryptoError, Signer, verifier_for};

const MAX_ENVELOPE_BYTES: usize = 4 * 1024 * 1024;

mod signature_match;

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

/// Signature bytes each supported algorithm produces: Ed25519 (RFC 8032)
/// and ECDSA over P-256 and secp256k1 in COSE's fixed-size `r || s` form
/// (RFC 9053 section 2.1) are 64 bytes; ML-DSA-65 is 3309 bytes (FIPS 204
/// table 2). The set is closed by [`algorithm`].
fn signature_bytes(name: &str) -> Result<usize, CryptoError> {
    algorithm(name)?;
    Ok(match name {
        "ml-dsa-65" => 3309,
        _ => 64,
    })
}

/// Bytes of an envelope's CBOR framing beyond its variable fields: the
/// four-element array header, the protected header's byte-string and map
/// headers with the algorithm, content-type and key-id labels and their
/// value headers, the empty unprotected map, and the payload and signature
/// byte-string headers, each at its widest encoding.
const ENVELOPE_FRAMING: usize = 48;

/// The most bytes [`sign`] can produce for a `payload_len`-byte payload
/// signed by `algorithm` under `anchor` with `media_type`. This bounds serialized
/// bytes, not construction allocations, hashing, or signer workspace.
pub fn envelope_bound(
    algorithm: &str,
    anchor: &Kappa,
    media_type: &str,
    payload_len: usize,
) -> Result<usize, CryptoError> {
    let signature = signature_bytes(algorithm)?;
    ENVELOPE_FRAMING
        .checked_add(media_type.len())
        .and_then(|total| total.checked_add(anchor.format().as_str().len()))
        .and_then(|total| total.checked_add(payload_len))
        .and_then(|total| total.checked_add(signature))
        .ok_or_else(|| CoseError::Profile("envelope bound overflows").into())
}

/// Sign an attached payload. All identity-defining headers are protected.
/// The envelope never exceeds [`envelope_bound`].
pub fn sign(
    signer: &dyn Signer,
    anchor: &Kappa,
    media_type: &str,
    payload: &[u8],
) -> Result<SignedPayload, CryptoError> {
    let prepared = UnsignedEnvelope::new(signer, anchor, media_type, payload)?;
    let signature = signer.sign(prepared.to_be_signed())?;
    prepared.complete(&signature)
}

/// Owned COSE signing input. Completion borrows returned signature bytes so
/// their publication owner retains them even when completion fails.
pub struct UnsignedEnvelope {
    envelope: CoseSign1,
    tbs: Vec<u8>,
    signature_len: usize,
    bound: usize,
}

impl UnsignedEnvelope {
    pub fn new(
        signer: &dyn Signer,
        anchor: &Kappa,
        media_type: &str,
        payload: &[u8],
    ) -> Result<Self, CryptoError> {
        if Kappa::from_key(signer.algorithm(), signer.public_key())? != *anchor {
            return Err(CryptoError::InvalidKey {
                reason: "COSE signer does not match anchor".into(),
            });
        }
        if payload.len() > MAX_ENVELOPE_BYTES / 2 {
            return Err(CoseError::Profile("payload exceeds envelope budget").into());
        }
        let bound = envelope_bound(signer.algorithm(), anchor, media_type, payload.len())?;
        let header = HeaderBuilder::new()
            .algorithm(algorithm(signer.algorithm())?)
            .content_type(media_type.into())
            .key_id(anchor.format().as_str().as_bytes().to_vec())
            .build();
        let envelope = CoseSign1Builder::new()
            .protected(header)
            .payload(payload.to_vec())
            .build();
        let tbs = envelope.tbs_data(&[]);
        Ok(Self {
            envelope,
            tbs,
            signature_len: signature_bytes(signer.algorithm())?,
            bound,
        })
    }

    pub fn to_be_signed(&self) -> &[u8] {
        &self.tbs
    }

    pub fn complete(&self, signature: &[u8]) -> Result<SignedPayload, CryptoError> {
        if signature.len() != self.signature_len {
            return Err(
                CoseError::Profile("signature length differs from algorithm profile").into(),
            );
        }
        let mut envelope = self.envelope.clone();
        envelope.signature = signature.to_vec();
        let bytes = envelope.to_vec().map_err(CoseError::from)?;
        if bytes.len() > self.bound {
            return Err(CoseError::Profile("envelope exceeds its admitted bound").into());
        }
        Ok(SignedPayload::from_cose_bytes(bytes))
    }
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

/// Compare an already authenticated envelope's signature to the exact bytes
/// retained at its signing boundary. This does not authenticate the envelope.
pub fn contains_signature(envelope: &SignedPayload, returned: &[u8]) -> Result<bool, CryptoError> {
    if envelope.is_empty() || envelope.len() > MAX_ENVELOPE_BYTES {
        return Err(CoseError::Profile("missing or oversized envelope").into());
    }
    signature_match::matches(envelope.as_bytes(), returned)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::Ed25519Signer;
    use kappa_types::signed::content_types;

    #[test]
    fn prepared_completion_preserves_input_and_matches_coset()
    -> Result<(), Box<dyn std::error::Error>> {
        let signer = Ed25519Signer::from_bytes(&[19; 32])?;
        let anchor = Kappa::from_key(signer.algorithm(), signer.public_key())?;
        let payload = b"retained signing input";
        let prepared = UnsignedEnvelope::new(&signer, &anchor, content_types::EPOCH, payload)?;
        let malformed = vec![0xa5; 63];
        assert!(prepared.complete(&malformed).is_err());
        assert_eq!(malformed, vec![0xa5; 63]);
        let signature = signer.sign(prepared.to_be_signed())?;
        let completed = prepared.complete(&signature)?;
        let independent = CoseSign1Builder::new()
            .protected(
                HeaderBuilder::new()
                    .algorithm(iana::Algorithm::EdDSA)
                    .content_type(content_types::EPOCH.into())
                    .key_id(anchor.format().as_str().as_bytes().to_vec())
                    .build(),
            )
            .payload(payload.to_vec())
            .try_create_signature(&[], |message| signer.sign(message))?
            .build()
            .to_vec()?;
        assert_eq!(completed.as_bytes(), independent.as_slice());
        assert!(contains_signature(&completed, &signature)?);
        assert!(!contains_signature(&completed, &malformed)?);
        verify(
            &completed,
            &anchor,
            signer.public_key(),
            content_types::EPOCH,
            payload,
        )?;
        Ok(())
    }

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
