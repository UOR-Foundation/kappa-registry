//! Typed signing boundaries for the substrate's canonical wire records.

use kappa_types::{
    DelegationScope, EpochRoot, IdentityAssertion, RetirementRequest, Revocation, Succession,
    TimeAttestation, Watermark, signed::content_types,
};

use crate::{CryptoError, Signer, cose};

/// Consume a succession only after both anchor-bound signatures verify.
pub fn admit_succession(
    record: Succession,
    old_algorithm: &str,
    old_public_key: &[u8],
    new_algorithm: &str,
    new_public_key: &[u8],
) -> Result<crate::Verified<Succession>, CryptoError> {
    if kappa_types::Kappa::from_key(old_algorithm, old_public_key)? != record.old_anchor
        || kappa_types::Kappa::from_key(new_algorithm, new_public_key)? != record.new_anchor
    {
        return Err(CryptoError::InvalidKey {
            reason: "succession key does not match claimed anchor".into(),
        });
    }
    verify_succession(&record, old_public_key, new_public_key)?;
    Ok(crate::Verified::from_verified(record))
}

macro_rules! signed_record {
    ($sign:ident, $verify:ident, $admit:ident, $ty:ty, $anchor:ident, $media:expr) => {
        pub fn $sign(mut record: $ty, signer: &dyn Signer) -> Result<$ty, CryptoError> {
            record.cose_signature =
                cose::sign(signer, &record.$anchor, $media, &record.signable_bytes())?;
            Ok(record)
        }

        pub fn $verify(record: &$ty, public_key: &[u8]) -> Result<(), CryptoError> {
            cose::verify(
                &record.cose_signature,
                &record.$anchor,
                public_key,
                $media,
                &record.signable_bytes(),
            )
        }

        pub fn $admit(record: $ty, public_key: &[u8]) -> Result<crate::Verified<$ty>, CryptoError> {
            $verify(&record, public_key)?;
            Ok(crate::Verified::from_verified(record))
        }
    };
}

signed_record!(
    sign_assertion,
    verify_assertion,
    admit_assertion,
    IdentityAssertion,
    asserter,
    content_types::ASSERTION
);
signed_record!(
    sign_revocation,
    verify_revocation,
    admit_revocation,
    Revocation,
    asserter,
    content_types::REVOCATION
);
signed_record!(
    sign_watermark,
    verify_watermark,
    admit_watermark,
    Watermark,
    asserter,
    content_types::WATERMARK
);
signed_record!(
    sign_delegation,
    verify_delegation,
    admit_delegation,
    DelegationScope,
    delegator,
    content_types::DELEGATION
);
signed_record!(
    sign_time_attestation,
    verify_time_attestation,
    admit_time_attestation,
    TimeAttestation,
    authority,
    content_types::TIME_ATTESTATION
);

/// Sign a retirement request as its principal. The signer's key must be
/// the key the request carries.
pub fn sign_retirement_request(
    mut record: RetirementRequest,
    signer: &dyn Signer,
) -> Result<RetirementRequest, CryptoError> {
    if signer.algorithm() != record.algorithm() || signer.public_key() != record.public_key() {
        return Err(CryptoError::InvalidKey {
            reason: "retirement request names another principal key".into(),
        });
    }
    record.cose_signature = cose::sign(
        signer,
        record.principal(),
        content_types::RETIREMENT_REQUEST,
        &record.signable_bytes(),
    )?;
    Ok(record)
}

/// Admit a retirement request whose principal signed it with the key it
/// carries.
pub fn admit_retirement_request(
    record: RetirementRequest,
) -> Result<crate::Verified<RetirementRequest>, CryptoError> {
    cose::verify(
        &record.cose_signature,
        record.principal(),
        record.public_key(),
        content_types::RETIREMENT_REQUEST,
        &record.signable_bytes(),
    )?;
    Ok(crate::Verified::from_verified(record))
}

pub fn sign_epoch(record: EpochRoot, signer: &dyn Signer) -> Result<EpochRoot, CryptoError> {
    let signature = cose::sign(
        signer,
        record.signer_anchor(),
        content_types::EPOCH,
        &record.signable_bytes(),
    )?;
    Ok(record.with_signature(signature))
}

pub fn verify_epoch(record: &EpochRoot, public_key: &[u8]) -> Result<(), CryptoError> {
    cose::verify(
        record.cose_signature(),
        record.signer_anchor(),
        public_key,
        content_types::EPOCH,
        &record.signable_bytes(),
    )
}

pub fn sign_succession(
    mut record: Succession,
    old_signer: &dyn Signer,
    new_signer: &dyn Signer,
) -> Result<Succession, CryptoError> {
    let payload = record.signable_bytes();
    let old_signature = cose::sign(
        old_signer,
        &record.old_anchor,
        content_types::SUCCESSION,
        &payload,
    )?;
    let new_signature = cose::sign(
        new_signer,
        &record.new_anchor,
        content_types::SUCCESSION,
        &payload,
    )?;
    record.old_cose_signature = old_signature;
    record.new_cose_signature = new_signature;
    Ok(record)
}

pub fn verify_succession(
    record: &Succession,
    old_public_key: &[u8],
    new_public_key: &[u8],
) -> Result<(), CryptoError> {
    let payload = record.signable_bytes();
    cose::verify(
        &record.old_cose_signature,
        &record.old_anchor,
        old_public_key,
        content_types::SUCCESSION,
        &payload,
    )?;
    cose::verify(
        &record.new_cose_signature,
        &record.new_anchor,
        new_public_key,
        content_types::SUCCESSION,
        &payload,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ed25519::Ed25519Signer;
    use kappa_types::{Kappa, SignedPayload, SuccessionReason};

    #[test]
    fn both_succession_signatures_are_required_and_bind_the_same_record() -> Result<(), CryptoError>
    {
        let old = Ed25519Signer::from_bytes(&[1; 32])?;
        let new = Ed25519Signer::from_bytes(&[2; 32])?;
        let record = Succession {
            old_anchor: Kappa::from_key(old.algorithm(), old.public_key())?,
            new_anchor: Kappa::from_key(new.algorithm(), new.public_key())?,
            reason: SuccessionReason::Rotation,
            effective_at_ms: 1,
            chain_anchor: None,
            prev_identifier: None,
            old_cose_signature: SignedPayload::empty(),
            new_cose_signature: SignedPayload::empty(),
        };
        let mut record = sign_succession(record, &old, &new)?;
        let evidence = admit_succession(
            record.clone(),
            old.algorithm(),
            old.public_key(),
            new.algorithm(),
            new.public_key(),
        )?;
        assert_eq!(evidence.get().old_anchor, record.old_anchor);
        assert_eq!(evidence.into_inner().new_anchor, record.new_anchor);
        assert!(
            admit_succession(
                record.clone(),
                new.algorithm(),
                new.public_key(),
                new.algorithm(),
                new.public_key(),
            )
            .is_err()
        );
        verify_succession(&record, old.public_key(), new.public_key())?;
        record.effective_at_ms = 2;
        assert!(verify_succession(&record, old.public_key(), new.public_key()).is_err());
        assert!(
            admit_succession(
                record.clone(),
                old.algorithm(),
                old.public_key(),
                new.algorithm(),
                new.public_key(),
            )
            .is_err()
        );
        record.effective_at_ms = 1;
        record.new_cose_signature = record.old_cose_signature.clone();
        assert!(verify_succession(&record, old.public_key(), new.public_key()).is_err());
        Ok(())
    }
}
