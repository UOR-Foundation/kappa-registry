//! Admission of content-bound temporal witnesses. Witnessed event time is
//! not interchangeable with the current time at receipt.

use kappa_types::{
    Kappa, TimeAttestation,
    clock::{TimeError, TimeInterval},
    identity::TimeSourceProtocol,
};

use crate::{CryptoError, signed_types::verify_time_attestation};

#[derive(Debug, thiserror::Error)]
pub enum TimeVerificationError {
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    #[error(transparent)]
    Time(#[from] TimeError),
    #[error("temporal witness authority is not the pinned authority")]
    AuthorityMismatch,
    #[error("temporal witness does not bind the requested content")]
    ContentMismatch,
    #[error("temporal witness does not bind the outstanding nonempty challenge")]
    ChallengeMismatch,
    #[error("temporal witness source protocol does not match the accepted protocol")]
    ProtocolMismatch,
    #[error("temporal witness uncertainty exceeds the accepted bound")]
    ExcessiveUncertainty,
}

/// Explicit acceptance inputs supplied by the composition's trust policy.
pub struct TimeWitnessRequest<'a> {
    pub authority: &'a Kappa,
    pub public_key: &'a [u8],
    pub content: &'a Kappa,
    pub nonce: &'a [u8],
    pub protocol: TimeSourceProtocol,
    pub max_uncertainty_ms: u64,
}

/// Signature-verified, policy-bound event witness. Private construction keeps
/// unverified timestamps from substituting for admitted evidence.
pub struct VerifiedTimeWitness {
    attestation: TimeAttestation,
    interval: TimeInterval,
}

impl VerifiedTimeWitness {
    pub fn admit(
        attestation: TimeAttestation,
        request: &TimeWitnessRequest<'_>,
    ) -> Result<Self, TimeVerificationError> {
        if &attestation.authority != request.authority {
            return Err(TimeVerificationError::AuthorityMismatch);
        }
        if &attestation.observed_kappa != request.content {
            return Err(TimeVerificationError::ContentMismatch);
        }
        if request.nonce.is_empty() || attestation.nonce.as_ref() != request.nonce {
            return Err(TimeVerificationError::ChallengeMismatch);
        }
        if attestation.source_protocol != request.protocol {
            return Err(TimeVerificationError::ProtocolMismatch);
        }
        if attestation.uncertainty_ms > request.max_uncertainty_ms {
            return Err(TimeVerificationError::ExcessiveUncertainty);
        }
        verify_time_attestation(&attestation, request.public_key)?;
        let interval = attestation.claimed_interval()?;
        Ok(Self {
            attestation,
            interval,
        })
    }

    pub fn attestation(&self) -> &TimeAttestation {
        &self.attestation
    }

    pub const fn interval(&self) -> TimeInterval {
        self.interval
    }
}
