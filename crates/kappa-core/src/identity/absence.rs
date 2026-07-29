//! Absence proofs: cryptographic evidence that no assertion exists.
//!
//! An absence proof demonstrates that no assertion about a given
//! subject on a given facet has ever been made. This is produced by
//! the AKD (Auditable Key Directory) as a non-membership proof.

use dcbor::prelude::*;

/// CBOR key assignments (PERMANENT):
///   0: subject (text)
///   1: facet (text)
///   2: epoch (unsigned, the epoch at which absence was proven)
///   3: proof_bytes (bytes, the AKD non-membership proof)
///   4: epoch_root_kappa (text, the epoch root this proof is relative to)
#[derive(Debug, Clone, CBORCodable)]
pub struct AbsenceProof {
    #[cbor(n = 0)]
    pub subject: String,
    #[cbor(n = 1)]
    pub facet: String,
    #[cbor(n = 2)]
    pub epoch: u64,
    #[cbor(n = 3)]
    pub proof_bytes: Vec<u8>,
    #[cbor(n = 4)]
    pub epoch_root_kappa: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    #[test]
    fn absence_proof_roundtrip() {
        let proof = AbsenceProof {
            subject: "sha256:subject".into(),
            facet: "sanctions/ofac".into(),
            epoch: 42,
            proof_bytes: vec![1, 2, 3, 4, 5],
            epoch_root_kappa: "sha256:epoch_root".into(),
        };
        let bytes = canonical_bytes(&proof);
        let decoded: AbsenceProof = from_canonical(&bytes).unwrap();
        assert_eq!(decoded.subject, proof.subject);
        assert_eq!(decoded.facet, proof.facet);
        assert_eq!(decoded.epoch, proof.epoch);
        assert_eq!(decoded.proof_bytes, proof.proof_bytes);
        assert_eq!(decoded.epoch_root_kappa, proof.epoch_root_kappa);
    }
}
