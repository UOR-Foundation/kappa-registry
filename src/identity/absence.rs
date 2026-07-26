//! Absence proofs via AKD NonMembershipProof.
//!
//! Proves that a specific asserter has NOT made an assertion about a
//! subject on a facet at a specific epoch. The proof is per-asserter
//! (absence is only ever issuer-scoped -- the system can never answer
//! "nobody has asserted X," only "this asserter has not").

use serde::{Deserialize, Serialize};

/// A proof that an assertion does not exist in an asserter's AKD tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbsenceProof {
    /// The asserter's namespace identifier.
    pub asserter_ns: String,
    /// The epoch at which absence is proven.
    pub epoch: u64,
    /// Kappa of the signed epoch root at this epoch.
    pub epoch_root_kappa: String,
    /// VRF proof bytes proving the label derivation from subject+facet.
    /// Verifier can check that the label was correctly derived without
    /// knowing the VRF private key.
    pub vrf_proof: Vec<u8>,
    /// AKD NonMembershipProof serialized bytes.
    /// The verifier checks this against the epoch root's AKD tree root.
    pub non_membership_proof: Vec<u8>,
}

impl AbsenceProof {
    /// The label that was proven absent.
    ///
    /// This is derived from the VRF proof and can be independently
    /// verified by the relying party using the VRF public key.
    /// The label is VRF(vrf_key, subject || "/" || facet).
    ///
    /// Returning the label here requires the VRF public key and
    /// proof verification, which is done at the handler level.
    /// This struct is the wire format only.
    pub fn asserter_ns(&self) -> &str {
        &self.asserter_ns
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absence_proof_serialization_roundtrip() {
        let proof = AbsenceProof {
            asserter_ns: "test-ns".to_owned(),
            epoch: 42,
            epoch_root_kappa: "sha256:abc".to_owned(),
            vrf_proof: vec![1, 2, 3],
            non_membership_proof: vec![4, 5, 6],
        };
        let json = serde_json::to_vec(&proof).unwrap();
        let parsed: AbsenceProof = serde_json::from_slice(&json).unwrap();
        assert_eq!(parsed.asserter_ns, "test-ns");
        assert_eq!(parsed.epoch, 42);
        assert_eq!(parsed.epoch_root_kappa, "sha256:abc");
        assert_eq!(parsed.vrf_proof, vec![1, 2, 3]);
        assert_eq!(parsed.non_membership_proof, vec![4, 5, 6]);
    }
}
