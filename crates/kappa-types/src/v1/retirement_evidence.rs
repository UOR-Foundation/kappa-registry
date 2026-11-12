//! The target-authenticated authority evidence of a retirement decision.
//!
//! A [`RetirementEvidence`] record names, by identity, the evidence that
//! proves who controlled one target namespace at the head a retirement
//! request names:
//!
//! - `epochs`: the target's signed epoch roots from that head back to the
//!   epoch whose ledger last recorded the namespace record (a
//!   `NamespaceUpdate`), newest first. Each root commits its ledger, so the
//!   ledgers are named through the roots.
//! - `record`: the canonical namespace record that last `NamespaceUpdate`
//!   names.
//! - `delegation`: when the principal is not the controlling authority
//!   itself, the signed delegation chain from that authority to the
//!   principal, each link with the delegator's verification key.
//!
//! The governing namespace publishes every named record with the decision,
//! so the evidence verifies from the governing namespace alone, after the
//! target's own storage is gone. What the evidence authorizes is decided
//! by `kappa_store::governed_retirement`.
//!
//! Decoding is strict: an unknown version or key, a target that is not 16
//! bytes, no epoch or more than [`MAX_EVIDENCE_EPOCHS`], a delegation chain
//! longer than [`crate::DELEGATION_CHAIN_MAX_DEPTH`], or a link whose key
//! does not derive its delegator are refused at the decode boundary.

use dcbor::prelude::*;

use crate::delegation::{DELEGATION_CHAIN_MAX_DEPTH, DelegationScope};
use crate::error::StoreError;
use crate::kappa::Kappa;
use crate::retirement::namespace_id;
use crate::wire_map::wire_map;

/// The only version of the record.
pub const RETIREMENT_EVIDENCE_VERSION: u64 = 1;

/// Most target epochs one evidence record names: the head and the epochs
/// back to the one that recorded the namespace record.
pub const MAX_EVIDENCE_EPOCHS: usize = 256;

/// One link of a delegation chain with the verification key of its
/// delegator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DelegationLink {
    scope: DelegationScope,
    algorithm: String,
    public_key: Vec<u8>,
}

/// Wire shape. Keys (PERMANENT): 0 scope, 1 algorithm, 2 public key.
struct DelegationLinkWire {
    scope: DelegationScope,
    algorithm: String,
    public_key: Vec<u8>,
}

wire_map!(DelegationLinkWire {
    scope: value = 0,
    algorithm: value = 1,
    public_key: bytes = 2,
});

impl DelegationLink {
    /// A link whose key derives the scope's delegator.
    pub fn new(
        scope: DelegationScope,
        algorithm: &str,
        public_key: &[u8],
    ) -> Result<Self, StoreError> {
        if Kappa::from_key(algorithm, public_key)? != scope.delegator {
            return Err(StoreError::Rejected(
                "delegation link key does not derive its delegator".into(),
            ));
        }
        Ok(Self {
            scope,
            algorithm: algorithm.to_owned(),
            public_key: public_key.to_vec(),
        })
    }

    pub const fn scope(&self) -> &DelegationScope {
        &self.scope
    }
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

impl From<DelegationLink> for CBOR {
    fn from(value: DelegationLink) -> Self {
        DelegationLinkWire {
            scope: value.scope,
            algorithm: value.algorithm,
            public_key: value.public_key,
        }
        .into()
    }
}

impl TryFrom<CBOR> for DelegationLink {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let wire = DelegationLinkWire::try_from(cbor)?;
        Self::new(wire.scope, &wire.algorithm, &wire.public_key)
            .map_err(|error| dcbor::Error::msg(error.to_string()))
    }
}

/// Wire shape. Keys (PERMANENT): 0 version, 1 target namespace, 2 epochs
/// (newest first), 3 namespace record, 4 delegation chain.
struct RetirementEvidenceWire {
    version: u64,
    target: Vec<u8>,
    epochs: Vec<Kappa>,
    record: Kappa,
    delegation: Vec<DelegationLink>,
}

wire_map!(RetirementEvidenceWire {
    version: value = 0,
    target: bytes = 1,
    epochs: value = 2,
    record: value = 3,
    delegation: value = 4,
});

/// The authority evidence of one decision (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetirementEvidence {
    target: [u8; 16],
    epochs: Vec<Kappa>,
    record: Kappa,
    delegation: Vec<DelegationLink>,
}

impl RetirementEvidence {
    /// A validated evidence record.
    pub fn new(
        target: [u8; 16],
        epochs: Vec<Kappa>,
        record: Kappa,
        delegation: Vec<DelegationLink>,
    ) -> Result<Self, StoreError> {
        if epochs.is_empty() {
            return Err(StoreError::Rejected(
                "retirement evidence names no target epoch".into(),
            ));
        }
        if epochs.len() > MAX_EVIDENCE_EPOCHS {
            return Err(StoreError::CapacityExceeded(format!(
                "retirement evidence names {} target epochs, at most {MAX_EVIDENCE_EPOCHS}",
                epochs.len()
            )));
        }
        let depth = u32::try_from(delegation.len()).unwrap_or(u32::MAX);
        if depth > DELEGATION_CHAIN_MAX_DEPTH {
            return Err(StoreError::Rejected(format!(
                "retirement delegation chain of {} links exceeds {DELEGATION_CHAIN_MAX_DEPTH}",
                delegation.len()
            )));
        }
        Ok(Self {
            target,
            epochs,
            record,
            delegation,
        })
    }

    pub const fn target(&self) -> &[u8; 16] {
        &self.target
    }
    /// The target's epoch roots, newest (the observed head) first.
    pub fn epochs(&self) -> &[Kappa] {
        &self.epochs
    }
    /// The namespace record the oldest epoch's ledger last recorded.
    pub const fn record(&self) -> &Kappa {
        &self.record
    }
    pub fn delegation(&self) -> &[DelegationLink] {
        &self.delegation
    }
}

impl From<RetirementEvidence> for CBOR {
    fn from(value: RetirementEvidence) -> Self {
        RetirementEvidenceWire {
            version: RETIREMENT_EVIDENCE_VERSION,
            target: value.target.to_vec(),
            epochs: value.epochs,
            record: value.record,
            delegation: value.delegation,
        }
        .into()
    }
}

impl From<&RetirementEvidence> for CBOR {
    fn from(value: &RetirementEvidence) -> Self {
        value.clone().into()
    }
}

impl TryFrom<CBOR> for RetirementEvidence {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let wire = RetirementEvidenceWire::try_from(cbor)?;
        let decode = || -> Result<Self, StoreError> {
            if wire.version != RETIREMENT_EVIDENCE_VERSION {
                return Err(StoreError::Rejected(format!(
                    "unknown retirement evidence version {}",
                    wire.version
                )));
            }
            Self::new(
                namespace_id(&wire.target, "evidence target")?,
                wire.epochs,
                wire.record,
                wire.delegation,
            )
        };
        decode().map_err(|error| dcbor::Error::msg(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};
    use crate::signed::SignedPayload;

    const KEY: [u8; 32] = [5; 32];

    fn link() -> Result<DelegationLink, StoreError> {
        let delegator = Kappa::from_key("ed25519", &KEY)?;
        DelegationLink::new(
            DelegationScope {
                delegator,
                delegate: Kappa::sha256(b"delegate"),
                scope: vec!["namespace:retire".into()],
                namespaces: None,
                valid_from_ms: 1,
                valid_until_ms: None,
                max_depth: 0,
                nonce: vec![1],
                cose_signature: SignedPayload::empty(),
            },
            "ed25519",
            &KEY,
        )
    }

    fn evidence(epochs: usize, links: usize) -> Result<RetirementEvidence, StoreError> {
        let mut delegation = Vec::new();
        for _ in 0..links {
            delegation.push(link()?);
        }
        RetirementEvidence::new(
            [2; 16],
            (0..epochs)
                .map(|i| Kappa::sha256(&i.to_be_bytes()))
                .collect(),
            Kappa::sha256(b"record"),
            delegation,
        )
    }

    #[test]
    fn evidence_roundtrips() -> Result<(), StoreError> {
        for value in [evidence(1, 0)?, evidence(3, 1)?] {
            let decoded: RetirementEvidence = from_canonical(&canonical_bytes(&value))?;
            assert_eq!(decoded, value);
        }
        Ok(())
    }

    #[test]
    fn construction_bounds_epochs_and_delegation() -> Result<(), StoreError> {
        assert!(evidence(0, 0).is_err(), "no epoch");
        assert!(evidence(MAX_EVIDENCE_EPOCHS, 0).is_ok());
        assert!(
            evidence(MAX_EVIDENCE_EPOCHS + 1, 0).is_err(),
            "too many epochs"
        );
        let depth = usize::try_from(DELEGATION_CHAIN_MAX_DEPTH)
            .map_err(|error| StoreError::Internal(error.to_string()))?;
        assert!(evidence(1, depth).is_ok());
        assert!(evidence(1, depth + 1).is_err(), "delegation too deep");
        Ok(())
    }

    #[test]
    fn a_link_key_must_derive_its_delegator() -> Result<(), StoreError> {
        let valid = link()?;
        assert!(DelegationLink::new(valid.scope().clone(), "ed25519", &[6; 32]).is_err());
        Ok(())
    }

    #[test]
    fn decoding_refuses_unknown_versions_and_keys() -> Result<(), StoreError> {
        let valid = evidence(2, 0)?;
        let encode = |key: u64, value: CBOR| {
            let CBORCase::Map(mut map) = CBOR::from(&valid).into_case() else {
                return Vec::new();
            };
            map.insert(key, value);
            CBOR::from(map).to_cbor_data()
        };
        assert!(from_canonical::<RetirementEvidence>(&encode(0, CBOR::from(2u64))).is_err());
        assert!(from_canonical::<RetirementEvidence>(&encode(5, CBOR::from(1u64))).is_err());
        let empty: Vec<Kappa> = Vec::new();
        assert!(from_canonical::<RetirementEvidence>(&encode(2, CBOR::from(empty))).is_err());
        Ok(())
    }
}
