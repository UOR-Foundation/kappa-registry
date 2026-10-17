//! The value a rotation witness signs.
//!
//! An authority rotation activates only with at least one countersignature
//! by a party distinct from both the outgoing and the incoming authority:
//! an [`crate::identity::IdentityAssertion`] whose
//!
//! - subject is the canonical string of the SHA-256 identity of the
//!   complete canonical, dual-signed succession record;
//! - facet is [`ROTATION_WITNESS_FACET`] and basis
//!   [`ROTATION_WITNESS_BASIS`];
//! - value is the canonical [`RotationWitness`], binding the authority
//!   domain the rotation activates in: the control namespace and its
//!   incarnation, the lineage's origin anchor, and the succession identity
//!   again.
//!
//! The witness never names the activation epoch: that epoch carries the
//! witness, so naming it would be circular. A witness proves a separate
//! signer, not organizational independence.
//!
//! Decoding is strict: unknown keys, an unknown version and an unknown
//! (all zero) incarnation are rejected.

use dcbor::prelude::*;

use crate::error::StoreError;
use crate::kappa::Kappa;
use crate::retirement::namespace_id;
use crate::wire_map::wire_map;

/// The facet of every rotation witness assertion.
pub const ROTATION_WITNESS_FACET: &str = "rotation-witness";
/// The basis of every rotation witness assertion.
pub const ROTATION_WITNESS_BASIS: &str = "kappa-authority-rotation-v1";
/// The only version of the value.
pub const ROTATION_WITNESS_VERSION: u64 = 1;

/// Wire shape. Keys (PERMANENT): 0 version, 1 control namespace, 2
/// control incarnation, 3 origin anchor, 4 succession.
struct RotationWitnessWire {
    version: u64,
    control: Vec<u8>,
    incarnation: Vec<u8>,
    origin: Kappa,
    succession: Kappa,
}

wire_map!(RotationWitnessWire {
    version: value = 0,
    control: bytes = 1,
    incarnation: bytes = 2,
    origin: value = 3,
    succession: value = 4,
});

/// The domain a rotation activates in: the control namespace's identity
/// and incarnation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationDomain {
    pub control: [u8; 16],
    pub incarnation: [u8; 16],
}

/// The witness value (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationWitness {
    domain: ActivationDomain,
    origin: Kappa,
    succession: Kappa,
}

impl RotationWitness {
    pub fn new(
        domain: ActivationDomain,
        origin: Kappa,
        succession: Kappa,
    ) -> Result<Self, StoreError> {
        if domain.incarnation == [0; 16] {
            return Err(StoreError::Rejected(
                "rotation witness names an unknown control incarnation".into(),
            ));
        }
        Ok(Self {
            domain,
            origin,
            succession,
        })
    }

    pub const fn domain(&self) -> &ActivationDomain {
        &self.domain
    }
    pub const fn origin(&self) -> &Kappa {
        &self.origin
    }
    pub const fn succession(&self) -> &Kappa {
        &self.succession
    }
}

impl From<RotationWitness> for CBOR {
    fn from(value: RotationWitness) -> Self {
        RotationWitnessWire {
            version: ROTATION_WITNESS_VERSION,
            control: value.domain.control.to_vec(),
            incarnation: value.domain.incarnation.to_vec(),
            origin: value.origin,
            succession: value.succession,
        }
        .into()
    }
}

impl From<&RotationWitness> for CBOR {
    fn from(value: &RotationWitness) -> Self {
        value.clone().into()
    }
}

impl TryFrom<CBOR> for RotationWitness {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let wire = RotationWitnessWire::try_from(cbor)?;
        let decode = || -> Result<Self, StoreError> {
            if wire.version != ROTATION_WITNESS_VERSION {
                return Err(StoreError::Rejected(format!(
                    "unknown rotation witness version {}",
                    wire.version
                )));
            }
            Self::new(
                ActivationDomain {
                    control: namespace_id(&wire.control, "control namespace")?,
                    incarnation: namespace_id(&wire.incarnation, "control incarnation")?,
                },
                wire.origin,
                wire.succession,
            )
        };
        decode().map_err(|error| dcbor::Error::msg(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    fn witness() -> Result<RotationWitness, StoreError> {
        RotationWitness::new(
            ActivationDomain {
                control: [1; 16],
                incarnation: [2; 16],
            },
            Kappa::sha256(b"origin"),
            Kappa::sha256(b"succession"),
        )
    }

    #[test]
    fn the_value_roundtrips_and_decodes_strictly() -> Result<(), StoreError> {
        let value = witness()?;
        let bytes = canonical_bytes(&value);
        assert_eq!(from_canonical::<RotationWitness>(&bytes)?, value);
        let CBORCase::Map(map) = CBOR::from(&value).into_case() else {
            return Err(StoreError::Internal("a witness encodes as a map".into()));
        };
        let with = |key: u64, item: CBOR| {
            let mut changed = map.clone();
            changed.insert(key, item);
            CBOR::from(changed).to_cbor_data()
        };
        assert!(from_canonical::<RotationWitness>(&with(0, CBOR::from(2u64))).is_err());
        assert!(from_canonical::<RotationWitness>(&with(5, CBOR::from(1u64))).is_err());
        assert!(
            from_canonical::<RotationWitness>(&with(
                2,
                CBOR::from(ByteString::from(vec![0u8; 16]))
            ))
            .is_err()
        );
        Ok(())
    }
}
