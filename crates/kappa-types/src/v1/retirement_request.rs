//! The principal's signed request to retire one storage instance.
//!
//! A [`RetirementRequest`] is the authorization evidence of a
//! [`crate::retirement::RetirementDecision`]: the principal signs, with the
//! key its anchor derives from, exactly the instance, disposition and head
//! the decision then carries. Whoever can write the governing namespace can
//! publish a decision record naming any principal; only the principal can
//! produce the signature, so a decision is authorized only when its
//! request verifies and corresponds field by field.
//!
//! The request carries the principal's algorithm and public key, so it is
//! verified from its own bytes: the signature envelope binds the anchor,
//! and the anchor must derive from the key (`kappa_crypto::cose::verify`).
//!
//! Decoding is strict and applies the decision's instance rules.

use dcbor::prelude::*;

use crate::error::StoreError;
use crate::kappa::Kappa;
use crate::retirement::{
    Disposition, ObservedHead, RETIREMENT_DECISION_VERSION, head_from_wire, head_to_wire,
    namespace_id, validate_instance,
};
use crate::signed::SignedPayload;
use crate::wire_map::wire_map;

/// Wire shape. Keys (PERMANENT): 0 version, 1 governing namespace, 2
/// target namespace, 3 target incarnation, 4 disposition, 5 head epoch,
/// 6 head root, 7 issued at, 8 principal, 9 algorithm, 10 public key,
/// 11 signature. The signed payload is keys 0-10.
struct RequestWire {
    version: u64,
    governing: Vec<u8>,
    target: Vec<u8>,
    incarnation: Vec<u8>,
    disposition: u64,
    head_epoch: Option<u64>,
    head_root: Option<Kappa>,
    issued_at_ms: i64,
    principal: Kappa,
    algorithm: String,
    public_key: Vec<u8>,
    cose_signature: SignedPayload,
}

wire_map!(RequestWire {
    version: value = 0,
    governing: bytes = 1,
    target: bytes = 2,
    incarnation: bytes = 3,
    disposition: value = 4,
    head_epoch: optional = 5,
    head_root: optional = 6,
    issued_at_ms: value = 7,
    principal: value = 8,
    algorithm: value = 9,
    public_key: bytes = 10,
    cose_signature: value = 11,
});

#[derive(Clone)]
struct SignableWire {
    version: u64,
    governing: Vec<u8>,
    target: Vec<u8>,
    incarnation: Vec<u8>,
    disposition: u64,
    head_epoch: Option<u64>,
    head_root: Option<Kappa>,
    issued_at_ms: i64,
    principal: Kappa,
    algorithm: String,
    public_key: Vec<u8>,
}

wire_map!(SignableWire {
    version: value = 0,
    governing: bytes = 1,
    target: bytes = 2,
    incarnation: bytes = 3,
    disposition: value = 4,
    head_epoch: optional = 5,
    head_root: optional = 6,
    issued_at_ms: value = 7,
    principal: value = 8,
    algorithm: value = 9,
    public_key: bytes = 10,
});

/// A principal's signed request (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetirementRequest {
    governing: [u8; 16],
    target: [u8; 16],
    incarnation: [u8; 16],
    disposition: Disposition,
    observed_head: Option<ObservedHead>,
    issued_at_ms: i64,
    principal: Kappa,
    algorithm: String,
    public_key: Vec<u8>,
    /// `COSE_Sign1` by the principal over [`Self::signable_bytes`]; set by
    /// `kappa_crypto::signed_types::sign_retirement_request`.
    pub cose_signature: SignedPayload,
}

impl RetirementRequest {
    /// An unsigned request. The principal anchor must derive from
    /// `algorithm` and `public_key`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        governing: [u8; 16],
        target: [u8; 16],
        incarnation: [u8; 16],
        disposition: Disposition,
        observed_head: Option<ObservedHead>,
        issued_at_ms: i64,
        algorithm: &str,
        public_key: &[u8],
    ) -> Result<Self, StoreError> {
        validate_instance(
            &governing,
            &target,
            &incarnation,
            disposition,
            observed_head.as_ref(),
        )?;
        Ok(Self {
            governing,
            target,
            incarnation,
            disposition,
            observed_head,
            issued_at_ms,
            principal: Kappa::from_key(algorithm, public_key)?,
            algorithm: algorithm.to_owned(),
            public_key: public_key.to_vec(),
            cose_signature: SignedPayload::empty(),
        })
    }

    pub const fn governing(&self) -> &[u8; 16] {
        &self.governing
    }
    pub const fn target(&self) -> &[u8; 16] {
        &self.target
    }
    pub const fn incarnation(&self) -> &[u8; 16] {
        &self.incarnation
    }
    pub const fn disposition(&self) -> Disposition {
        self.disposition
    }
    pub const fn observed_head(&self) -> Option<&ObservedHead> {
        self.observed_head.as_ref()
    }
    pub const fn issued_at_ms(&self) -> i64 {
        self.issued_at_ms
    }
    pub const fn principal(&self) -> &Kappa {
        &self.principal
    }
    pub fn algorithm(&self) -> &str {
        &self.algorithm
    }
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Canonical dCBOR of every field but the signature: the payload the
    /// principal signs.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let (head_epoch, head_root) = head_to_wire(self.observed_head.clone());
        crate::canonical::canonical_bytes(&SignableWire {
            version: RETIREMENT_DECISION_VERSION,
            governing: self.governing.to_vec(),
            target: self.target.to_vec(),
            incarnation: self.incarnation.to_vec(),
            disposition: self.disposition.code(),
            head_epoch,
            head_root,
            issued_at_ms: self.issued_at_ms,
            principal: self.principal.clone(),
            algorithm: self.algorithm.clone(),
            public_key: self.public_key.clone(),
        })
    }
}

impl From<RetirementRequest> for CBOR {
    fn from(value: RetirementRequest) -> Self {
        let (head_epoch, head_root) = head_to_wire(value.observed_head);
        RequestWire {
            version: RETIREMENT_DECISION_VERSION,
            governing: value.governing.to_vec(),
            target: value.target.to_vec(),
            incarnation: value.incarnation.to_vec(),
            disposition: value.disposition.code(),
            head_epoch,
            head_root,
            issued_at_ms: value.issued_at_ms,
            principal: value.principal,
            algorithm: value.algorithm,
            public_key: value.public_key,
            cose_signature: value.cose_signature,
        }
        .into()
    }
}

impl From<&RetirementRequest> for CBOR {
    fn from(value: &RetirementRequest) -> Self {
        value.clone().into()
    }
}

impl TryFrom<CBOR> for RetirementRequest {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let wire = RequestWire::try_from(cbor)?;
        let decode = || -> Result<Self, StoreError> {
            if wire.version != RETIREMENT_DECISION_VERSION {
                return Err(StoreError::Rejected(format!(
                    "unknown retirement request version {}",
                    wire.version
                )));
            }
            let mut request = Self::new(
                namespace_id(&wire.governing, "governing namespace")?,
                namespace_id(&wire.target, "target namespace")?,
                namespace_id(&wire.incarnation, "incarnation")?,
                Disposition::from_code(wire.disposition)?,
                head_from_wire(wire.head_epoch, wire.head_root)?,
                wire.issued_at_ms,
                &wire.algorithm,
                &wire.public_key,
            )?;
            if request.principal != wire.principal {
                return Err(StoreError::Rejected(
                    "retirement request principal does not derive from its key".into(),
                ));
            }
            request.cose_signature = wire.cose_signature;
            Ok(request)
        };
        decode().map_err(|error| dcbor::Error::msg(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    fn request() -> Result<RetirementRequest, StoreError> {
        RetirementRequest::new(
            [1; 16],
            [2; 16],
            [3; 16],
            Disposition::ReleaseLost,
            None,
            7,
            "ed25519",
            &[9; 32],
        )
    }

    #[test]
    fn requests_roundtrip_and_sign_everything_but_the_signature() -> Result<(), StoreError> {
        let mut value = request()?;
        let unsigned = value.signable_bytes();
        value.cose_signature = SignedPayload::from_cose_bytes(vec![1, 2, 3]);
        assert_eq!(
            value.signable_bytes(),
            unsigned,
            "the signature is not signed"
        );
        let decoded: RetirementRequest = from_canonical(&canonical_bytes(&value))?;
        assert_eq!(decoded, value);
        Ok(())
    }

    #[test]
    fn a_principal_not_derived_from_the_key_is_rejected_at_decode() -> Result<(), StoreError> {
        let value = request()?;
        let CBORCase::Map(mut map) = CBOR::from(&value).into_case() else {
            return Err(StoreError::Internal("a request encodes as a map".into()));
        };
        map.insert(8u64, Kappa::sha256(b"someone else"));
        assert!(from_canonical::<RetirementRequest>(&CBOR::from(map).to_cbor_data()).is_err());
        Ok(())
    }

    #[test]
    fn requests_obey_the_instance_rules() {
        let retire = |governing: [u8; 16], incarnation: [u8; 16], head: Option<ObservedHead>| {
            RetirementRequest::new(
                governing,
                [2; 16],
                incarnation,
                Disposition::RetirePresent,
                head,
                7,
                "ed25519",
                &[9; 32],
            )
        };
        let head = ObservedHead {
            epoch_number: 3,
            root: Kappa::sha256(b"root"),
        };
        assert!(retire([1; 16], [3; 16], Some(head.clone())).is_ok());
        assert!(retire([1; 16], [3; 16], None).is_err());
        assert!(retire([2; 16], [3; 16], Some(head.clone())).is_err());
        assert!(retire([1; 16], [0; 16], Some(head)).is_err());
    }
}
