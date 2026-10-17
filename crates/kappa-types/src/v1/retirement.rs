//! The governed decision to retire one storage instance of a namespace.
//!
//! A [`RetirementDecision`] is published as a record by an execution of
//! its governing namespace; that publication is the only authority for
//! releasing the target's storage. The record names exactly one instance
//! (the target namespace and its known incarnation), so a decision about
//! one instance never applies to a later instance of the same namespace.
//!
//! - [`Disposition::RetirePresent`]: the target's storage exists and its
//!   committed history ends at `observed_head`, which is required.
//! - [`Disposition::ReleaseLost`]: the target's storage is gone; the
//!   decision releases its ownership. `observed_head`, when present, is the
//!   last authenticated head known for it, not evidence of the current one.
//!
//! Decoding is strict: unknown keys, an unknown version, an unknown (all
//! zero) incarnation, a governing namespace equal to the target, a head
//! given in part, or a present-storage retirement without a head are all
//! rejected at the decode boundary, with the same rules construction
//! applies.

use dcbor::prelude::*;

use crate::error::StoreError;
use crate::kappa::Kappa;
use crate::wire_map::wire_map;

/// The only version of the record.
pub const RETIREMENT_DECISION_VERSION: u64 = 1;

/// What the decision does to the target instance.
/// Discriminants (PERMANENT): 0 retire present, 1 release lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    RetirePresent,
    ReleaseLost,
}

impl Disposition {
    pub(crate) const fn code(self) -> u64 {
        match self {
            Self::RetirePresent => 0,
            Self::ReleaseLost => 1,
        }
    }

    pub(crate) fn from_code(code: u64) -> Result<Self, StoreError> {
        match code {
            0 => Ok(Self::RetirePresent),
            1 => Ok(Self::ReleaseLost),
            other => Err(StoreError::Rejected(format!(
                "unknown retirement disposition {other}"
            ))),
        }
    }
}

/// An authenticated epoch head: its number and root identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedHead {
    pub epoch_number: u64,
    pub root: Kappa,
}

/// Wire shape. Keys (PERMANENT): 0 version, 1 governing namespace, 2
/// target namespace, 3 target incarnation, 4 disposition, 5 head epoch,
/// 6 head root, 7 request, 8 principal, 9 evidence.
struct RetirementDecisionWire {
    version: u64,
    governing: Vec<u8>,
    target: Vec<u8>,
    incarnation: Vec<u8>,
    disposition: u64,
    head_epoch: Option<u64>,
    head_root: Option<Kappa>,
    request: Kappa,
    principal: Kappa,
    evidence: Kappa,
}

wire_map!(RetirementDecisionWire {
    version: value = 0,
    governing: bytes = 1,
    target: bytes = 2,
    incarnation: bytes = 3,
    disposition: value = 4,
    head_epoch: optional = 5,
    head_root: optional = 6,
    request: value = 7,
    principal: value = 8,
    evidence: value = 9,
});

/// One governed retirement decision (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetirementDecision {
    governing: [u8; 16],
    target: [u8; 16],
    incarnation: [u8; 16],
    disposition: Disposition,
    observed_head: Option<ObservedHead>,
    request: Kappa,
    principal: Kappa,
    evidence: Kappa,
}

pub(crate) fn namespace_id(bytes: &[u8], what: &str) -> Result<[u8; 16], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Rejected(format!("retirement {what} is not 16 bytes")))
}

/// The instance rules every retirement record obeys, request and decision
/// alike.
pub(crate) fn validate_instance(
    governing: &[u8; 16],
    target: &[u8; 16],
    incarnation: &[u8; 16],
    disposition: Disposition,
    observed_head: Option<&ObservedHead>,
) -> Result<(), StoreError> {
    if governing == target {
        return Err(StoreError::Rejected(
            "a namespace cannot govern its own retirement".into(),
        ));
    }
    if *incarnation == [0; 16] {
        return Err(StoreError::Rejected(
            "retirement names an unknown incarnation".into(),
        ));
    }
    if disposition == Disposition::RetirePresent && observed_head.is_none() {
        return Err(StoreError::Rejected(
            "retiring present storage requires its observed head".into(),
        ));
    }
    if observed_head.is_some_and(|head| head.epoch_number == 0) {
        return Err(StoreError::Rejected(
            "an observed head has epoch number 0".into(),
        ));
    }
    Ok(())
}

/// The observed head two optional wire fields encode.
pub(crate) fn head_from_wire(
    epoch: Option<u64>,
    root: Option<Kappa>,
) -> Result<Option<ObservedHead>, StoreError> {
    match (epoch, root) {
        (Some(epoch_number), Some(root)) => Ok(Some(ObservedHead { epoch_number, root })),
        (None, None) => Ok(None),
        _ => Err(StoreError::Rejected(
            "retirement head names only one of its epoch and root".into(),
        )),
    }
}

pub(crate) fn head_to_wire(head: Option<ObservedHead>) -> (Option<u64>, Option<Kappa>) {
    head.map_or((None, None), |head| {
        (Some(head.epoch_number), Some(head.root))
    })
}

impl RetirementDecision {
    /// A validated decision.
    ///
    /// `request` is the canonical identity of the request that asked for
    /// the retirement; `principal` the anchor that authorized it;
    /// `evidence` the identity of the authorization evidence the governing
    /// publication admits.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        governing: [u8; 16],
        target: [u8; 16],
        incarnation: [u8; 16],
        disposition: Disposition,
        observed_head: Option<ObservedHead>,
        request: Kappa,
        principal: Kappa,
        evidence: Kappa,
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
            request,
            principal,
            evidence,
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
    pub const fn request(&self) -> &Kappa {
        &self.request
    }
    pub const fn principal(&self) -> &Kappa {
        &self.principal
    }
    pub const fn evidence(&self) -> &Kappa {
        &self.evidence
    }
}

impl From<RetirementDecision> for CBOR {
    fn from(value: RetirementDecision) -> Self {
        let (head_epoch, head_root) = head_to_wire(value.observed_head);
        RetirementDecisionWire {
            version: RETIREMENT_DECISION_VERSION,
            governing: value.governing.to_vec(),
            target: value.target.to_vec(),
            incarnation: value.incarnation.to_vec(),
            disposition: value.disposition.code(),
            head_epoch,
            head_root,
            request: value.request,
            principal: value.principal,
            evidence: value.evidence,
        }
        .into()
    }
}

impl From<&RetirementDecision> for CBOR {
    fn from(value: &RetirementDecision) -> Self {
        value.clone().into()
    }
}

impl TryFrom<CBOR> for RetirementDecision {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let wire = RetirementDecisionWire::try_from(cbor)?;
        let decode = || -> Result<Self, StoreError> {
            if wire.version != RETIREMENT_DECISION_VERSION {
                return Err(StoreError::Rejected(format!(
                    "unknown retirement decision version {}",
                    wire.version
                )));
            }
            let observed_head = head_from_wire(wire.head_epoch, wire.head_root)?;
            Self::new(
                namespace_id(&wire.governing, "governing namespace")?,
                namespace_id(&wire.target, "target namespace")?,
                namespace_id(&wire.incarnation, "incarnation")?,
                Disposition::from_code(wire.disposition)?,
                observed_head,
                wire.request,
                wire.principal,
                wire.evidence,
            )
        };
        decode().map_err(|error| dcbor::Error::msg(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    fn head() -> ObservedHead {
        ObservedHead {
            epoch_number: 4,
            root: Kappa::sha256(b"root"),
        }
    }

    fn decision(
        disposition: Disposition,
        head: Option<ObservedHead>,
    ) -> Result<RetirementDecision, StoreError> {
        RetirementDecision::new(
            [1; 16],
            [2; 16],
            [3; 16],
            disposition,
            head,
            Kappa::sha256(b"request"),
            Kappa::sha256(b"principal"),
            Kappa::sha256(b"evidence"),
        )
    }

    #[test]
    fn decisions_roundtrip() -> Result<(), StoreError> {
        for value in [
            decision(Disposition::RetirePresent, Some(head()))?,
            decision(Disposition::ReleaseLost, Some(head()))?,
            decision(Disposition::ReleaseLost, None)?,
        ] {
            let decoded: RetirementDecision = from_canonical(&canonical_bytes(&value))?;
            assert_eq!(decoded, value);
        }
        Ok(())
    }

    #[test]
    fn construction_refuses_invalid_decisions() {
        assert!(decision(Disposition::RetirePresent, None).is_err());
        let zero_head = ObservedHead {
            epoch_number: 0,
            root: Kappa::sha256(b"root"),
        };
        assert!(decision(Disposition::ReleaseLost, Some(zero_head)).is_err());
        let own = RetirementDecision::new(
            [1; 16],
            [1; 16],
            [3; 16],
            Disposition::ReleaseLost,
            None,
            Kappa::sha256(b"r"),
            Kappa::sha256(b"p"),
            Kappa::sha256(b"e"),
        );
        assert!(own.is_err());
        let unknown = RetirementDecision::new(
            [1; 16],
            [2; 16],
            [0; 16],
            Disposition::ReleaseLost,
            None,
            Kappa::sha256(b"r"),
            Kappa::sha256(b"p"),
            Kappa::sha256(b"e"),
        );
        assert!(unknown.is_err());
    }

    #[test]
    fn decoding_enforces_the_construction_rules() -> Result<(), StoreError> {
        let valid = decision(Disposition::RetirePresent, Some(head()))?;
        let encode = |edit: &dyn Fn(&mut Map)| {
            let CBORCase::Map(mut map) = CBOR::from(&valid).into_case() else {
                return Vec::new();
            };
            edit(&mut map);
            CBOR::from(map).to_cbor_data()
        };
        let decodes = |bytes: &[u8]| from_canonical::<RetirementDecision>(bytes).is_ok();
        assert!(decodes(&encode(&|_| {})));
        assert!(
            !decodes(&encode(&|map| map.insert(0u64, 2u64))),
            "unknown version"
        );
        assert!(
            !decodes(&encode(&|map| map.insert(10u64, 1u64))),
            "unknown key"
        );
        assert!(
            !decodes(&encode(&|map| map.insert(4u64, 7u64))),
            "unknown disposition"
        );
        assert!(
            !decodes(&encode(
                &|map| map.insert(3u64, ByteString::from(vec![0u8; 16]))
            )),
            "unknown incarnation"
        );
        assert!(
            !decodes(&encode(
                &|map| map.insert(1u64, ByteString::from(vec![2u8; 16]))
            )),
            "self-governed"
        );
        assert!(
            !decodes(&encode(
                &|map| map.insert(2u64, ByteString::from(vec![2u8; 15]))
            )),
            "short namespace"
        );
        let without_root = |map: &mut Map| {
            let mut rebuilt = Map::new();
            for (key, value) in map.iter() {
                if key != &CBOR::from(6u64) {
                    rebuilt.insert(key.clone(), value.clone());
                }
            }
            *map = rebuilt;
        };
        assert!(!decodes(&encode(&without_root)), "partial head");
        // A present-storage retirement without its head.
        let headless = |map: &mut Map| {
            let mut rebuilt = Map::new();
            for (key, value) in map.iter() {
                if key != &CBOR::from(5u64) && key != &CBOR::from(6u64) {
                    rebuilt.insert(key.clone(), value.clone());
                }
            }
            *map = rebuilt;
        };
        assert!(
            !decodes(&encode(&headless)),
            "present retirement without a head"
        );
        Ok(())
    }
}
