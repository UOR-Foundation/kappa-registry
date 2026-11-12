//! The guarantees a plane provides and a namespace requires, and the
//! admitted assignment of a namespace to a plane.
//!
//! A guarantee set is carried as one bit per [`Guarantee`]; the canonical
//! encoding is the unsigned integer of those bits, and a decoder refuses
//! any bit no guarantee defines, so a record requiring a guarantee this
//! node does not know is never read as requiring less.

use std::fmt;

use dcbor::prelude::CBORCodable;
use kappa_store::error::StoreError;

use super::ControlPlaneId;

/// One property an agreement mechanism may guarantee for a decided
/// proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Guarantee {
    /// Decided proposals form one total order per namespace.
    TotalOrder,
    /// A decided proposal survives the loss of this node.
    Replicated,
    /// A proposer of an older configuration generation cannot have a
    /// proposal decided after a newer generation was activated.
    Fenced,
    /// Reads served by this node observe every decided proposal.
    LinearizableReads,
}

impl Guarantee {
    /// Every guarantee, in bit order.
    pub const ALL: [Self; 4] = [
        Self::TotalOrder,
        Self::Replicated,
        Self::Fenced,
        Self::LinearizableReads,
    ];

    const fn bit(self) -> u8 {
        match self {
            Self::TotalOrder => 1,
            Self::Replicated => 1 << 1,
            Self::Fenced => 1 << 2,
            Self::LinearizableReads => 1 << 3,
        }
    }
}

/// A set of [`Guarantee`]s.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Guarantees(u8);

impl Guarantees {
    /// The empty set.
    pub const NONE: Self = Self(0);
    /// Every bit a guarantee defines.
    const DEFINED: u8 = 0b1111;

    /// This set with `guarantee` added.
    #[must_use]
    pub const fn with(self, guarantee: Guarantee) -> Self {
        Self(self.0 | guarantee.bit())
    }

    /// Whether this set holds `guarantee`.
    pub const fn provides(self, guarantee: Guarantee) -> bool {
        self.0 & guarantee.bit() != 0
    }

    /// Whether `self` provides everything `required` asks for.
    pub const fn satisfies(self, required: Self) -> bool {
        required.0 & !self.0 == 0
    }

    /// The canonical bits of this set.
    pub const fn bits(self) -> u8 {
        self.0
    }

    /// The set whose canonical bits are `bits`; refused when a bit names
    /// no guarantee.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::DEFINED == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }
}

impl fmt::Debug for Guarantees {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_set()
            .entries(
                Guarantee::ALL
                    .iter()
                    .filter(|guarantee| self.provides(**guarantee)),
            )
            .finish()
    }
}

impl From<Guarantees> for dcbor::CBOR {
    fn from(value: Guarantees) -> Self {
        Self::from(value.0)
    }
}

impl TryFrom<dcbor::CBOR> for Guarantees {
    type Error = dcbor::Error;

    fn try_from(cbor: dcbor::CBOR) -> Result<Self, Self::Error> {
        let bits: u8 = cbor.try_into()?;
        Self::from_bits(bits).ok_or_else(|| {
            dcbor::Error::msg(format!(
                "guarantee set {bits:#06b} names an undefined guarantee"
            ))
        })
    }
}

/// The admitted assignment of a namespace to a plane.
///
/// Recorded in the namespace's own database under `ASSIGNMENT_KEY` and
/// settled into the registry's assignment projection
/// (`projection::Family::Assignment`).
#[derive(Clone, Debug, PartialEq, Eq, CBORCodable)]
pub struct AssignmentRecord {
    #[cbor(n = 0)]
    pub namespace_id: Vec<u8>,
    #[cbor(n = 1)]
    pub plane: Vec<u8>,
    /// Assignment generation: increases with every reassignment of the
    /// namespace and fences proposals made under the previous plane.
    #[cbor(n = 2)]
    pub generation: u64,
    /// The guarantees the namespace requires of its plane.
    #[cbor(n = 3)]
    pub requires: Guarantees,
}

impl AssignmentRecord {
    pub fn plane_id(&self) -> Result<ControlPlaneId, StoreError> {
        <[u8; 16]>::try_from(self.plane.as_slice())
            .map(ControlPlaneId)
            .map_err(|_| StoreError::Rejected("assignment names no plane".into()))
    }
}

/// Bytes of an assignment's settled projection value.
pub const ASSIGNMENT_BYTES: usize = 24;

/// `[plane:16][generation:8 BE]`, the settled projection value: the one
/// writer of the format, into a fixed array.
pub fn assignment_bytes(plane: ControlPlaneId, generation: u64) -> [u8; ASSIGNMENT_BYTES] {
    let mut bytes = [0; ASSIGNMENT_BYTES];
    bytes[..16].copy_from_slice(&plane.0);
    bytes[16..].copy_from_slice(&generation.to_be_bytes());
    bytes
}

/// [`assignment_bytes`] in a vector, for callers that own one.
pub fn encode_assignment(plane: ControlPlaneId, generation: u64) -> Vec<u8> {
    assignment_bytes(plane, generation).to_vec()
}

pub fn decode_assignment(value: &[u8]) -> Result<(ControlPlaneId, u64), StoreError> {
    if value.len() != 24 {
        return Err(StoreError::Internal("malformed assignment entry".into()));
    }
    let mut plane = [0u8; 16];
    plane.copy_from_slice(&value[..16]);
    let generation = u64::from_be_bytes(
        value[16..]
            .try_into()
            .map_err(|_| StoreError::Internal("assignment generation decode".into()))?,
    );
    Ok((ControlPlaneId(plane), generation))
}
