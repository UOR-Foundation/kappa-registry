//! Schema-owned construction bounds composed with the decoder's own bounds.

use std::sync::Arc;

use dcbor::bounded::decode::{BoundedDecodable, Options, decode_bound_with, decode_typed_with};
use dcbor::bounded::{Allocator, Budget, owned_growth};

use super::{Decoded, decode_store_error, live, store_error};
use crate::axis::Axis;
use crate::capacity::{CapacityPool, Reservation};
use crate::error::StoreError;
use crate::kappa::Kappa;
use crate::verified::VerifiedContent;
use crate::work::{Dimension, Meter, Work};

#[cfg(test)]
#[path = "record_tests.rs"]
mod tests;

/// Constructor work excluding the parser and the allocation-permit container.
/// `peak` and `held` count requested storage, independently of cumulative
/// `allocated`. Bounds include constructor failures, not only valid records.
#[derive(Debug, Clone, Copy)]
pub struct ConstructionBound {
    pub values: u64,
    pub bytes: u64,
    pub allocated: u64,
    pub peak: u64,
    pub held: u64,
    pub permits: u64,
}

/// A record's decoding policy and the cost of its concrete constructor.
pub trait BoundedRecord: BoundedDecodable {
    const OPTIONS: Options;
    const AXIS: Axis;
    /// Allowed scalar major types at each integer field key, as a bit mask.
    /// Containers and tags are excluded. Missing/required-field semantics
    /// remain with the constructor; this describes allocation-free framing.
    const FIELDS: &'static [u8];
    fn construction(input: u64) -> ConstructionBound;
}

/// Work, peak live requested bytes, and retained requested bytes of decoding.
/// Raw input and any enclosing shared allocation are accounted by their owners.
#[derive(Debug, Clone, Copy)]
pub struct DecodeCost {
    pub work: Work,
    pub peak: u64,
    pub held: u64,
}

fn overflow() -> StoreError {
    StoreError::CapacityExceeded("canonical record resource bound overflows".into())
}

fn sum(left: u64, right: u64) -> Result<u64, StoreError> {
    left.checked_add(right).ok_or_else(overflow)
}

/// Compose private parser layouts with the schema's constructor and this
/// adapter's permit layout. No private decoder layout is duplicated here.
pub fn decode_cost<T: BoundedRecord>(input: u64) -> Result<DecodeCost, StoreError> {
    if T::OPTIONS.text != dcbor::bounded::decode::TextPolicy::QuickOnly
        || T::OPTIONS.max_depth != 1
        || T::FIELDS.len() > 23
        || T::FIELDS.iter().any(|mask| mask & !0b1111 != 0)
    {
        return Err(StoreError::Internal(
            "bounded record must be a scalar map with small integer keys".into(),
        ));
    }
    // Preflight below proves one map and at most two scalar nodes per field.
    // Calling the fork's bound at that node count bounds the arena, stack,
    // header visits, completions and one-byte integer key comparisons. Scalar
    // payloads do not add nodes. Add their complete input-length bound twice:
    // once for payload examination and once for text quick checking. The
    // fork's small-input payload allowance remains conservative slack.
    let nodes = (T::FIELDS.len() as u64) * 2 + 1;
    let parser = decode_bound_with::<StoreError>(nodes, T::OPTIONS).map_err(store_error)?;
    let construction = T::construction(input);
    let permits = owned_growth::<StoreError>(
        construction.permits,
        std::mem::size_of::<Reservation>() as u64,
    )
    .map_err(store_error)?;
    let work = Work::total(&[
        (Dimension::BytesDecoded, input),
        (Dimension::Entries, parser.values),
        (Dimension::Entries, nodes),
        (Dimension::Entries, construction.values),
        (Dimension::BytesRead, parser.bytes),
        (Dimension::BytesRead, nodes * 9),
        (Dimension::BytesRead, input),
        (Dimension::BytesRead, input),
        (Dimension::BytesRead, construction.bytes),
        (Dimension::BytesRead, permits.copied),
        (Dimension::BytesAllocated, parser.allocated),
        (Dimension::BytesAllocated, construction.allocated),
        (Dimension::BytesAllocated, permits.allocated),
    ])
    .map_err(|_| overflow())?;
    Ok(DecodeCost {
        work,
        peak: parser
            .peak
            .max(sum(parser.retained, sum(construction.peak, permits.peak)?)?),
        held: sum(construction.held, permits.held)?,
    })
}

/// A constructed record and the identity of the exact verified input decoded.
/// No owned value can be extracted separately from its allocation permits.
pub struct Record<T> {
    identity: Kappa,
    decoded: Decoded<T>,
}

impl<T> Record<T> {
    pub const fn identity(&self) -> &Kappa {
        &self.identity
    }

    pub fn value(&self) -> &T {
        self.decoded.value()
    }
}

/// Inside an admitted decode, exceeding a predicted work bound is a defect.
/// Capacity is still acquired per allocation, before that allocation exists.
struct Construction<'a> {
    work: &'a mut dyn Meter,
    storage: &'a Arc<CapacityPool>,
}

impl Budget for Construction<'_> {
    type Refusal = StoreError;

    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), StoreError> {
        self.work.account(Dimension::Entries, values)?;
        self.work.account(Dimension::BytesRead, bytes)
    }
}

impl Allocator for Construction<'_> {
    type Permit = Reservation;

    fn allocate(&mut self, bytes: u64) -> Result<Reservation, StoreError> {
        self.work.account(Dimension::BytesAllocated, bytes)?;
        live(self.storage, bytes)
    }
}

/// Admit one complete decode before touching the evidence. Admission refusal
/// leaves the borrowed evidence available for the next step. Successful
/// construction never hashes or copies the raw input into another raw buffer.
pub fn bounded_record<T: BoundedRecord>(
    evidence: &VerifiedContent,
    work: &mut dyn Meter,
    storage: &Arc<CapacityPool>,
) -> Result<Record<T>, StoreError> {
    if evidence.axis() != T::AXIS {
        return Err(StoreError::Rejected(
            "verified record identity uses the wrong axis".into(),
        ));
    }
    let length = evidence.content().len() as u64;
    let cost = decode_cost::<T>(length)?;
    let mut unit = work.admit(&cost.work.as_bound())?;
    unit.account(Dimension::BytesDecoded, length)?;
    scalar_map::<T>(evidence.content(), &mut unit)?;
    let decoded = decode_typed_with(
        evidence.content(),
        T::OPTIONS,
        &mut Construction {
            work: &mut unit,
            storage,
        },
    )
    .map_err(decode_store_error)?;
    Ok(Record {
        identity: evidence.kappa().clone(),
        decoded,
    })
}

/// Validate only the bounded scalar-map shape. dCBOR remains responsible for
/// canonical integers, UTF-8/NFC, and the constructor for field semantics.
fn scalar_map<T: BoundedRecord>(input: &[u8], work: &mut dyn Meter) -> Result<(), StoreError> {
    fn head(input: &[u8], work: &mut dyn Meter) -> Result<(u8, u64, usize), StoreError> {
        work.account(Dimension::Entries, 1)?;
        work.account(Dimension::BytesRead, input.len().min(9) as u64)?;
        super::framing::head(input)?
            .ok_or_else(|| StoreError::Rejected("truncated canonical record head".into()))
    }
    let (major, count, mut position) = head(input, work)?;
    if major != 5 || count > T::FIELDS.len() as u64 {
        return Err(StoreError::Rejected(
            "canonical record must be a bounded field map".into(),
        ));
    }
    let mut previous = None;
    for _ in 0..count {
        let (major, key, length) = head(&input[position..], work)?;
        if major != 0 || length != 1 || previous.is_some_and(|previous| key <= previous) {
            return Err(StoreError::Rejected(
                "canonical record keys must be increasing small integers".into(),
            ));
        }
        let allowed = T::FIELDS
            .get(key as usize)
            .ok_or_else(|| StoreError::Rejected("unknown canonical record field".into()))?;
        previous = Some(key);
        position += length;
        let (major, argument, length) = head(&input[position..], work)?;
        if major > 3 || allowed & (1 << major) == 0 {
            return Err(StoreError::Rejected(
                "canonical record field has the wrong scalar type".into(),
            ));
        }
        position += length;
        if major == 2 || major == 3 {
            let length = usize::try_from(argument).map_err(|_| {
                StoreError::Rejected("canonical record payload exceeds address space".into())
            })?;
            position = position
                .checked_add(length)
                .filter(|end| *end <= input.len())
                .ok_or_else(|| StoreError::Rejected("truncated canonical record payload".into()))?;
        }
    }
    if position != input.len() {
        return Err(StoreError::Rejected(
            "trailing canonical record bytes".into(),
        ));
    }
    Ok(())
}
