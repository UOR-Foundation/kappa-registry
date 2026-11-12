use std::sync::Arc;

use dcbor::bounded::decode::{
    BoundedDecodable, ConstructResult, Constructed, DecodeError, Kind, Node, decode_typed, visit,
    wrong_type,
};
use dcbor::bounded::{Allocator, BoundedError, Budget, Encoded, Schema, prepare};
use dcbor::prelude::*;

use crate::capacity::{CapacityError, CapacityPool, Reservation};
use crate::error::StoreError;
use crate::work::{Dimension, Meter, Work};

/// Bytes of canonical encodings a store's operations may hold live at once
/// by default (`encoding_storage` of each store's configuration): prepared
/// normalization scratch and encoded records awaiting their storage.
pub const DEFAULT_ENCODING_STORAGE: u64 = 64 * 1024 * 1024;

/// Bytes of bounded decoding a store's operations may hold live at once by
/// default (`settlement_decoded_bytes` of each store's configuration): the
/// decoder's document arena while a value is constructed, the permits of
/// every heap allocation a constructed value holds, and the constructed
/// values retained. A capacity policy, not a bound derived from any record
/// size: construction that does not fit is refused through the pool.
pub const DEFAULT_DECODED_STORAGE: u64 = 64 * 1024 * 1024;

/// A record's canonical encoding with the live-storage reservation that owns
/// its bytes, released when the bytes are freed.
pub type Canonical = Encoded<Reservation>;

/// A value constructed from canonical bytes under bounded decoding
/// ([`bounded_from_canonical`]), owned with the live-storage reservation of
/// every heap allocation it holds; the value is borrowed through
/// `Constructed::value` for as long as those reservations are held, and no
/// API separates it from them.
pub type Decoded<T> = Constructed<T, Reservation>;

pub mod framing;
mod shared;
pub(crate) use shared::SharedRecord;
mod record;
pub use record::{
    BoundedRecord, ConstructionBound, DecodeCost, Record, bounded_record, decode_cost,
};

#[derive(Debug, thiserror::Error)]
pub enum CanonicalError {
    #[error("canonical decode error: {0}")]
    Decode(dcbor::Error),
    #[error("canonical conversion error: {0}")]
    Conversion(dcbor::Error),
}

/// Encode a value to canonical dCBOR bytes.
pub fn canonical_bytes<T: Into<CBOR> + Clone>(value: &T) -> Vec<u8> {
    value.clone().into().to_cbor_data()
}

/// Decode canonical dCBOR bytes back to a value.
/// Rejects non-canonical input.
pub fn from_canonical<T>(bytes: &[u8]) -> Result<T, CanonicalError>
where
    T: TryFrom<CBOR, Error = dcbor::Error>,
{
    let cbor = CBOR::try_from_data(bytes).map_err(CanonicalError::Decode)?;
    T::try_from(cbor).map_err(CanonicalError::Conversion)
}

/// The preparation's work, charged on the operation's meter as it is
/// reported, each before it is done: values visited as entries, source
/// bytes examined as bytes read, every allocation in its whole requested
/// size as bytes allocated. A refusal is the meter's, typed.
///
/// Two accounts, never confused. `BytesAllocated` is cumulative consumption
/// (`work.rs`: bytes of buffers the operation allocates), charged once and
/// never refunded. Live storage is a [`Reservation`] against `storage`, held
/// by the allocation's permit for exactly the allocation's life and released
/// when it drops; it does not borrow the meter, so the operation keeps
/// metering while the storage lives.
struct Charged<'m> {
    work: &'m mut dyn Meter,
    storage: &'m Arc<CapacityPool>,
}

impl Budget for Charged<'_> {
    type Refusal = StoreError;

    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), StoreError> {
        self.work
            .charge_all(&[(Dimension::Entries, values), (Dimension::BytesRead, bytes)])
            .map_err(StoreError::WorkRefused)
    }
}

impl Allocator for Charged<'_> {
    type Permit = Reservation;

    fn allocate(&mut self, bytes: u64) -> Result<Reservation, StoreError> {
        self.work
            .charge(Dimension::BytesAllocated, bytes)
            .map_err(StoreError::WorkRefused)?;
        live(self.storage, bytes)
    }
}

/// A live reservation of `bytes` of encoding storage; a refusal is the
/// store's capacity condition.
fn live(storage: &Arc<CapacityPool>, bytes: u64) -> Result<Reservation, StoreError> {
    storage
        .reserve(bytes)
        .map_err(|error: CapacityError| StoreError::CapacityExceeded(error.to_string()))
}

/// The write's work, accounted inside the unit admitted at the plan's
/// emission bound (`Prepared::write_work`), without another deadline check:
/// passing that bound is a defect of the bound, never a budget refusal. A
/// write allocates nothing through the budget.
struct Accounted<'m>(&'m mut dyn Meter);

impl Budget for Accounted<'_> {
    type Refusal = StoreError;

    fn traverse(&mut self, values: u64, bytes: u64) -> Result<(), StoreError> {
        self.0.account(Dimension::Entries, values)?;
        self.0.account(Dimension::BytesRead, bytes)
    }
}

/// A bounded encoding's failure as the store reports it: the meter's or the
/// storage pool's own refusal unchanged; an encoding whose length or work
/// does not fit in `u64`, whose nesting passes the encoder's limit, or whose
/// allocation the heap refused, a capacity condition of the value; a value
/// outside the dCBOR profile or with colliding canonical map keys, a
/// rejection of the value; and every other variant, each a violated encoding
/// invariant (an output of another length than the plan, a source answering
/// outside its schema contract, a plan whose bytes do not account for its
/// length), an internal defect. Matched exhaustively, so a new variant is
/// classified here before it compiles.
fn store_error(error: BoundedError<StoreError>) -> StoreError {
    match error {
        BoundedError::Refused(error) => error,
        BoundedError::Overflow => {
            StoreError::CapacityExceeded("canonical length or work exceeds u64".into())
        }
        BoundedError::DepthLimit => {
            StoreError::CapacityExceeded("canonical value nests past its limit".into())
        }
        BoundedError::Allocation { bytes } => StoreError::CapacityExceeded(format!(
            "canonical construction could not allocate {bytes} bytes"
        )),
        BoundedError::OutOfRange => {
            StoreError::Rejected("value is outside the dCBOR profile".into())
        }
        BoundedError::DuplicateKey => {
            StoreError::Rejected("value has two map keys with one canonical encoding".into())
        }
        defect @ (BoundedError::OutputSize { .. } | BoundedError::PlanMismatch) => {
            StoreError::Internal(format!("bounded canonical operation: {defect}"))
        }
    }
}

/// A bounded decoding's failure as the store reports it: a resource refusal
/// as [`store_error`] classifies it (the meter's or the pool's unchanged),
/// malformed or non-canonical input a rejection of the bytes, and nesting
/// past the caller's depth limit a capacity condition.
fn decode_store_error(error: DecodeError<StoreError>) -> StoreError {
    match error {
        DecodeError::Resource(error) => store_error(error),
        DecodeError::Invalid(error) => StoreError::Rejected(format!("canonical decode: {error}")),
        DecodeError::DepthLimit { limit } => {
            StoreError::CapacityExceeded(format!("canonical decode exceeds nesting limit {limit}"))
        }
        DecodeError::UnprovenText => StoreError::Rejected(
            "canonical record text is not proven NFC by its decoding policy".into(),
        ),
    }
}

/// `T` constructed from the canonical dCBOR bytes `input`, under `work`, the
/// owning operation's meter, in storage reserved from `storage`: the bytes
/// are decoded strictly into a borrowed document whose arena is admitted and
/// reserved, `T` is built from that document with every heap allocation it
/// holds requested in its whole size before it is made
/// (`dcbor::bounded::decode::decode_typed`), the arena is released once the
/// value exists, and the value is returned with the reservations of what it
/// holds ([`Decoded`]). The input is charged as decoded bytes first; every
/// value examined, byte scanned and allocation made is charged through
/// `Charged` as it is reported. No symbolic tree is built and no
/// unrestricted conversion follows: a value this cannot construct is not
/// constructed. Nesting is bounded by `max_depth`.
pub fn bounded_from_canonical<T>(
    input: &[u8],
    max_depth: usize,
    work: &mut dyn Meter,
    storage: &Arc<CapacityPool>,
) -> Result<Decoded<T>, StoreError>
where
    T: BoundedDecodable,
{
    work.charge(Dimension::BytesDecoded, input.len() as u64)?;
    decode_typed(input, max_depth, &mut Charged { work, storage }).map_err(decode_store_error)
}

/// The fields of the map `node` by integer key, for a record whose keys
/// are `0..N`: one pass over the entries in canonical key order, each key
/// placed in its slot, a key at or past `N` or a non-integer key refused as
/// an unknown field, a repeated key refused as a duplicate. Strict records
/// (`EpochRootData`, `NamespaceState`) construct through this where the
/// derived construction, which ignores unknown keys, would weaken their
/// decode contract. Charges one visit for the map and one per entry.
pub(crate) fn bounded_map_fields<'d, 'a, A, const N: usize>(
    node: Node<'d, 'a>,
    allocator: &mut A,
) -> ConstructResult<[Option<Node<'d, 'a>>; N], A>
where
    A: Allocator,
{
    visit(allocator)?;
    let Kind::Map(_) = node.kind() else {
        return Err(wrong_type());
    };
    let mut fields = [None; N];
    let mut children = node.children();
    while let Some(key) = children.next() {
        visit(allocator)?;
        let Kind::Unsigned(key) = key.kind() else {
            return Err(wrong_type());
        };
        let slot = usize::try_from(key)
            .ok()
            .and_then(|key| fields.get_mut(key))
            .ok_or_else(|| {
                DecodeError::Invalid(dcbor::Error::msg("unknown canonical record field"))
            })?;
        let value = children.next().ok_or_else(|| {
            DecodeError::Invalid(dcbor::Error::msg("canonical map has no value for its key"))
        })?;
        if slot.replace(value).is_some() {
            return Err(DecodeError::Invalid(dcbor::Error::DuplicateMapKey));
        }
    }
    Ok(fields)
}

/// A field a record requires, or the error the symbolic extraction gives
/// for its absence.
pub(crate) fn bounded_required<'d, 'a, R>(
    field: Option<Node<'d, 'a>>,
) -> Result<Node<'d, 'a>, DecodeError<R>> {
    field.ok_or(DecodeError::Invalid(dcbor::Error::MissingMapKey))
}

/// A byte string of exactly `N` bytes, copied into a fixed array: no heap
/// allocation, the copy charged as bytes scanned.
pub(crate) fn bounded_fixed_bytes<A: Allocator, const N: usize>(
    node: Node<'_, '_>,
    allocator: &mut A,
) -> ConstructResult<[u8; N], A> {
    visit(allocator)?;
    let Kind::Bytes(bytes) = node.kind() else {
        return Err(wrong_type());
    };
    allocator
        .traverse(0, bytes.len() as u64)
        .map_err(BoundedError::Refused)?;
    bytes.try_into().map_err(|_| {
        DecodeError::Invalid(dcbor::Error::msg(
            "canonical byte string has the wrong fixed length",
        ))
    })
}

/// `value`'s canonical dCBOR encoding, produced under `work`, the owning
/// operation's meter, in storage reserved from `storage`: the bytes
/// [`canonical_bytes`] produces, without a symbolic tree, owned with the
/// reservation that holds them live.
///
/// The value is prepared first (`dcbor::bounded::prepare`): its shape
/// walked, then its plan built in an arena capped at the walked extent,
/// every unit of work and every allocation, a normalized text's included,
/// charged on `work` and reserved live from `storage` before it is made.
/// Then one unit is admitted on `work` for the output: its allocation and
/// the write the plan's emission bound states, the output's initialization
/// included (`Prepared::write_work`). Inside that unit the output's live
/// storage is reserved, while the plan's arena still exists, and the
/// encoding written into storage allocated fallibly at exactly the plan's
/// length (`Prepared::encode_owned`), accounted without another deadline
/// check; every unit of the write is the plan's, within that bound, and
/// must fill the output exactly. A refusal before the unit is admitted is
/// `WorkRefused`; work consumed before a failure stays charged; every live
/// reservation of a failed encoding is released with its storage.
pub fn bounded_canonical_bytes<T>(
    value: &T,
    work: &mut dyn Meter,
    storage: &Arc<CapacityPool>,
) -> Result<Canonical, StoreError>
where
    T: Schema + ?Sized,
{
    let prepared = prepare(
        value,
        &mut Charged {
            work: &mut *work,
            storage,
        },
    )
    .map_err(store_error)?;
    let len = u64::try_from(prepared.len())
        .map_err(|_| StoreError::CapacityExceeded("canonical length exceeds u64".into()))?;
    let predicted = prepared.write_work::<StoreError>().map_err(store_error)?;
    // The output's initialization is part of the write bound, reported as
    // bytes the write touches, as `Accounted` lands them: on `BytesRead`.
    let aggregate = Work::total(&[
        (Dimension::Entries, predicted.values),
        (Dimension::BytesRead, predicted.bytes),
        (Dimension::BytesAllocated, len),
    ])
    .map_err(|dimension| {
        StoreError::CapacityExceeded(format!("canonical encoding work overflows {dimension:?}"))
    })?;
    let mut unit = work.admit(&aggregate.as_bound())?;
    unit.account(Dimension::BytesAllocated, len)?;
    let output = live(storage, len)?;
    prepared
        .encode_owned(output, &mut Accounted(&mut unit))
        .map_err(store_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::axis::Axis;
    use crate::identity::{Succession, SuccessionReason};
    use crate::kappa::Kappa;
    use crate::signed::SignedPayload;
    use crate::work::{WorkLimit, WorkMeter};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Encoding storage no test exhausts.
    fn storage() -> Arc<CapacityPool> {
        Arc::new(CapacityPool::new("test encodings", u64::MAX))
    }

    fn succession(
        reason: SuccessionReason,
        effective_at_ms: i64,
        chain_anchor: Option<Kappa>,
        prev_identifier: Option<Kappa>,
        signature: usize,
    ) -> Succession {
        Succession {
            old_anchor: Kappa::sha256(b"old"),
            new_anchor: Kappa::sha256(b"new"),
            reason,
            effective_at_ms,
            chain_anchor,
            prev_identifier,
            old_cose_signature: SignedPayload::from_cose_bytes(vec![0x5a; signature]),
            new_cose_signature: SignedPayload::from_cose_bytes(vec![0xa5; signature / 2]),
        }
    }

    /// Every succession shape encodes to the symbolic path's exact bytes:
    /// each reason, the optional anchors absent, each present and both, a
    /// timestamp at every integer width of either sign, signatures across
    /// head widths, and anchors of another axis.
    #[test]
    fn succession_bytes_are_the_symbolic_bytes() -> TestResult {
        let other_axis = Kappa::compute(Axis::Sha512, b"chain")?;
        let anchors = [
            (None, None),
            (Some(Kappa::sha256(b"chain")), None),
            (None, Some(other_axis.clone())),
            (Some(other_axis), Some(Kappa::sha256(b"prev"))),
        ];
        let timestamps = [
            i64::MIN,
            -4_294_967_297,
            -4_294_967_296,
            -65_537,
            -257,
            -25,
            -24,
            -1,
            0,
            23,
            24,
            255,
            256,
            65_535,
            65_536,
            4_294_967_295,
            4_294_967_296,
            i64::MAX,
        ];
        for reason in [
            SuccessionReason::Rotation,
            SuccessionReason::KeyCompromise,
            SuccessionReason::Administrative,
        ] {
            for (chain, prev) in &anchors {
                for timestamp in timestamps {
                    for signature in [0, 23, 24, 256] {
                        let record =
                            succession(reason, timestamp, chain.clone(), prev.clone(), signature);
                        assert_eq!(
                            bounded_canonical_bytes(
                                &record,
                                &mut WorkMeter::unbounded(),
                                &storage()
                            )?
                            .as_ref(),
                            canonical_bytes(&record),
                            "{record:?}"
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// The least encoding storage `value`'s encoding fits in: a larger pool
    /// admits whatever a smaller one admits, so a binary search finds it
    /// exactly. Every refusal on the way is the pool's capacity condition.
    fn least_storage<T: Schema + ?Sized>(value: &T) -> u64 {
        let fits = |limit| {
            let pool = Arc::new(CapacityPool::new("searched encodings", limit));
            match bounded_canonical_bytes(value, &mut WorkMeter::unbounded(), &pool) {
                Ok(_) => true,
                Err(StoreError::CapacityExceeded(_)) => false,
                Err(error) => panic!("a storage search failed otherwise: {error}"),
            }
        };
        let (mut low, mut high) = (0u64, 1u64 << 20);
        assert!(fits(high), "the search's upper end fits the encoding");
        while low < high {
            let middle = low + (high - low) / 2;
            if fits(middle) {
                high = middle;
            } else {
                low = middle + 1;
            }
        }
        high
    }

    /// An allowance that admits the preparation but not the output refuses
    /// before the output is allocated: the preparation's allocations stay
    /// charged, the output's is never charged, nothing stays reserved, and
    /// the refusal is the meter's own. The allowance of the whole encoding
    /// admits it exactly.
    #[test]
    fn an_insufficient_allowance_refuses_before_the_output_exists() -> TestResult {
        let record = succession(SuccessionReason::Rotation, 1, None, None, 64);
        let length = canonical_bytes(&record).len() as u64;
        let mut measured = WorkMeter::unbounded();
        drop(bounded_canonical_bytes(&record, &mut measured, &storage())?);
        let total = measured.used().get(Dimension::BytesAllocated);
        let storage = storage();
        let mut meter =
            WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, total - 1));
        assert!(matches!(
            bounded_canonical_bytes(&record, &mut meter, &storage),
            Err(StoreError::WorkRefused(_))
        ));
        assert_eq!(
            meter.used().get(Dimension::BytesAllocated),
            total - length,
            "only the preparation's allocations were charged"
        );
        assert_eq!(storage.used(), 0, "nothing stays reserved");
        let mut exact =
            WorkMeter::new(WorkLimit::unbounded().with(Dimension::BytesAllocated, total));
        assert_eq!(
            bounded_canonical_bytes(&record, &mut exact, &storage)?.as_ref(),
            canonical_bytes(&record)
        );
        assert_eq!(exact.used().get(Dimension::BytesAllocated), total);
        Ok(())
    }

    /// The encoding owns its live storage: once it returns, only its output
    /// is held, while the bytes are, released exactly when they are dropped,
    /// never refunding the consumed allocation work. In the least storage the
    /// encoding fits, a second encoding beside the first's output refuses as
    /// a capacity condition and releases all it held; one byte less storage
    /// refuses the first, reserving nothing.
    #[test]
    fn the_encoding_owns_its_live_storage() -> TestResult {
        let record = succession(SuccessionReason::Rotation, 1, None, None, 64);
        let length = canonical_bytes(&record).len() as u64;
        let least = least_storage(&record);
        let exact = Arc::new(CapacityPool::new("least encodings", least));
        let mut meter = WorkMeter::unbounded();
        let encoded = bounded_canonical_bytes(&record, &mut meter, &exact)?;
        assert_eq!(exact.used(), length, "only the output is held once it returns");
        assert!(
            matches!(
                bounded_canonical_bytes(&record, &mut meter, &exact),
                Err(StoreError::CapacityExceeded(_))
            ),
            "a second encoding does not fit beside the first's output"
        );
        assert_eq!(
            exact.used(),
            length,
            "the refused encoding released all it held"
        );
        let consumed = meter.used().get(Dimension::BytesAllocated);
        drop(encoded);
        assert_eq!(exact.used(), 0, "released with the bytes");
        assert_eq!(
            meter.used().get(Dimension::BytesAllocated),
            consumed,
            "consumed allocation work is never refunded"
        );
        let short = Arc::new(CapacityPool::new("short encodings", least - 1));
        assert!(matches!(
            bounded_canonical_bytes(&record, &mut WorkMeter::unbounded(), &short),
            Err(StoreError::CapacityExceeded(_))
        ));
        assert_eq!(short.used(), 0);
        Ok(())
    }

    /// The plan and the output coexist: text that needs normalization is
    /// prepared into the plan's arena, which holds at least the encoding
    /// while the output is reserved beside it, so the least storage the
    /// encoding fits in holds the encoding twice; both are released once
    /// the encoding returns and drops, but for the output while it lives.
    #[test]
    fn preparation_and_output_reservations_coexist() -> TestResult {
        let text = "e\u{301}".repeat(8);
        let symbolic = canonical_bytes(&text);
        let pool = storage();
        let encoded = bounded_canonical_bytes(text.as_str(), &mut WorkMeter::unbounded(), &pool)?;
        assert_eq!(encoded.as_ref(), symbolic);
        assert_eq!(
            pool.used(),
            symbolic.len() as u64,
            "the plan is released when the encoding returns; the output stays"
        );
        drop(encoded);
        assert_eq!(pool.used(), 0);
        assert!(
            least_storage(text.as_str()) >= 2 * symbolic.len() as u64,
            "the output is reserved while the plan's arena still lives"
        );
        Ok(())
    }

    /// A source that is its own child, without end.
    struct Endless;

    impl Schema for Endless {
        fn instruction(&self, index: usize) -> dcbor::bounded::encoding::Instruction<'_> {
            match index {
                0 => dcbor::bounded::encoding::Instruction::Child(self),
                _ => dcbor::bounded::encoding::Instruction::End,
            }
        }
    }

    /// A value nesting past the encoder's limit is refused by its shape
    /// walk, a capacity condition of the value, before anything is
    /// allocated or reserved.
    #[test]
    fn a_value_past_the_nesting_limit_is_refused_before_construction() {
        let mut meter = WorkMeter::unbounded();
        let pool = storage();
        assert!(matches!(
            bounded_canonical_bytes(&Endless, &mut meter, &pool),
            Err(StoreError::CapacityExceeded(_))
        ));
        assert_eq!(meter.used().get(Dimension::BytesAllocated), 0);
        assert_eq!(pool.used(), 0);
    }

    /// The meter's refusal passes through unchanged; a length, work or heap
    /// condition of the value is a capacity condition; every violated
    /// encoding invariant is internal.
    #[test]
    fn bounded_failures_keep_their_class() {
        let refused = StoreError::WorkRefused(crate::work::WorkExhausted::Deadline);
        assert!(matches!(
            store_error(BoundedError::Refused(refused)),
            StoreError::WorkRefused(crate::work::WorkExhausted::Deadline)
        ));
        for capacity in [
            BoundedError::Overflow,
            BoundedError::DepthLimit,
            BoundedError::Allocation { bytes: 7 },
        ] {
            assert!(
                matches!(store_error(capacity), StoreError::CapacityExceeded(_)),
                "a capacity condition of the value"
            );
        }
        for rejected in [BoundedError::OutOfRange, BoundedError::DuplicateKey] {
            assert!(
                matches!(store_error(rejected), StoreError::Rejected(_)),
                "a value no canonical encoding admits"
            );
        }
        for defect in [
            BoundedError::OutputSize {
                measured: 2,
                provided: 1,
            },
            BoundedError::PlanMismatch,
        ] {
            assert!(
                matches!(store_error(defect), StoreError::Internal(_)),
                "a violated encoding invariant"
            );
        }
    }

    /// A counted map whose source visits one field of the two its head
    /// carries.
    struct Miscounted;

    impl Schema for Miscounted {
        fn instruction(&self, index: usize) -> dcbor::bounded::encoding::Instruction<'_> {
            use dcbor::bounded::encoding::Instruction;
            match index {
                0 => Instruction::CountedMap(2),
                1 => Instruction::Field(0, Some(&true)),
                _ => Instruction::End,
            }
        }
    }

    /// A source answering outside its schema contract is stopped by the
    /// encoder before any output exists: an internal defect, the output
    /// never admitted, and every reservation of the preparation released.
    #[test]
    fn a_source_outside_its_schema_contract_is_an_internal_defect() {
        let mut meter = WorkMeter::unbounded();
        let pool = storage();
        assert!(matches!(
            bounded_canonical_bytes(&Miscounted, &mut meter, &pool),
            Err(StoreError::Internal(_))
        ));
        assert_eq!(pool.used(), 0, "the failed preparation released its storage");
    }
}
