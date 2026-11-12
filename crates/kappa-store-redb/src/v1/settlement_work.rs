//! The work settlement and recovery do, on the shared meter
//! (`kappa_store::work`): the upper bound of each indivisible unit on every
//! dimension ([`SettlementLimits`]) and the rule that schedules the parts of
//! a step ([`part_cap`]).
//!
//! Every bound is derived from the cost functions of the readers that do
//! the work (`content_read::record_lookup_cost`, `stored_read_cost`,
//! `verified_content_cost`, `ExternalSource::chunk_cost`), so an admitted
//! unit names every dimension its readers charge. An epoch read is staged
//! (`settlement_ledger_open`): each stage's unit is admitted, or its readers
//! charge, only once its extent is known, and a refused stage keeps every
//! stage before it. The units:
//!
//! - opening an epoch read: the namespace snapshot's handle; the epoch
//!   index lookup; each seal record's row lookup and its buffer reserved at
//!   its validated extent; one stored chunk read, decrypted and hashed; the
//!   root decoded and its authority verified; the state decoded; the ledger
//!   row looked up and its allocation opened;
//! - one ledger element: one entry, the element decoded and its leaf
//!   re-encoded, its evidence read and verified, and the rows its staging
//!   admits;
//! - one seal record or edge target: one entry and the row it admits;
//! - one element's application (`settlement_apply`): every version its
//!   effects write and the cursor's finalization, admitted as one unit at
//!   exactly what the prepared writes cost (`ProjectionStage::write_cost`).

use kappa_store::identity::SUCCESSION_CHAIN_MAX;
use kappa_store::work::{Dimension, Meter, Work, WorkLimit};
use kappa_store::StoreError;

use super::stage::{EFFECTS_BUFFER_BYTES, MAX_ELEMENT_EFFECTS};
use crate::content_read::{
    record_lookup_cost, verified_content_cost, ENVELOPE_OVERHEAD, MAX_EPOCH_ROOT_BYTES,
};
use crate::projection::reduce::selection_unit;
use crate::projection::VersionBounds;

/// Versions one element's application writes at most: the row its mutation
/// names (a catalog entry and, for an External row, its owner and
/// allocation locator: 3), and either a content row it admits or a
/// retirement (3 each), an assignment or a directory record (1), or an
/// identity effect, of which a succession writes the most: its record and
/// the depth of every anchor after it, at most `SUCCESSION_CHAIN_MAX`
/// (`settlement_apply`). A preparation beyond it is a defect, refused.
pub const MAX_ELEMENT_WRITES: usize = 3 + 1 + SUCCESSION_CHAIN_MAX;

/// Bytes the buffers one ledger element's retained preparation builds hold
/// at most (`settlement_apply::ElementPreparation`), under the record limit
/// `record_bytes`; `None` when unrepresentable. Payloads are borrowed from
/// the pending element's own effects and allocation identifiers are
/// inline, so the buffers built are keys: per effect at most an
/// assertion's subject key (its subject, a separator and its facet, all
/// within the one record it decodes from) and four compact Kappa keys (the
/// assertion's, the asserter's, and the two of the subject member). The
/// succession record's encoding is held in encoding storage, not here.
pub const fn element_preparation_bytes(record_bytes: u64) -> Option<u64> {
    let keys = 4 * kappa_store::kappa::MAX_KEY_BYTES as u64;
    match record_bytes.checked_add(keys) {
        Some(effect) => effect.checked_mul(MAX_ELEMENT_EFFECTS as u64),
        None => None,
    }
}

/// The default bytes of retained preparation across `cursors` epoch
/// cursors, each holding at most one pending element, under the record
/// limit `record_bytes`: saturating, as a ceiling it only caps.
pub const fn default_preparation_bytes(cursors: usize, record_bytes: u64) -> u64 {
    match element_preparation_bytes(record_bytes) {
        Some(element) => element.saturating_mul(cursors as u64),
        None => u64::MAX,
    }
}

/// Rows one ledger element's staging admits at most (`settlement_stage`):
/// the row its mutation names and the content row its content transition
/// admits.
const STAGE_ADMITS: u64 = 2;

/// Identity rows one ledger element's staging reads at most
/// (`settlement_identity::collect`, `collect_grace`): the row and a
/// credential's grace row, each within the record limit.
const STAGE_IDENTITY_READS: u64 = 2;

/// The signature an epoch read verifies when its root is completed: the
/// root's authority (`settlement_ledger_open`).
pub const OPENING_SIGNATURES: u64 = 1;

/// The signature an epoch read verifies when its ledger is complete: the
/// root's authority again, against the history in force then
/// (`settlement_ledger::finish_ledger`).
pub const VERIFICATION_SIGNATURES: u64 = 1;

/// Signatures one epoch read verifies in all, each charged when it is
/// verified.
pub const EPOCH_SIGNATURES: u64 = OPENING_SIGNATURES + VERIFICATION_SIGNATURES;

/// The indivisible units of opening one epoch read, each checked against a
/// step when the limits are made (`PersistentStore::validate_settlement`):
/// the snapshot, the index lookup, a seal record's lookup and buffer, one
/// stored chunk, the root's completion, the state's completion, and the
/// ledger's opening.
pub const OPENING_UNITS: usize = 8;

/// Limits of settlement reads, validated together so that every bound
/// derived from them is representable. Staging headroom is not among them:
/// it is decided per element from the versions that element writes
/// (`settlement_apply`).
#[derive(Clone, Copy, Debug)]
pub struct SettlementLimits {
    record_bytes: u64,
    opening: [Work; OPENING_UNITS],
    mutation: Work,
    record: Work,
    epoch_unit: Work,
    versions: VersionBounds,
    selection_unit: Work,
}

/// On every dimension, the largest amount any of `units` names.
fn widest(units: &[Work]) -> Work {
    let mut widest = Work::default();
    for unit in units {
        for dimension in Dimension::ALL {
            if unit.get(dimension) > widest.get(dimension) {
                widest = widest.with(dimension, unit.get(dimension));
            }
        }
    }
    widest
}

/// The aggregate of `parts`, `None` when it does not fit in `u64`.
fn sum(parts: &[Work]) -> Option<Work> {
    let mut total = Work::default();
    for part in parts {
        total.checked_add_assign(part).ok()?;
    }
    Some(total)
}

impl SettlementLimits {
    /// Limits admitting records of at most `record_bytes`. Refused when some
    /// committed epoch could never be read under them (an epoch root or an
    /// inline row larger than one record) or when a derived bound does not
    /// fit in `u64`.
    pub(crate) fn new(record_bytes: u64, inline_limit: u64) -> Result<Self, StoreError> {
        if record_bytes < MAX_EPOCH_ROOT_BYTES {
            return Err(StoreError::Rejected(format!(
                "settlement record limit {record_bytes} is below the epoch root limit {MAX_EPOCH_ROOT_BYTES}"
            )));
        }
        if record_bytes <= inline_limit {
            return Err(StoreError::Rejected(format!(
                "settlement record limit {record_bytes} does not exceed the inline limit {inline_limit}"
            )));
        }
        let unrepresentable = || {
            StoreError::Rejected(format!(
                "settlement record limit {record_bytes} makes the unit bounds unrepresentable"
            ))
        };
        let versions = VersionBounds::for_records(record_bytes).ok_or_else(unrepresentable)?;
        let lookup = record_lookup_cost(record_bytes).ok_or_else(unrepresentable)?;
        let row = |dimension, amount| Work::default().with(dimension, amount);
        let key = kappa_store::kappa::MAX_KEY_BYTES as u64;
        let plain = crate::BLOB_CHUNK_SIZE as u64;
        let framed = plain + ENVELOPE_OVERHEAD;
        // One stored chunk (`ExternalSource::unverified_chunk_cost` at its
        // largest): its framed buffer and read, its decrypted buffer and
        // decryption, its copy into the record buffer, and its hashing as
        // it arrives (`settlement_ledger_open::RecordReader::read_chunk`).
        let chunk = Work::total(&[
            (Dimension::BytesAllocated, framed),
            (Dimension::BytesRead, framed),
            (Dimension::BytesAllocated, plain),
            (Dimension::BytesDecoded, plain),
            (Dimension::BytesRead, plain),
            (Dimension::BytesHashed, plain),
        ])
        .map_err(|_| unrepresentable())?;
        let opening = [
            // The namespace snapshot.
            row(Dimension::Handles, 1),
            // The epoch index lookup and its stored key.
            sum(&[row(Dimension::Entries, 1), row(Dimension::BytesRead, key)])
                .ok_or_else(unrepresentable)?,
            // A seal record's row and its alias target's, its buffer
            // reserved at its extent, its allocation opened, and inline
            // bytes copied and hashed.
            sum(&[
                lookup,
                lookup,
                row(Dimension::BytesAllocated, record_bytes),
                row(Dimension::Handles, 1),
                row(Dimension::BytesRead, record_bytes),
                row(Dimension::BytesHashed, record_bytes),
            ])
            .ok_or_else(unrepresentable)?,
            chunk,
            // Root construction retains its result before authority admission.
            kappa_types::epoch_root::EpochRoot::verified_cost(MAX_EPOCH_ROOT_BYTES)?.work,
            // The state decoded.
            kappa_store::canonical::decode_cost::<kappa_store::NamespaceState>(
                kappa_store::NamespaceState::MAX_ENCODED_LEN,
            )?
            .work,
            // The ledger row and its alias target's, its allocation opened.
            sum(&[lookup, lookup, row(Dimension::Handles, 1)]).ok_or_else(unrepresentable)?,
            row(Dimension::Signatures, OPENING_SIGNATURES),
        ];
        let evidence =
            verified_content_cost(record_bytes, record_bytes).ok_or_else(unrepresentable)?;
        let admits = (0..STAGE_ADMITS).map(|_| lookup).collect::<Vec<_>>();
        let mut mutation = sum(&[
            row(Dimension::Entries, 1),
            row(Dimension::BytesDecoded, record_bytes),
            row(Dimension::BytesAllocated, record_bytes),
            row(Dimension::BytesAllocated, EFFECTS_BUFFER_BYTES),
            evidence,
            row(
                Dimension::BytesRead,
                record_bytes
                    .checked_mul(STAGE_IDENTITY_READS)
                    .ok_or_else(unrepresentable)?,
            ),
        ])
        .ok_or_else(unrepresentable)?;
        mutation
            .checked_add_assign(&sum(&admits).ok_or_else(unrepresentable)?)
            .map_err(|_| unrepresentable())?;
        let record = sum(&[
            row(Dimension::Entries, 1),
            row(Dimension::BytesAllocated, EFFECTS_BUFFER_BYTES),
            lookup,
        ])
        .ok_or_else(unrepresentable)?;
        // The smallest share a part of a step must hold to advance any
        // epoch: one visit's entry and handle, and on every dimension the
        // widest indivisible unit of reading an epoch.
        let mut units = opening.to_vec();
        units.push(mutation);
        units.push(record);
        let mut epoch_unit = widest(&units);
        epoch_unit
            .checked_add_assign(
                &sum(&[row(Dimension::Entries, 1), row(Dimension::Handles, 1)])
                    .ok_or_else(unrepresentable)?,
            )
            .map_err(|_| unrepresentable())?;
        // Every signature an epoch read charges is one of the two named
        // here; a third would be work no unit admits.
        const { assert!(OPENING_SIGNATURES + VERIFICATION_SIGNATURES == EPOCH_SIGNATURES) };
        Ok(Self {
            record_bytes,
            opening,
            mutation,
            record,
            epoch_unit,
            versions,
            selection_unit: selection_unit(&versions).map_err(|_| unrepresentable())?,
        })
    }

    /// Largest ledger element, referenced record or row one read admits;
    /// a larger one is refused before it is copied or decoded.
    pub(crate) const fn record_bytes(self) -> u64 {
        self.record_bytes
    }

    /// The indivisible units of opening an epoch read ([`OPENING_UNITS`]),
    /// in the order the stages run.
    #[cfg(test)]
    pub(crate) const fn opening(self) -> [Work; OPENING_UNITS] {
        self.opening
    }

    /// Taking the namespace snapshot: one handle.
    pub(crate) const fn opening_snapshot(self) -> Work {
        self.opening[0]
    }

    /// The epoch index lookup and its stored key.
    pub(crate) const fn opening_index(self) -> Work {
        self.opening[1]
    }

    /// Locating one seal record: its row and its alias target's row, its
    /// buffer reserved at its extent, its allocation opened, or its inline
    /// bytes copied and hashed.
    pub(crate) const fn opening_record(self) -> Work {
        self.opening[2]
    }

    /// One stored chunk of a seal record read, copied and hashed.
    pub(crate) const fn opening_chunk(self) -> Work {
        self.opening[3]
    }

    /// The actual retained root decoded; authority has a separate stage.
    pub(crate) fn opening_root_completion(self, length: u64) -> Result<Work, StoreError> {
        Ok(kappa_types::epoch_root::EpochRoot::verified_cost(length)?.work)
    }

    pub(crate) const fn opening_authority(self) -> Work {
        self.opening[7]
    }

    /// The state decoded.
    pub(crate) fn opening_state_completion(self, length: u64) -> Result<Work, StoreError> {
        Ok(kappa_store::canonical::decode_cost::<kappa_store::NamespaceState>(length)?.work)
    }

    /// The ledger row and its alias target's, its allocation opened.
    pub(crate) const fn opening_ledger(self) -> Work {
        self.opening[6]
    }

    /// The bound of reading one ledger element: an entry, the element
    /// decoded and its leaf re-encoded, the buffer its effects are
    /// collected into, its evidence read and verified
    /// (`verified_content_cost`), the rows its staging admits, and the
    /// identity rows it reads. The leaf's push into the mutation tree is the
    /// element's finalization, admitted with its application at what the
    /// effects write (`settlement_apply`).
    pub(crate) const fn mutation(self) -> Work {
        self.mutation
    }

    /// The bound of reading one seal record or edge target: an entry, the
    /// buffer its effect is collected into, and the row it admits.
    pub(crate) const fn record(self) -> Work {
        self.record
    }

    /// The smallest share of a step that can advance an epoch: one visit's
    /// entry and handle and, on every dimension, the widest indivisible
    /// unit of reading one. A step limit that does not admit it is refused
    /// (`PersistentStore::validate_settlement`).
    pub(crate) const fn epoch_unit(self) -> Work {
        self.epoch_unit
    }

    /// The longest projection version key and value staging under these
    /// limits writes (`VersionBounds`).
    pub(crate) const fn versions(self) -> VersionBounds {
        self.versions
    }

    /// The admitted bound of examining one projection version under these
    /// limits (`projection::selection_unit`), computed and checked once.
    pub(crate) const fn selection_unit(self) -> Work {
        self.selection_unit
    }
}

/// Whether `meter` can start one more examination: the deadline has not
/// passed and an entry remains.
pub(crate) fn exhausted(meter: &dyn Meter) -> bool {
    meter.admits(&[(Dimension::Entries, 1)]).is_err()
}

/// The cap of one part of a step that `parts` parts, this one included,
/// still share: on each dimension an even share of what `meter` has left,
/// but never less than the part's indivisible `unit` (its aggregate,
/// `Work::total`: a part given less could not advance, however the budget
/// is conserved). The last part (`parts == 1`) takes everything left, so
/// what earlier parts did not use is not lost. A part whose unit no longer
/// fits gets what is left and stops at its first admission; the order the
/// parts run in rotates across steps, so each leads in turn with the whole
/// step before it.
pub(crate) fn part_cap(meter: &dyn Meter, parts: u64, unit: &Work) -> WorkLimit {
    let mut cap = WorkLimit::unbounded();
    if parts <= 1 {
        return cap;
    }
    for dimension in Dimension::ALL {
        let remaining = meter.remaining(dimension);
        if remaining == u64::MAX {
            continue;
        }
        cap = cap.with(dimension, (remaining / parts).max(unit.get(dimension)));
    }
    cap
}

#[cfg(test)]
mod tests {
    use super::{part_cap, SettlementLimits, OPENING_UNITS};
    use crate::content_read::{record_lookup_cost, verified_content_cost, MAX_EPOCH_ROOT_BYTES};
    use kappa_store::work::{Dimension, Meter, Work, WorkLimit, WorkMeter};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Limits refuse records smaller than an epoch root or an inline row,
    /// and a record limit whose derived bounds would overflow.
    #[test]
    fn limits_refuse_unreadable_and_unrepresentable_bounds() -> TestResult {
        assert!(SettlementLimits::new(MAX_EPOCH_ROOT_BYTES - 1, 1024).is_err());
        assert!(SettlementLimits::new(MAX_EPOCH_ROOT_BYTES, MAX_EPOCH_ROOT_BYTES).is_err());
        assert!(SettlementLimits::new(u64::MAX / 3, 1024).is_err());
        Ok(())
    }

    /// Every unit names every dimension its readers charge: the element
    /// unit holds its evidence read and both admitted rows exactly, and the
    /// step unit holds every opening unit and the element unit on every
    /// dimension, plus one visit.
    #[test]
    fn units_are_derived_from_the_readers_costs() -> TestResult {
        let record = MAX_EPOCH_ROOT_BYTES;
        let limits = SettlementLimits::new(record, 1024)?;
        let lookup = record_lookup_cost(record).ok_or("lookup cost overflows")?;
        let evidence = verified_content_cost(record, record).ok_or("evidence cost overflows")?;
        let mutation = limits.mutation();
        for dimension in [
            Dimension::BytesAllocated,
            Dimension::BytesHashed,
            Dimension::BytesRead,
            Dimension::Handles,
        ] {
            assert!(
                mutation.get(dimension) >= evidence.get(dimension) + 2 * lookup.get(dimension),
                "{dimension:?}: the element unit covers its evidence and both admitted rows"
            );
        }
        assert_eq!(
            mutation.get(Dimension::Entries),
            1 + evidence.get(Dimension::Entries) + 2
        );
        let unit = limits.epoch_unit();
        let opening = limits.opening();
        assert_eq!(opening.len(), OPENING_UNITS);
        for part in opening.iter().chain([&mutation, &limits.record()]) {
            for dimension in Dimension::ALL {
                assert!(
                    unit.get(dimension) >= part.get(dimension),
                    "{dimension:?}: the step unit admits every indivisible unit"
                );
            }
        }
        assert_eq!(
            unit.get(Dimension::Handles),
            1 + opening
                .iter()
                .map(|part| part.get(Dimension::Handles))
                .max()
                .unwrap_or(0)
                .max(mutation.get(Dimension::Handles)),
            "a visit's handle beside the widest unit's"
        );
        Ok(())
    }

    /// A part is never capped below its indivisible unit, even when an even
    /// share would strand every part: two signatures shared by two parts,
    /// each needing two, gives the first part both.
    #[test]
    fn a_part_cap_admits_a_whole_unit_or_takes_what_is_left() -> TestResult {
        let meter = WorkMeter::new(
            WorkLimit::unbounded()
                .with(Dimension::Signatures, 2)
                .with(Dimension::Entries, 10),
        );
        let unit = Work::total(&[(Dimension::Signatures, 2), (Dimension::Entries, 1)])
            .map_err(|dimension| format!("{dimension:?} overflows"))?;
        let first = part_cap(&meter, 2, &unit);
        assert_eq!(
            first.limit(Dimension::Signatures),
            2,
            "a whole unit, not half"
        );
        assert_eq!(
            first.limit(Dimension::Entries),
            5,
            "an even share above the unit"
        );
        assert_eq!(
            first.limit(Dimension::BytesRead),
            u64::MAX,
            "an unbounded dimension stays unbounded"
        );
        let last = part_cap(&meter, 1, &unit);
        assert_eq!(
            last.limit(Dimension::Signatures),
            u64::MAX,
            "the last part borrows all"
        );
        Ok(())
    }

    /// A share capped by `part_cap` admits one whole unit whenever the
    /// meter does, so the part that leads a step always advances.
    #[test]
    fn the_leading_part_can_always_advance() -> TestResult {
        let limits = SettlementLimits::new(MAX_EPOCH_ROOT_BYTES, 1024)?;
        let unit = limits.epoch_unit();
        let mut limit = WorkLimit::unbounded();
        for (dimension, amount) in unit.as_bound() {
            limit = limit.with(dimension, amount);
        }
        let mut meter = WorkMeter::new(limit);
        for parts in 1..=3 {
            let cap = part_cap(&meter, parts, &unit);
            let share = meter.scope(&cap);
            assert!(
                share.admits(&unit.as_bound()).is_ok(),
                "{parts} parts: the lead admits a unit"
            );
        }
        Ok(())
    }
}
