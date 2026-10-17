//! The budget of one settlement or recovery step ([`Work`]) and the limits
//! every settlement read is held to ([`SettlementLimits`]).

use kappa_store::StoreError;

use crate::content_read::MAX_EPOCH_ROOT_BYTES;

/// What decoding one ledger element costs, in record-sized units: the
/// element decoded into a mutation (1) and the mutation re-encoded as its
/// Merkle leaf (1). The element's bytes themselves are charged when they
/// are read (`settlement_ledger`).
const DECODE_UNITS: u64 = 2;

/// What staging one mutation may cost, in record-sized units, on its most
/// expensive path (`settlement_stage`): an identity mutation admits the row
/// it names (1) and reads its transition record, its row and a
/// credential's grace row (3). A commitment, alias or composition admits
/// the row it names, reads the record and admits the content it names (3);
/// a metadata or namespace update admits and reads (2); every other
/// operation admits (1). Effects emitted are accounted by their consumer.
const STAGE_UNITS: u64 = 4;

/// Limits of settlement reads, validated together so that every bound
/// derived from them is representable.
#[derive(Clone, Copy, Debug)]
pub struct SettlementLimits {
    record_bytes: u64,
    mutation_quantum: u64,
    minimum_step_bytes: u64,
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
                "settlement record limit {record_bytes} makes the step budget unrepresentable"
            ))
        };
        let mutation_quantum = record_bytes
            .checked_mul(DECODE_UNITS + STAGE_UNITS)
            .ok_or_else(unrepresentable)?;
        let minimum_step_bytes = mutation_quantum
            .checked_mul(2)
            .ok_or_else(unrepresentable)?;
        Ok(Self {
            record_bytes,
            mutation_quantum,
            minimum_step_bytes,
        })
    }

    /// Largest ledger element, referenced record or row one read admits;
    /// a larger one is refused before it is copied or decoded.
    pub(crate) const fn record_bytes(self) -> u64 {
        self.record_bytes
    }

    /// Bytes reserved before one ledger element is decoded and staged: its
    /// decoding and every read on its most expensive staging path. Also
    /// covers opening a cursor (an epoch root and a ledger row).
    pub(crate) const fn mutation_quantum(self) -> u64 {
        self.mutation_quantum
    }

    /// The smallest step byte budget: a split step gives each class half,
    /// and each half must admit one mutation.
    pub(crate) const fn minimum_step_bytes(self) -> u64 {
        self.minimum_step_bytes
    }
}

/// The work a settlement or recovery step may still do: mutations (ledger
/// elements, seal records and edges examined) and bytes read, decoded or
/// copied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Work {
    pub mutations: u64,
    pub bytes: u64,
}

impl Work {
    /// Whether one more examination costing at most `bytes` fits.
    pub(crate) const fn admits(&self, bytes: u64) -> bool {
        self.mutations > 0 && self.bytes >= bytes
    }

    /// Whether nothing more can be examined.
    pub(crate) const fn spent(&self) -> bool {
        self.mutations == 0 || self.bytes == 0
    }

    pub(crate) fn charge_mutation(&mut self) -> Result<(), StoreError> {
        self.mutations = self
            .mutations
            .checked_sub(1)
            .ok_or_else(|| StoreError::Internal("settlement examined past its budget".into()))?;
        Ok(())
    }

    /// Charge `bytes` under a reservation `admits` granted; exceeding it is
    /// a defect of the reservation, refused rather than absorbed.
    pub(crate) fn charge_bytes(&mut self, bytes: u64) -> Result<(), StoreError> {
        self.bytes = self.bytes.checked_sub(bytes).ok_or_else(|| {
            StoreError::Internal("settlement read past its reserved budget".into())
        })?;
        Ok(())
    }

    /// Split into the share for queued obligations and the share for
    /// discovery: halves of each dimension holding two or more units; a
    /// dimension of one unit goes wholly to the class `to_queue` names.
    /// Returns the shares and whether a one-unit dimension decided them.
    pub(crate) const fn split(self, to_queue: bool) -> (Self, Self, bool) {
        let (queued_mutations, discovery_mutations, single_mutation) =
            halve(self.mutations, to_queue);
        let (queued_bytes, discovery_bytes, single_bytes) = halve(self.bytes, to_queue);
        (
            Self {
                mutations: queued_mutations,
                bytes: queued_bytes,
            },
            Self {
                mutations: discovery_mutations,
                bytes: discovery_bytes,
            },
            single_mutation || single_bytes,
        )
    }

    /// The part of `self` spent since it was `before`.
    pub(crate) const fn spent_since(self, before: Self) -> Self {
        Self {
            mutations: before.mutations.saturating_sub(self.mutations),
            bytes: before.bytes.saturating_sub(self.bytes),
        }
    }

    /// `self` less `spent`, refused when `spent` exceeds it.
    pub(crate) fn deduct(&mut self, spent: Self) -> Result<(), StoreError> {
        let exceeded = || StoreError::Internal("a recovery visit spent more than its share".into());
        self.mutations = self
            .mutations
            .checked_sub(spent.mutations)
            .ok_or_else(exceeded)?;
        self.bytes = self.bytes.checked_sub(spent.bytes).ok_or_else(exceeded)?;
        Ok(())
    }
}

/// `(queued, discovery, single)` shares of `units`.
const fn halve(units: u64, to_queue: bool) -> (u64, u64, bool) {
    match units {
        0 => (0, 0, false),
        1 if to_queue => (1, 0, true),
        1 => (0, 1, true),
        _ => (units / 2, units - units / 2, false),
    }
}

#[cfg(test)]
mod tests {
    use super::{SettlementLimits, Work};
    use crate::content_read::MAX_EPOCH_ROOT_BYTES;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Limits refuse records smaller than an epoch root or an inline row,
    /// and a record limit whose derived step budget would overflow.
    #[test]
    fn limits_refuse_unreadable_and_unrepresentable_bounds() -> TestResult {
        assert!(SettlementLimits::new(MAX_EPOCH_ROOT_BYTES - 1, 1024).is_err());
        assert!(SettlementLimits::new(MAX_EPOCH_ROOT_BYTES, MAX_EPOCH_ROOT_BYTES).is_err());
        assert!(SettlementLimits::new(u64::MAX / 3, 1024).is_err());
        let limits = SettlementLimits::new(MAX_EPOCH_ROOT_BYTES, 1024)?;
        assert_eq!(limits.mutation_quantum(), MAX_EPOCH_ROOT_BYTES * 6);
        assert_eq!(limits.minimum_step_bytes(), MAX_EPOCH_ROOT_BYTES * 12);
        Ok(())
    }

    /// A split conserves every unit, and a one-unit dimension goes to the
    /// class whose turn it is.
    #[test]
    fn split_conserves_work_and_alternates_single_units() {
        for (mutations, bytes) in [(0, 0), (1, 1), (2, 7), (9, 1), (u64::MAX, u64::MAX)] {
            for turn in [true, false] {
                let (queued, discovery, _) = Work { mutations, bytes }.split(turn);
                assert_eq!(queued.mutations + discovery.mutations, mutations);
                assert_eq!(queued.bytes + discovery.bytes, bytes);
            }
        }
        let (queued, discovery, single) = Work {
            mutations: 1,
            bytes: 8,
        }
        .split(true);
        assert!(single);
        assert_eq!((queued.mutations, discovery.mutations), (1, 0));
        let (queued, discovery, single) = Work {
            mutations: 1,
            bytes: 8,
        }
        .split(false);
        assert!(single);
        assert_eq!((queued.mutations, discovery.mutations), (0, 1));
    }

    /// Deduction refuses spending beyond the share.
    #[test]
    fn deduction_refuses_overspending() {
        let mut work = Work {
            mutations: 2,
            bytes: 10,
        };
        assert!(
            work.deduct(Work {
                mutations: 1,
                bytes: 4
            })
            .is_ok()
        );
        assert_eq!(
            work,
            Work {
                mutations: 1,
                bytes: 6
            }
        );
        assert!(
            work.deduct(Work {
                mutations: 2,
                bytes: 0
            })
            .is_err()
        );
    }
}
