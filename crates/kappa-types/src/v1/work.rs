//! Work consumption: what one bounded operation may do, charged before it
//! does it.
//!
//! A [`WorkMeter`] carries one operation's limit on each [`Dimension`]
//! and its deadline, and records what it consumed. Work is charged before
//! it is performed with checked arithmetic ([`WorkMeter::charge`]): an
//! operation that would pass its limit refuses with [`WorkExhausted`]
//! before reading, decoding, allocating, hashing or signing anything more.
//! Consumption is not retained capacity: what an operation leaves held
//! after it returns is a `capacity::Reservation`, charged separately.
//!
//! Work whose exact cost is known only once it is done is admitted at its
//! checked upper bound first ([`WorkMeter::admits`]: the deadline and the
//! headroom, nothing charged), then accounted as measured
//! ([`WorkMeter::consume`]: the limit only). The deadline is an admission
//! deadline: no unit of work starts after it, and a unit admitted before it
//! is accounted whenever it finishes.
//!
//! A part of an operation runs under a scoped share of its meter
//! ([`WorkMeter::scope`]): an allowance fixed before the part starts, at
//! most what the operation has left, that nothing else can draw on while
//! the part runs. What the part consumed is the operation's, accounted when
//! the share ends however it ends; what it left unused stays the
//! operation's.
//!
//! The dimensions are defined, not inferred:
//!
//! - `Entries`: records, nodes or index entries examined;
//! - `BytesRead`: bytes read from storage;
//! - `BytesDecoded`: bytes produced by decoding or decompression;
//! - `BytesAllocated`: bytes of buffers the operation allocates;
//! - `BytesHashed`: bytes input to a cryptographic hash;
//! - `Signatures`: signatures produced or verified;
//! - `Handles`: storage handles (namespace databases, files) opened;
//! - `Candidates`: candidate owners materialized from a discovery index.

use std::time::Instant;

/// One dimension of work (see the module documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dimension {
    Entries,
    BytesRead,
    BytesDecoded,
    BytesAllocated,
    BytesHashed,
    Signatures,
    Handles,
    Candidates,
}

impl Dimension {
    pub const ALL: [Self; 8] = [
        Self::Entries,
        Self::BytesRead,
        Self::BytesDecoded,
        Self::BytesAllocated,
        Self::BytesHashed,
        Self::Signatures,
        Self::Handles,
        Self::Candidates,
    ];

    const fn index(self) -> usize {
        self as usize
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Entries => "entries examined",
            Self::BytesRead => "bytes read",
            Self::BytesDecoded => "bytes decoded",
            Self::BytesAllocated => "bytes allocated",
            Self::BytesHashed => "bytes hashed",
            Self::Signatures => "signatures",
            Self::Handles => "handles opened",
            Self::Candidates => "candidate owners materialized",
        }
    }
}

/// An amount on every dimension.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Work([u64; 8]);

impl Work {
    pub const fn get(&self, dimension: Dimension) -> u64 {
        self.0[dimension.index()]
    }

    /// This amount with `amount` on `dimension`: how a record of work
    /// persisted per dimension is restored.
    #[must_use]
    pub const fn with(mut self, dimension: Dimension, amount: u64) -> Self {
        self.0[dimension.index()] = amount;
        self
    }

    /// The amount a multidimensional bound names: a dimension named more
    /// than once is the sum of its amounts, and a dimension not named is
    /// zero. The one interpretation of a bound, for admission, aggregate
    /// charging and admitted units. Refused, naming the dimension, when a
    /// sum overflows.
    pub fn total(bounds: &[(Dimension, u64)]) -> Result<Self, Dimension> {
        let mut total = Self::default();
        for (dimension, amount) in bounds {
            let index = dimension.index();
            total.0[index] = total.0[index].checked_add(*amount).ok_or(*dimension)?;
        }
        Ok(total)
    }

    /// Add `other` to this amount on every dimension, refused, naming the
    /// first dimension whose sum overflows, with this amount unchanged: the
    /// whole sum is decided before any dimension is written. Accumulates a
    /// bound without building a list of its parts.
    pub fn checked_add_assign(&mut self, other: &Self) -> Result<(), Dimension> {
        let mut next = *self;
        for dimension in Dimension::ALL {
            let index = dimension.index();
            next.0[index] = next.0[index].checked_add(other.0[index]).ok_or(dimension)?;
        }
        *self = next;
        Ok(())
    }

    /// This amount as a bound: every dimension with its amount, the form
    /// admission takes.
    pub fn as_bound(&self) -> [(Dimension, u64); 8] {
        Dimension::ALL.map(|dimension| (dimension, self.get(dimension)))
    }

    /// The sum of two amounts, saturating: a reported total never wraps.
    /// Reporting only; admission uses [`Self::total`].
    #[must_use]
    pub fn saturating_add(&self, other: &Self) -> Self {
        let mut out = *self;
        for dimension in Dimension::ALL {
            out.0[dimension.index()] =
                out.0[dimension.index()].saturating_add(other.0[dimension.index()]);
        }
        out
    }

    /// What a meter consumed since it read `earlier`: consumption only
    /// grows, so this is exact for two readings of one meter, in order.
    #[must_use]
    pub fn since(&self, earlier: &Self) -> Self {
        let mut out = *self;
        for dimension in Dimension::ALL {
            out.0[dimension.index()] =
                out.0[dimension.index()].saturating_sub(earlier.0[dimension.index()]);
        }
        out
    }
}

/// What an operation may consume: a limit per dimension (`u64::MAX` is
/// unbounded on that dimension) and an optional deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkLimit {
    limits: [u64; 8],
    deadline: Option<Instant>,
}

impl WorkLimit {
    /// No bound on any dimension and no deadline.
    pub const fn unbounded() -> Self {
        Self {
            limits: [u64::MAX; 8],
            deadline: None,
        }
    }

    #[must_use]
    pub const fn with(mut self, dimension: Dimension, limit: u64) -> Self {
        self.limits[dimension.index()] = limit;
        self
    }

    #[must_use]
    pub const fn with_deadline(mut self, deadline: Instant) -> Self {
        self.deadline = Some(deadline);
        self
    }

    pub const fn limit(&self, dimension: Dimension) -> u64 {
        self.limits[dimension.index()]
    }

    pub const fn deadline(&self) -> Option<Instant> {
        self.deadline
    }
}

/// Why an operation stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WorkExhausted {
    #[error("{} limit {limit} reached: {used} used, {requested} more requested", .dimension.as_str())]
    Limit {
        dimension: Dimension,
        limit: u64,
        used: u64,
        requested: u64,
    },
    #[error("deadline passed")]
    Deadline,
}

impl From<WorkExhausted> for crate::error::StoreError {
    /// The one conversion of a refused unit: a typed refusal, never a
    /// capacity or rejection of the request's subject.
    fn from(error: WorkExhausted) -> Self {
        Self::WorkRefused(error)
    }
}

/// One operation's limit and consumption (see the module documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkMeter {
    limit: WorkLimit,
    used: Work,
}

impl WorkMeter {
    pub const fn new(limit: WorkLimit) -> Self {
        Self {
            limit,
            used: Work([0; 8]),
        }
    }

    /// A meter with no limits, for work whose bound is enforced by the
    /// caller's own admission (which must then account what it reports).
    pub const fn unbounded() -> Self {
        Self::new(WorkLimit::unbounded())
    }

    pub const fn limit(&self) -> &WorkLimit {
        &self.limit
    }
    pub const fn used(&self) -> &Work {
        &self.used
    }

    /// What remains on `dimension`.
    pub const fn remaining(&self, dimension: Dimension) -> u64 {
        self.limit
            .limit(dimension)
            .saturating_sub(self.used.get(dimension))
    }

    /// Bring the admission deadline forward to `deadline` when it is earlier
    /// than the one this meter has: an operation that learns its deadline
    /// after its allowance exists keeps one allowance, never an extended one.
    pub fn tighten_deadline(&mut self, deadline: Instant) {
        self.limit.deadline = Some(
            self.limit
                .deadline
                .map_or(deadline, |current| current.min(deadline)),
        );
    }

    /// Charge `amount` on `dimension` before performing it, refusing when
    /// it would pass the limit or the deadline has passed. A refusal
    /// charges nothing.
    pub fn charge(&mut self, dimension: Dimension, amount: u64) -> Result<(), WorkExhausted> {
        self.check_deadline()?;
        let index = dimension.index();
        let used = self.used.0[index];
        let limit = self.limit.limits[index];
        match used.checked_add(amount) {
            Some(total) if total <= limit => {
                self.used.0[index] = total;
                Ok(())
            }
            _ => Err(WorkExhausted::Limit {
                dimension,
                limit,
                used,
                requested: amount,
            }),
        }
    }

    /// Charge the aggregate of `charges` ([`Work::total`]) or nothing.
    pub fn charge_all(&mut self, charges: &[(Dimension, u64)]) -> Result<(), WorkExhausted> {
        self.check_deadline()?;
        let total = self.total(charges)?;
        let mut next = self.used;
        for dimension in Dimension::ALL {
            let index = dimension.index();
            next.0[index] = self.fit(dimension, total.get(dimension))?;
        }
        self.used = next;
        Ok(())
    }

    /// The aggregate of `bounds`, an overflow refused as a request past
    /// every limit.
    fn total(&self, bounds: &[(Dimension, u64)]) -> Result<Work, WorkExhausted> {
        Work::total(bounds).map_err(|dimension| WorkExhausted::Limit {
            dimension,
            limit: self.limit.limit(dimension),
            used: self.used.get(dimension),
            requested: u64::MAX,
        })
    }

    /// What `dimension` would have consumed after `amount` more, when that
    /// is within its limit.
    fn fit(&self, dimension: Dimension, amount: u64) -> Result<u64, WorkExhausted> {
        let used = self.used.get(dimension);
        let limit = self.limit.limit(dimension);
        used.checked_add(amount)
            .filter(|total| *total <= limit)
            .ok_or(WorkExhausted::Limit {
                dimension,
                limit,
                used,
                requested: amount,
            })
    }

    /// Refuse once the deadline has passed, by the monotonic clock.
    pub fn check_deadline(&self) -> Result<(), WorkExhausted> {
        self.check_deadline_at(Instant::now())
    }

    /// Refuse when the deadline has passed at `now`: the one deadline
    /// comparison. Every public operation reaches it with the monotonic
    /// clock; only this module's deterministic schedules supply a time, so
    /// no caller can admit work against a stale one.
    fn check_deadline_at(&self, now: Instant) -> Result<(), WorkExhausted> {
        match self.limit.deadline {
            Some(deadline) if now > deadline => Err(WorkExhausted::Deadline),
            _ => Ok(()),
        }
    }

    /// Whether a unit of work costing at most the aggregate of `bounds`
    /// ([`Work::total`]) may start: the deadline has not passed and each
    /// dimension's total fits what remains. Charges nothing.
    pub fn admits(&self, bounds: &[(Dimension, u64)]) -> Result<(), WorkExhausted> {
        self.admits_at(bounds, Instant::now())
    }

    /// [`Self::admits`] with the deadline decided at `now`.
    fn admits_at(&self, bounds: &[(Dimension, u64)], now: Instant) -> Result<(), WorkExhausted> {
        self.check_deadline_at(now)?;
        let total = self.total(bounds)?;
        for dimension in Dimension::ALL {
            self.fit(dimension, total.get(dimension))?;
        }
        Ok(())
    }

    /// Admit one indivisible unit of work costing at most the aggregate of
    /// `bounds` ([`Work::total`]). The deadline and the headroom are decided
    /// once, here, against the whole aggregate, never clipped: a refusal
    /// changes nothing. The unit then runs on a share whose limits are
    /// exactly the aggregate (zero on every dimension `bounds` does not
    /// name) and which carries no deadline, so work the unit was admitted
    /// for is charged and accounted inside it whenever it finishes. The
    /// share exclusively borrows this meter; what it consumed is accounted
    /// here when it ends, on every path, and what it left unused remains
    /// here. The next unit is admitted afresh, against this meter's
    /// deadline. A scheduler share ([`Self::scope`]) is clipped and keeps
    /// the deadline instead.
    pub fn admit(&mut self, bounds: &[(Dimension, u64)]) -> Result<ScopedMeter<'_>, WorkExhausted> {
        self.admit_at(bounds, Instant::now())
    }

    /// [`Self::admit`] with the deadline decided at `now`.
    fn admit_at(
        &mut self,
        bounds: &[(Dimension, u64)],
        now: Instant,
    ) -> Result<ScopedMeter<'_>, WorkExhausted> {
        self.admits_at(bounds, now)?;
        let total = self.total(bounds)?;
        let mut limit = WorkLimit::unbounded();
        for dimension in Dimension::ALL {
            limit = limit.with(dimension, total.get(dimension));
        }
        Ok(ScopedMeter {
            parent: self,
            share: Self::new(limit),
        })
    }

    /// Account `amount` on `dimension` for work already admitted, whatever
    /// the time: the deadline admits units of work, it does not erase what
    /// an admitted unit did. Refused, charging nothing, only when it would
    /// pass the limit: work measured past its admitted bound.
    pub const fn consume(
        &mut self,
        dimension: Dimension,
        amount: u64,
    ) -> Result<(), WorkExhausted> {
        let index = dimension.index();
        let used = self.used.0[index];
        let limit = self.limit.limits[index];
        match used.checked_add(amount) {
            Some(total) if total <= limit => {
                self.used.0[index] = total;
                Ok(())
            }
            _ => Err(WorkExhausted::Limit {
                dimension,
                limit,
                used,
                requested: amount,
            }),
        }
    }

    /// A share of this meter for one part of the operation: on each
    /// dimension the smaller of `cap`'s limit and what remains here, and the
    /// earlier of the two deadlines. The share borrows this meter, so
    /// nothing else draws on the allowance while the part runs; when the
    /// share is dropped, on every path, what it consumed is accounted here
    /// and what it left unused remains here.
    pub fn scope(&mut self, cap: &WorkLimit) -> ScopedMeter<'_> {
        let mut limit = *cap;
        for dimension in Dimension::ALL {
            let index = dimension.index();
            limit.limits[index] = limit.limits[index].min(self.remaining(dimension));
        }
        limit.deadline = match (self.limit.deadline, cap.deadline) {
            (Some(parent), Some(share)) => Some(parent.min(share)),
            (parent, share) => parent.or(share),
        };
        ScopedMeter {
            parent: self,
            share: Self::new(limit),
        }
    }
}

/// Make room in `out` for one more element, charging any growth of its
/// buffer to `work` before the buffer grows: the requested storage of the
/// added capacity in `T`'s concrete size, computed checked. The buffer
/// doubles (from four), so the charges over a buffer's life sum to its
/// final requested capacity. A refusal leaves `out` and the meter as they
/// were; after success one push cannot allocate. The one way a metered
/// operation grows a result buffer whose final length it cannot know up
/// front: the caller gives up what it pushes only once room is secured.
pub fn reserve_charged<T>(work: &mut dyn Meter, out: &mut Vec<T>) -> Result<(), WorkExhausted> {
    if out.len() == out.capacity() {
        let refused = || WorkExhausted::Limit {
            dimension: Dimension::BytesAllocated,
            limit: work.limit().limit(Dimension::BytesAllocated),
            used: work.used().get(Dimension::BytesAllocated),
            requested: u64::MAX,
        };
        let grown = if out.capacity() == 0 {
            4
        } else {
            out.capacity().checked_mul(2).ok_or_else(refused)?
        };
        let added = grown - out.len();
        let bytes = u64::try_from(added)
            .ok()
            .and_then(|added| added.checked_mul(std::mem::size_of::<T>() as u64))
            .ok_or_else(refused)?;
        work.charge(Dimension::BytesAllocated, bytes)?;
        out.reserve_exact(added);
    }
    Ok(())
}

/// The metering operations of a [`WorkMeter`] and of a share of one
/// ([`ScopedMeter`]).
///
/// What work is charged, admitted and accounted through. It exposes no way
/// to replace a meter or its consumption, so a share's cap and the
/// consumption its parent is owed hold for its whole life.
pub trait Meter {
    /// The limit work is charged against.
    fn limit(&self) -> &WorkLimit;
    /// The work consumed so far.
    fn used(&self) -> &Work;
    /// What remains on `dimension`.
    fn remaining(&self, dimension: Dimension) -> u64;
    /// [`WorkMeter::charge`].
    fn charge(&mut self, dimension: Dimension, amount: u64) -> Result<(), WorkExhausted>;
    /// [`WorkMeter::charge_all`].
    fn charge_all(&mut self, charges: &[(Dimension, u64)]) -> Result<(), WorkExhausted>;
    /// [`WorkMeter::admits`].
    fn admits(&self, bounds: &[(Dimension, u64)]) -> Result<(), WorkExhausted>;
    /// [`WorkMeter::consume`].
    fn consume(&mut self, dimension: Dimension, amount: u64) -> Result<(), WorkExhausted>;
    /// [`WorkMeter::check_deadline`].
    fn check_deadline(&self) -> Result<(), WorkExhausted>;
    /// A share of this meter capped by `cap` ([`WorkMeter::scope`]).
    fn scope(&mut self, cap: &WorkLimit) -> ScopedMeter<'_>;
    /// One admitted indivisible unit ([`WorkMeter::admit`]).
    fn admit(&mut self, bounds: &[(Dimension, u64)]) -> Result<ScopedMeter<'_>, WorkExhausted>;

    /// Account `amount` on `dimension` of work admitted at its bound
    /// ([`Self::admit`]): refused only when the measurement passes what was
    /// admitted, which is a defect of the bound the unit was admitted at,
    /// never a budget the caller may retry against.
    fn account(
        &mut self,
        dimension: Dimension,
        amount: u64,
    ) -> Result<(), crate::error::StoreError> {
        self.consume(dimension, amount).map_err(|error| {
            crate::error::StoreError::Internal(format!(
                "work measured past the bound it was admitted at: {error}"
            ))
        })
    }
}

impl Meter for WorkMeter {
    fn limit(&self) -> &WorkLimit {
        Self::limit(self)
    }
    fn used(&self) -> &Work {
        Self::used(self)
    }
    fn remaining(&self, dimension: Dimension) -> u64 {
        Self::remaining(self, dimension)
    }
    fn charge(&mut self, dimension: Dimension, amount: u64) -> Result<(), WorkExhausted> {
        Self::charge(self, dimension, amount)
    }
    fn charge_all(&mut self, charges: &[(Dimension, u64)]) -> Result<(), WorkExhausted> {
        Self::charge_all(self, charges)
    }
    fn admits(&self, bounds: &[(Dimension, u64)]) -> Result<(), WorkExhausted> {
        Self::admits(self, bounds)
    }
    fn consume(&mut self, dimension: Dimension, amount: u64) -> Result<(), WorkExhausted> {
        Self::consume(self, dimension, amount)
    }
    fn check_deadline(&self) -> Result<(), WorkExhausted> {
        Self::check_deadline(self)
    }
    fn scope(&mut self, cap: &WorkLimit) -> ScopedMeter<'_> {
        Self::scope(self, cap)
    }
    fn admit(&mut self, bounds: &[(Dimension, u64)]) -> Result<ScopedMeter<'_>, WorkExhausted> {
        Self::admit(self, bounds)
    }
}

/// A share of a [`WorkMeter`] (see [`WorkMeter::scope`]), metered through
/// [`Meter`].
///
/// Its own meter is private: nothing can replace it, raise its cap or erase
/// what it consumed, which is what lets its drop account that consumption
/// to the parent exactly.
#[derive(Debug)]
pub struct ScopedMeter<'p> {
    parent: &'p mut WorkMeter,
    share: WorkMeter,
}

impl Meter for ScopedMeter<'_> {
    fn limit(&self) -> &WorkLimit {
        self.share.limit()
    }
    fn used(&self) -> &Work {
        self.share.used()
    }
    fn remaining(&self, dimension: Dimension) -> u64 {
        self.share.remaining(dimension)
    }
    fn charge(&mut self, dimension: Dimension, amount: u64) -> Result<(), WorkExhausted> {
        self.share.charge(dimension, amount)
    }
    fn charge_all(&mut self, charges: &[(Dimension, u64)]) -> Result<(), WorkExhausted> {
        self.share.charge_all(charges)
    }
    fn admits(&self, bounds: &[(Dimension, u64)]) -> Result<(), WorkExhausted> {
        self.share.admits(bounds)
    }
    fn consume(&mut self, dimension: Dimension, amount: u64) -> Result<(), WorkExhausted> {
        self.share.consume(dimension, amount)
    }
    fn check_deadline(&self) -> Result<(), WorkExhausted> {
        self.share.check_deadline()
    }
    /// A share of this share: it borrows this share's private meter, so its
    /// consumption reaches this share's parent through this share.
    fn scope(&mut self, cap: &WorkLimit) -> ScopedMeter<'_> {
        self.share.scope(cap)
    }
    /// A unit of this share: admitted against what the share has left and
    /// its deadline, accounted to the share's parent through the share.
    fn admit(&mut self, bounds: &[(Dimension, u64)]) -> Result<ScopedMeter<'_>, WorkExhausted> {
        self.share.admit(bounds)
    }
}

impl Drop for ScopedMeter<'_> {
    /// The share's consumption becomes the parent's, exactly. The share's
    /// limit was at most what the parent had left on each dimension when the
    /// share was made, the parent has been exclusively borrowed since, and
    /// every mutation of the share's meter is checked against that limit, so
    /// the parent's consumption plus the share's never passes the parent's
    /// limit and the addition cannot overflow.
    fn drop(&mut self) {
        for dimension in Dimension::ALL {
            let index = dimension.index();
            self.parent.used.0[index] += self.share.used.0[index];
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn charges_are_checked_before_work_and_refusals_charge_nothing() -> Result<(), WorkExhausted> {
        let mut meter = WorkMeter::new(
            WorkLimit::unbounded()
                .with(Dimension::BytesAllocated, 100)
                .with(Dimension::Entries, 3),
        );
        meter.charge(Dimension::BytesAllocated, 60)?;
        let refused = meter.charge(Dimension::BytesAllocated, 41);
        assert_eq!(
            refused,
            Err(WorkExhausted::Limit {
                dimension: Dimension::BytesAllocated,
                limit: 100,
                used: 60,
                requested: 41,
            })
        );
        assert_eq!(meter.used().get(Dimension::BytesAllocated), 60);
        assert_eq!(meter.remaining(Dimension::BytesAllocated), 40);
        assert!(
            meter.charge(Dimension::BytesHashed, u64::MAX).is_ok(),
            "unbounded"
        );
        assert!(
            meter.charge(Dimension::BytesHashed, 1).is_err(),
            "never wraps"
        );
        let before = *meter.used();
        assert!(
            meter
                .charge_all(&[(Dimension::Entries, 2), (Dimension::BytesAllocated, 41)])
                .is_err()
        );
        assert_eq!(meter.used(), &before, "charge_all is all or nothing");
        meter.charge_all(&[(Dimension::Entries, 3), (Dimension::BytesAllocated, 40)])?;
        assert_eq!(meter.remaining(Dimension::Entries), 0);
        Ok(())
    }

    /// Admission charges nothing and refuses past the deadline or the
    /// headroom; consumption of admitted work is accounted after the
    /// deadline and refused only past the limit.
    #[test]
    fn admitted_work_is_consumed_whatever_the_time() -> Result<(), WorkExhausted> {
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let mut meter = WorkMeter::new(
            WorkLimit::unbounded()
                .with(Dimension::BytesRead, 10)
                .with_deadline(Instant::now() + Duration::from_secs(3600)),
        );
        meter.admits(&[(Dimension::BytesRead, 10)])?;
        assert_eq!(
            meter.used().get(Dimension::BytesRead),
            0,
            "admission charges nothing"
        );
        assert!(meter.admits(&[(Dimension::BytesRead, 11)]).is_err());
        let mut late = WorkMeter::new(
            WorkLimit::unbounded()
                .with(Dimension::BytesRead, 10)
                .with_deadline(past),
        );
        if Instant::now() > past {
            assert_eq!(late.admits(&[]), Err(WorkExhausted::Deadline));
        }
        late.consume(Dimension::BytesRead, 7)?;
        assert_eq!(
            late.used().get(Dimension::BytesRead),
            7,
            "accounted after the deadline"
        );
        assert!(
            late.consume(Dimension::BytesRead, 4).is_err(),
            "never past the limit"
        );
        assert_eq!(late.used().get(Dimension::BytesRead), 7);
        meter.consume(Dimension::BytesRead, 10)?;
        Ok(())
    }

    /// A share is capped by what the parent has left and by its own cap,
    /// takes the earlier deadline, and returns its exact consumption to the
    /// parent on every path, early return and error included.
    #[test]
    fn a_share_is_bounded_and_accounted_on_every_path() -> Result<(), WorkExhausted> {
        let mut parent = WorkMeter::new(
            WorkLimit::unbounded()
                .with(Dimension::Entries, 10)
                .with(Dimension::Signatures, 4),
        );
        parent.charge(Dimension::Entries, 3)?;
        let capped = WorkLimit::unbounded().with(Dimension::Signatures, 2);
        {
            let mut share = parent.scope(&capped);
            assert_eq!(
                share.remaining(Dimension::Entries),
                7,
                "borrows what is left"
            );
            assert_eq!(share.remaining(Dimension::Signatures), 2, "capped");
            share.charge(Dimension::Entries, 5)?;
            assert!(share.charge(Dimension::Signatures, 3).is_err());
            share.charge(Dimension::Signatures, 2)?;
        }
        assert_eq!(parent.used().get(Dimension::Entries), 8);
        assert_eq!(parent.used().get(Dimension::Signatures), 2);
        let uncapped = WorkLimit::unbounded();
        let failed = (|| -> Result<(), WorkExhausted> {
            let mut share = parent.scope(&uncapped);
            share.charge(Dimension::Entries, 1)?;
            share.charge(Dimension::Entries, 5)?;
            Ok(())
        })();
        assert!(failed.is_err());
        assert_eq!(
            parent.used().get(Dimension::Entries),
            9,
            "the work done before the refusal is the parent's"
        );
        let soon = Instant::now() + Duration::from_secs(60);
        let deadline = WorkLimit::unbounded().with_deadline(soon);
        let share = parent.scope(&deadline);
        assert_eq!(Meter::limit(&share).deadline(), Some(soon));
        drop(share);
        assert_eq!(
            parent.remaining(Dimension::Entries),
            1,
            "unused share returns"
        );
        Ok(())
    }

    /// A share of a share is capped by both and reaches the outermost meter
    /// through the share it was taken from.
    #[test]
    fn nested_shares_account_through_their_parent() -> Result<(), WorkExhausted> {
        let mut parent = WorkMeter::new(WorkLimit::unbounded().with(Dimension::Entries, 10));
        let outer_cap = WorkLimit::unbounded().with(Dimension::Entries, 6);
        let inner_cap = WorkLimit::unbounded().with(Dimension::Entries, 8);
        {
            let mut outer = parent.scope(&outer_cap);
            {
                let mut inner = outer.scope(&inner_cap);
                assert_eq!(
                    inner.remaining(Dimension::Entries),
                    6,
                    "capped by the outer share"
                );
                inner.charge(Dimension::Entries, 4)?;
            }
            assert_eq!(Meter::used(&outer).get(Dimension::Entries), 4);
            outer.charge(Dimension::Entries, 2)?;
            assert!(outer.charge(Dimension::Entries, 1).is_err());
        }
        assert_eq!(parent.used().get(Dimension::Entries), 6);
        Ok(())
    }

    /// The consumption between two readings of one meter is exactly what was
    /// charged and consumed between them, and sums back to the later one.
    #[test]
    fn consumption_since_a_reading_is_exact() -> Result<(), WorkExhausted> {
        let mut meter = WorkMeter::unbounded();
        meter.charge(Dimension::Entries, 4)?;
        let earlier = *meter.used();
        meter.charge(Dimension::Entries, 3)?;
        meter.consume(Dimension::Signatures, 2)?;
        let between = meter.used().since(&earlier);
        assert_eq!(between.get(Dimension::Entries), 3);
        assert_eq!(between.get(Dimension::Signatures), 2);
        assert_eq!(between.get(Dimension::BytesHashed), 0);
        assert_eq!(&earlier.saturating_add(&between), meter.used());
        Ok(())
    }

    /// A dimension named twice is admitted and charged as its sum: each
    /// amount fits alone, the sum does not, and nothing is charged.
    #[test]
    fn repeated_dimensions_aggregate_everywhere() {
        let mut meter = WorkMeter::new(WorkLimit::unbounded().with(Dimension::Entries, 3));
        let bound = [(Dimension::Entries, 2), (Dimension::Entries, 2)];
        assert!(meter.admits(&bound).is_err(), "admission sums");
        assert!(meter.charge_all(&bound).is_err(), "charging sums");
        assert!(meter.admit(&bound).is_err(), "a unit sums");
        assert_eq!(meter.used(), &Work::default(), "a refusal charges nothing");
        assert_eq!(
            Work::total(&bound).map(|total| total.get(Dimension::Entries)),
            Ok(4)
        );
    }

    /// An aggregate that overflows is refused before anything changes.
    #[test]
    fn an_overflowing_aggregate_changes_nothing() -> Result<(), WorkExhausted> {
        let mut meter = WorkMeter::unbounded();
        meter.charge(Dimension::Handles, 1)?;
        let before = *meter.used();
        let bound = [
            (Dimension::Handles, 1),
            (Dimension::Entries, u64::MAX),
            (Dimension::Entries, 1),
        ];
        assert_eq!(Work::total(&bound), Err(Dimension::Entries));
        assert!(meter.charge_all(&bound).is_err());
        assert!(meter.admit(&bound).is_err());
        assert_eq!(meter.used(), &before);
        Ok(())
    }

    /// Through the actual admission path: a unit admitted at a supplied
    /// time before the deadline charges and accounts its work, its share
    /// keeping no deadline; its consumption reaches the parent exactly when
    /// it ends; the next unit, admitted at a supplied time after the
    /// deadline, is refused. The unit is capped at exactly its bound, zero
    /// on the dimensions it does not name.
    #[test]
    fn an_admitted_unit_finishes_after_the_deadline() -> Result<(), WorkExhausted> {
        let deadline = Instant::now() + Duration::from_secs(3600);
        let before = deadline - Duration::from_secs(1);
        let after = deadline + Duration::from_secs(1);
        let mut meter = WorkMeter::new(
            WorkLimit::unbounded()
                .with(Dimension::Entries, 10)
                .with_deadline(deadline),
        );
        {
            let mut unit = meter.admit_at(&[(Dimension::Entries, 2)], before)?;
            assert_eq!(unit.remaining(Dimension::Entries), 2, "exactly the bound");
            assert_eq!(unit.remaining(Dimension::Handles), 0, "nothing unnamed");
            assert!(
                unit.limit().deadline().is_none(),
                "the unit keeps no deadline"
            );
            unit.charge(Dimension::Entries, 1)?;
            unit.consume(Dimension::Entries, 1)?;
            assert!(unit.charge(Dimension::Entries, 1).is_err(), "never past it");
        }
        assert_eq!(meter.used().get(Dimension::Entries), 2);
        assert_eq!(
            meter.admit_at(&[(Dimension::Entries, 1)], after).err(),
            Some(WorkExhausted::Deadline),
            "the next unit is admitted against the deadline"
        );
        assert_eq!(meter.check_deadline_at(after), Err(WorkExhausted::Deadline));
        assert_eq!(meter.check_deadline_at(before), Ok(()));
        Ok(())
    }

    /// A unit ended by an error accounts what it consumed exactly once,
    /// and returns what it did not use; a unit nested in a share reaches
    /// the outermost meter once, through the share.
    #[test]
    fn a_unit_accounts_once_on_every_path() -> Result<(), WorkExhausted> {
        let mut meter = WorkMeter::new(WorkLimit::unbounded().with(Dimension::Entries, 10));
        let failed = (|| -> Result<(), WorkExhausted> {
            let mut unit = meter.admit(&[(Dimension::Entries, 4)])?;
            unit.charge(Dimension::Entries, 1)?;
            unit.charge(Dimension::Entries, 9)?;
            Ok(())
        })();
        assert!(failed.is_err());
        assert_eq!(meter.used().get(Dimension::Entries), 1, "consumed, once");
        assert_eq!(meter.remaining(Dimension::Entries), 9, "unused returns");
        {
            let cap = WorkLimit::unbounded().with(Dimension::Entries, 5);
            let mut share = meter.scope(&cap);
            {
                let mut unit = share.admit(&[(Dimension::Entries, 3)])?;
                unit.charge(Dimension::Entries, 2)?;
            }
            assert!(
                share.admit(&[(Dimension::Entries, 4)]).is_err(),
                "the share bounds it"
            );
        }
        assert_eq!(meter.used().get(Dimension::Entries), 3);
        Ok(())
    }

    /// Accumulation sums every dimension, and an overflow on any one leaves
    /// the accumulated amount exactly as it was.
    #[test]
    fn checked_accumulation_is_all_or_nothing() {
        let mut total = Work::default()
            .with(Dimension::Entries, 2)
            .with(Dimension::BytesRead, u64::MAX - 1);
        let part = Work::default()
            .with(Dimension::Entries, 3)
            .with(Dimension::BytesHashed, 7);
        assert_eq!(total.checked_add_assign(&part), Ok(()));
        assert_eq!(total.get(Dimension::Entries), 5);
        assert_eq!(total.get(Dimension::BytesHashed), 7);
        let before = total;
        let overflowing = Work::default()
            .with(Dimension::Entries, 1)
            .with(Dimension::BytesRead, 2);
        assert_eq!(
            total.checked_add_assign(&overflowing),
            Err(Dimension::BytesRead)
        );
        assert_eq!(total, before, "a refused sum changes nothing");
    }

    /// A deadline learned later only ever moves earlier, and the meter then
    /// refuses against it.
    #[test]
    fn a_tightened_deadline_never_extends_the_allowance() {
        let now = Instant::now();
        let early = now + Duration::from_secs(60);
        let late = now + Duration::from_secs(3600);
        let mut meter = WorkMeter::unbounded();
        meter.tighten_deadline(late);
        assert_eq!(meter.limit().deadline(), Some(late));
        meter.tighten_deadline(early);
        assert_eq!(meter.limit().deadline(), Some(early));
        meter.tighten_deadline(late);
        assert_eq!(meter.limit().deadline(), Some(early), "never extended");
        assert_eq!(
            meter.check_deadline_at(early + Duration::from_secs(1)),
            Err(WorkExhausted::Deadline)
        );
    }

    #[test]
    fn a_passed_deadline_refuses_every_charge() {
        let past = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap_or_else(Instant::now);
        let mut meter = WorkMeter::new(WorkLimit::unbounded().with_deadline(past));
        if Instant::now() > past {
            assert_eq!(
                meter.charge(Dimension::Entries, 0),
                Err(WorkExhausted::Deadline)
            );
        }
    }
}
