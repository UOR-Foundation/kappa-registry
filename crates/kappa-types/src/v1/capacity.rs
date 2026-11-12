//! Retained capacity: what an owner holds while it holds it.
//!
//! A [`CapacityPool`] bounds one retained quantity of a process (bytes of
//! decoded deltas in flight, bytes of retained publication evidence, open
//! preparations, ...). A [`Reservation`] is the charge one owner holds
//! against it: taken with checked arithmetic before the resource exists,
//! released when the reservation drops, and moved between owners
//! explicitly ([`Reservation::split`], [`Reservation::merge`]) so a charge
//! is never released while the resource it accounts for is still held.
//! A reservation taken at a checked upper bound is reduced to the measured
//! amount with [`Reservation::shrink`] once the work is done.
//!
//! Closure is separate from measured use. A closed pool refuses every new
//! reservation, whatever its headroom, and keeps every reservation already
//! held: closing a pool never erases a charge. A pool closes when part of
//! its debt is unmeasured (`CapacityPool::close`), and reopens only when
//! the owner that closed it establishes the debt.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Why a reservation was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CapacityError {
    /// The pool cannot hold the amount alongside what is reserved.
    #[error("{pool}: {requested} requested, {available} of {limit} available")]
    Exhausted {
        pool: &'static str,
        requested: u64,
        available: u64,
        limit: u64,
    },
    /// The pool is closed: part of its debt is unmeasured.
    #[error("{pool} is closed until its unmeasured debt is established")]
    Closed { pool: &'static str },
    /// Two reservations of different pools cannot combine.
    #[error("reservations of {left} and {right} cannot combine")]
    Mismatched {
        left: &'static str,
        right: &'static str,
    },
    /// A split or shrink names more than the reservation holds.
    #[error("{pool}: {requested} exceeds the {held} this reservation holds")]
    Exceeds {
        pool: &'static str,
        requested: u64,
        held: u64,
    },
}

/// One bounded retained quantity (see the module documentation).
#[derive(Debug)]
pub struct CapacityPool {
    name: &'static str,
    limit: u64,
    used: AtomicU64,
    closed: AtomicBool,
}

impl CapacityPool {
    pub const fn new(name: &'static str, limit: u64) -> Self {
        Self {
            name,
            limit,
            used: AtomicU64::new(0),
            closed: AtomicBool::new(false),
        }
    }

    pub const fn name(&self) -> &'static str {
        self.name
    }
    pub const fn limit(&self) -> u64 {
        self.limit
    }
    /// The amount every outstanding reservation holds.
    pub fn used(&self) -> u64 {
        self.used.load(Ordering::Acquire)
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    /// Refuse every new reservation until [`Self::reopen`].
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
    }

    /// Admit reservations again.
    pub fn reopen(&self) {
        self.closed.store(false, Ordering::Release);
    }

    /// Reserve `amount`, refusing when the pool is closed or cannot hold it.
    pub fn reserve(self: &Arc<Self>, amount: u64) -> Result<Reservation, CapacityError> {
        if self.is_closed() {
            return Err(CapacityError::Closed { pool: self.name });
        }
        self.used
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(amount)
                    .filter(|total| *total <= self.limit)
            })
            .map_err(|used| CapacityError::Exhausted {
                pool: self.name,
                requested: amount,
                available: self.limit.saturating_sub(used),
                limit: self.limit,
            })?;
        Ok(Reservation {
            pool: Arc::clone(self),
            amount,
        })
    }

    fn release(&self, amount: u64) {
        // Every release returns an amount a reservation of this pool held,
        // so the subtraction cannot pass zero.
        self.used.fetch_sub(amount, Ordering::AcqRel);
    }
}

/// A charge against one pool, released on drop.
#[derive(Debug)]
#[must_use = "dropping a reservation releases its charge"]
pub struct Reservation {
    pool: Arc<CapacityPool>,
    amount: u64,
}

impl Reservation {
    pub const fn amount(&self) -> u64 {
        self.amount
    }
    pub const fn pool(&self) -> &Arc<CapacityPool> {
        &self.pool
    }

    /// Reduce the charge to `amount`, releasing the rest: a reservation
    /// taken at a checked upper bound keeps what the work measured.
    pub fn shrink(&mut self, amount: u64) -> Result<(), CapacityError> {
        let released = self
            .amount
            .checked_sub(amount)
            .ok_or(CapacityError::Exceeds {
                pool: self.pool.name,
                requested: amount,
                held: self.amount,
            })?;
        self.pool.release(released);
        self.amount = amount;
        Ok(())
    }

    /// Move `amount` of this charge to a new reservation of the same pool,
    /// for another owner.
    pub fn split(&mut self, amount: u64) -> Result<Self, CapacityError> {
        self.amount = self
            .amount
            .checked_sub(amount)
            .ok_or(CapacityError::Exceeds {
                pool: self.pool.name,
                requested: amount,
                held: self.amount,
            })?;
        Ok(Self {
            pool: Arc::clone(&self.pool),
            amount,
        })
    }

    /// Take over `other`'s charge, which must be of the same pool.
    pub fn merge(&mut self, mut other: Self) -> Result<(), CapacityError> {
        if !Arc::ptr_eq(&self.pool, &other.pool) {
            return Err(CapacityError::Mismatched {
                left: self.pool.name,
                right: other.pool.name,
            });
        }
        // The pool total already counts both charges; the sum of two
        // charges the pool held cannot exceed its limit.
        self.amount += other.amount;
        other.amount = 0;
        Ok(())
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if self.amount > 0 {
            self.pool.release(self.amount);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), CapacityError>;

    #[test]
    fn reservations_are_bounded_released_and_transferred() -> TestResult {
        let pool = Arc::new(CapacityPool::new("test pool", 100));
        let mut first = pool.reserve(60)?;
        assert!(matches!(
            pool.reserve(41),
            Err(CapacityError::Exhausted { available: 40, .. })
        ));
        let second = first.split(20)?;
        assert_eq!((first.amount(), second.amount(), pool.used()), (40, 20, 60));
        first.shrink(10)?;
        assert_eq!(pool.used(), 30);
        assert!(first.shrink(11).is_err(), "shrink cannot grow a charge");
        first.merge(second)?;
        assert_eq!((first.amount(), pool.used()), (30, 30));
        drop(first);
        assert_eq!(pool.used(), 0);
        let max = pool.reserve(100)?;
        assert!(matches!(
            pool.reserve(u64::MAX),
            Err(CapacityError::Exhausted { .. })
        ));
        drop(max);
        Ok(())
    }

    #[test]
    fn closure_refuses_new_charges_and_keeps_held_ones() -> TestResult {
        let pool = Arc::new(CapacityPool::new("test pool", 100));
        let held = pool.reserve(30)?;
        pool.close();
        assert_eq!(
            pool.reserve(1).err(),
            Some(CapacityError::Closed { pool: "test pool" })
        );
        assert_eq!(pool.used(), 30, "closing never erases a charge");
        pool.reopen();
        let more = pool.reserve(70)?;
        drop((held, more));
        assert_eq!(pool.used(), 0);
        Ok(())
    }

    #[test]
    fn reservations_of_different_pools_do_not_combine() -> TestResult {
        let a = Arc::new(CapacityPool::new("a", 10));
        let b = Arc::new(CapacityPool::new("b", 10));
        let mut left = a.reserve(1)?;
        let right = b.reserve(1)?;
        assert!(matches!(
            left.merge(right),
            Err(CapacityError::Mismatched { .. })
        ));
        assert_eq!(
            (a.used(), b.used()),
            (1, 0),
            "the refused charge was released"
        );
        Ok(())
    }
}
