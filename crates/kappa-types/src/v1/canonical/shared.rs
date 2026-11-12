//! Fallibly allocated, strong-only sharing of a permit-bearing record.
//!
//! The allocation layout belongs to this owner. No standard-library private
//! Arc layout, raw-pointer conversion, weak reference, or copy-on-write escape
//! is exposed. Reference counting uses release on drop and acquire before
//! destruction, as in Arc; clones only extend immutable ownership.

use std::alloc::{Layout, alloc, dealloc};
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering, fence};

use super::Record;
use crate::capacity::{CapacityPool, Reservation};
use crate::error::StoreError;
use crate::work::{Dimension, Meter};

#[cfg(test)]
#[path = "shared_tests.rs"]
mod tests;

struct Allocation<T> {
    references: AtomicUsize,
    record: Record<T>,
    reservation: Reservation,
}

pub(crate) struct SharedRecord<T> {
    pointer: NonNull<Allocation<T>>,
    owner: PhantomData<Allocation<T>>,
}

// SAFETY: only immutable access is exposed. Every owner keeps the allocation
// alive through the atomic count. T's destruction can occur on any owner thread.
unsafe impl<T: Send + Sync> Send for SharedRecord<T> {}
// SAFETY: shared access reaches only immutable T and an atomic reference count.
unsafe impl<T: Send + Sync> Sync for SharedRecord<T> {}

impl<T> SharedRecord<T> {
    pub(crate) const fn allocation_bytes() -> u64 {
        std::mem::size_of::<Allocation<T>>() as u64
    }

    /// Called inside the complete root-construction admission. On any failure,
    /// the input record releases its permits and no shared owner is published.
    pub(crate) fn new(
        record: Record<T>,
        work: &mut dyn Meter,
        pool: &Arc<CapacityPool>,
    ) -> Result<Self, StoreError> {
        let bytes = Self::allocation_bytes();
        work.account(Dimension::BytesAllocated, bytes)?;
        let reservation = pool
            .reserve(bytes)
            .map_err(|error| StoreError::CapacityExceeded(error.to_string()))?;
        let layout = Layout::new::<Allocation<T>>();
        // SAFETY: Allocation contains an AtomicUsize and is nonzero-sized.
        // The pointer is checked before initialization and uses its own layout.
        let pointer =
            NonNull::new(unsafe { alloc(layout) }.cast::<Allocation<T>>()).ok_or_else(|| {
                StoreError::CapacityExceeded("shared record allocation failed".into())
            })?;
        // SAFETY: the allocation is aligned, uniquely owned, and uninitialized.
        unsafe {
            pointer.as_ptr().write(Allocation {
                references: AtomicUsize::new(1),
                record,
                reservation,
            });
        }
        Ok(Self {
            pointer,
            owner: PhantomData,
        })
    }

    pub(crate) fn value(&self) -> &T {
        // SAFETY: this strong owner keeps the initialized allocation alive.
        unsafe { self.pointer.as_ref() }.record.value()
    }
}

impl<T> Clone for SharedRecord<T> {
    fn clone(&self) -> Self {
        // SAFETY: this owner prevents concurrent destruction of the count.
        let previous = unsafe { self.pointer.as_ref() }
            .references
            .fetch_add(1, Ordering::Relaxed);
        // As for Arc, reaching the signed pointer-sized maximum requires
        // forgetting an impossible number of live owners. Never permit wrap.
        if previous >= isize::MAX as usize {
            std::process::abort();
        }
        Self {
            pointer: self.pointer,
            owner: PhantomData,
        }
    }
}

impl<T> Drop for SharedRecord<T> {
    fn drop(&mut self) {
        // SAFETY: this owner contributes one reference until this decrement.
        if unsafe { self.pointer.as_ref() }
            .references
            .fetch_sub(1, Ordering::Release)
            != 1
        {
            return;
        }
        fence(Ordering::Acquire);
        // Deallocate and return capacity even if dropping a generic T unwinds.
        struct Release<T> {
            pointer: NonNull<Allocation<T>>,
            _reservation: Reservation,
        }
        impl<T> Drop for Release<T> {
            fn drop(&mut self) {
                // SAFETY: the last owner created this guard with the original
                // allocation and layout. The record has been dropped first.
                unsafe { dealloc(self.pointer.as_ptr().cast(), Layout::new::<Allocation<T>>()) };
            }
        }
        // SAFETY: the last strong owner has exclusive destruction rights;
        // no Weak or raw owner can access the allocation after this point.
        unsafe {
            let pointer = self.pointer.as_ptr();
            let release = Release {
                pointer: self.pointer,
                _reservation: std::ptr::read(&raw const (*pointer).reservation),
            };
            std::ptr::drop_in_place(&raw mut (*pointer).record);
            drop(release);
        }
    }
}
