//! Pause points inside the store's commit paths, for tests that must
//! deterministically interleave a publication with a rotation.
//!
//! Each point runs the hook installed for it, if any, on the thread that
//! reaches it, while that thread holds whatever the point documents. The
//! hook runs after its slot's lock is released, so a hook may clear or
//! replace itself, and a blocked hook never blocks clearing.

use std::sync::{Arc, Mutex};

#[path = "namespace_lifecycle_tests.rs"]
mod lifecycle_tests;

thread_local! {
    pub(crate) static ACTIVITY_RELEASE: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

pub fn activity_released() {
    ACTIVITY_RELEASE.with(|slot| {
        if let Some(hook) = slot.borrow_mut().take() {
            hook();
        }
    });
}

type Hook = Arc<dyn Fn() + Send + Sync>;

/// The outcome the next registry commit reports in place of its own
/// (`Registry::inject_commit_fault`): both schedules of a commit whose
/// outcome redb leaves unknown, run through the production classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitFault {
    /// The transaction commits; its caller is told the outcome is unknown.
    PersistedUnknown,
    /// The transaction is rolled back; its caller is told the outcome is
    /// unknown.
    AbortedUnknown,
}

/// A point in a commit path where a test may pause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Point {
    /// An epoch's write transaction has returned from `commit`, successfully
    /// or not; the shared activation gate is held and the published-time
    /// bound is not yet raised.
    AfterEpochCommit,
    /// A rotation holds its control namespace's writer and has not yet
    /// requested the exclusive activation gate.
    RotationWriterHeld,
    /// A rotation holds the database writer and the exclusive activation
    /// gate, has found every witness standing, and has not committed.
    RotationStandingChecked,
    /// Recovery has read a head and has not installed its cached number.
    RecoveryHeadRead,
}

#[derive(Default)]
pub struct TestHooks {
    after_epoch_commit: Mutex<Option<Hook>>,
    rotation_writer_held: Mutex<Option<Hook>>,
    rotation_standing_checked: Mutex<Option<Hook>>,
    recovery_head_read: Mutex<Option<Hook>>,
    /// While set, installing a committed assignment on its controller
    /// fails, as a plane this node stops serving would make it fail.
    refuse_assignment_refresh: std::sync::atomic::AtomicBool,
    /// While set, an activation's governing epoch is refused at the last
    /// point before its commit: a known noncommit.
    refuse_activation_commit: std::sync::atomic::AtomicBool,
}

impl TestHooks {
    pub fn refuse_activation_commit(&self, refuse: bool) {
        self.refuse_activation_commit
            .store(refuse, std::sync::atomic::Ordering::Release);
    }

    pub fn activation_commit_refused(&self) -> bool {
        self.refuse_activation_commit
            .load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn refuse_assignment_refresh(&self, refuse: bool) {
        self.refuse_assignment_refresh
            .store(refuse, std::sync::atomic::Ordering::Release);
    }

    pub fn assignment_refresh_refused(&self) -> bool {
        self.refuse_assignment_refresh
            .load(std::sync::atomic::Ordering::Acquire)
    }

    fn slot(&self, point: Point) -> &Mutex<Option<Hook>> {
        match point {
            Point::AfterEpochCommit => &self.after_epoch_commit,
            Point::RotationWriterHeld => &self.rotation_writer_held,
            Point::RotationStandingChecked => &self.rotation_standing_checked,
            Point::RecoveryHeadRead => &self.recovery_head_read,
        }
    }

    /// Run `hook` every time a thread reaches `point`, until cleared.
    pub fn install(&self, point: Point, hook: impl Fn() + Send + Sync + 'static) {
        *self
            .slot(point)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(hook));
    }

    pub fn clear(&self, point: Point) {
        *self
            .slot(point)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }

    pub fn reach(&self, point: Point) {
        let hook = self
            .slot(point)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook {
            hook();
        }
    }
}
