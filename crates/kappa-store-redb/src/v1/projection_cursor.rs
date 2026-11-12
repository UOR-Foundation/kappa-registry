//! Ordered traversal of the keys of one projected family that hold a
//! completed put (`projection`), as a `FallibleCursor`: the registry-wide
//! identity listing over `Family::Catalog`. The cursor owns its
//! [`ProjectionRead`], so it reads one registry snapshot for its life, and
//! copies only the current key. It is one read operation: every key it
//! finds is found on the one meter it was made with, so a traversal of any
//! length stays within that allowance. A storage failure or a refusal of
//! the allowance is latched: every later call reports it.

use std::sync::Arc;

use kappa_cursor::FallibleCursor;
use kappa_store::StoreError;
use kappa_store::work::{Dimension, WorkMeter};

use crate::projection::{Family, ProjectionRead};
use crate::redb_cursor::RedbCursor;

pub struct ProjectionKeyCursor {
    read: ProjectionRead,
    family: Family,
    work: WorkMeter,
    head: Option<Vec<u8>>,
    failure: Option<Arc<StoreError>>,
    remaining: u64,
}

impl ProjectionKeyCursor {
    /// A cursor at the first visible key of `family`, finding keys on
    /// `work` for its life.
    pub(crate) fn new(
        read: ProjectionRead,
        family: Family,
        mut work: WorkMeter,
    ) -> Result<Self, StoreError> {
        let remaining = read.version_count()?;
        let head = read.next_key(family, &[], &mut work)?;
        Ok(Self {
            read,
            family,
            work,
            head,
            failure: None,
            remaining,
        })
    }

    fn ensure_valid(&self) -> Result<(), StoreError> {
        self.failure
            .as_ref()
            .map_or_else(|| Ok(()), |error| Err(RedbCursor::retained_error(error)))
    }

    /// Latch `error`: the cursor reports it from now on.
    fn fail(&mut self, error: StoreError) -> StoreError {
        self.head = None;
        let error = Arc::new(error);
        let result = RedbCursor::retained_error(&error);
        self.failure = Some(error);
        result
    }

    /// Move to the first visible key at or after `from`.
    fn load(&mut self, from: &[u8]) -> Result<(), StoreError> {
        match self.read.next_key(self.family, from, &mut self.work) {
            Ok(head) => {
                if head.is_none() {
                    self.remaining = 0;
                }
                self.head = head;
                Ok(())
            }
            Err(error) => Err(self.fail(error)),
        }
    }
}

impl FallibleCursor for ProjectionKeyCursor {
    type Error = StoreError;

    fn key(&self) -> Result<Option<&[u8]>, StoreError> {
        self.ensure_valid()?;
        Ok(self.head.as_deref())
    }

    fn advance(&mut self) -> Result<Option<&[u8]>, StoreError> {
        self.ensure_valid()?;
        if let Some(head) = self.head.take() {
            self.remaining = self.remaining.saturating_sub(1);
            // The least key greater than `head`: `head` and a zero byte,
            // in a buffer of exactly that length, charged before it is made.
            let length = head.len() + 1;
            if let Err(refused) = self.work.charge(Dimension::BytesAllocated, length as u64) {
                return Err(self.fail(refused.into()));
            }
            let mut successor = Vec::with_capacity(length);
            successor.extend_from_slice(&head);
            successor.push(0);
            self.load(&successor)?;
        }
        self.key()
    }

    fn seek(&mut self, target: &[u8]) -> Result<Option<&[u8]>, StoreError> {
        self.ensure_valid()?;
        if self.head.as_deref().is_some_and(|head| head < target) {
            self.load(target)?;
        }
        self.key()
    }

    fn size_hint(&self) -> u64 {
        self.remaining
    }

    fn cost(&self) -> u64 {
        // An upper bound: the versions left to pass over, not a measured
        // latency.
        self.remaining
    }
}
