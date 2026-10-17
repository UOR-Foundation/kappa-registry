//! Ordered traversal of the keys of one projected family that hold a
//! completed put (`projection`), as a `FallibleCursor`: the registry-wide
//! identity listing over `Family::Catalog`. The cursor owns its
//! [`ProjectionRead`], so it reads one registry snapshot for its life, and
//! copies only the current key. A storage failure is latched: every later
//! call reports it.

use std::sync::Arc;

use kappa_cursor::FallibleCursor;
use kappa_store::StoreError;

use crate::projection::{Family, ProjectionRead};
use crate::redb_cursor::RedbCursor;

pub struct ProjectionKeyCursor {
    read: ProjectionRead,
    family: Family,
    head: Option<Vec<u8>>,
    failure: Option<Arc<StoreError>>,
    remaining: u64,
}

impl ProjectionKeyCursor {
    /// A cursor at the first visible key of `family`.
    pub(crate) fn new(read: ProjectionRead, family: Family) -> Result<Self, StoreError> {
        let remaining = read.version_count()?;
        let head = read.next_key(family, &[])?;
        Ok(Self {
            read,
            family,
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

    /// Move to the first visible key at or after `from`.
    fn load(&mut self, from: &[u8]) -> Result<(), StoreError> {
        match self.read.next_key(self.family, from) {
            Ok(head) => {
                if head.is_none() {
                    self.remaining = 0;
                }
                self.head = head;
                Ok(())
            }
            Err(error) => {
                self.head = None;
                let error = Arc::new(error);
                let result = RedbCursor::retained_error(&error);
                self.failure = Some(error);
                Err(result)
            }
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
            // The least key greater than `head`.
            let mut successor = head;
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
