//! Physical inventory of a backend's content storage.
//!
//! Committed rows own representations; a representation that no committed
//! row owns (a preparation that never installed, a publication that
//! aborted, a deletion interrupted between its steps) is physical residue
//! that only the backend can recognize. The inventory is bounded and
//! resumable: each call examines at most `limit` entries from where the
//! previous call stopped and reports whether the pass reached the end, so
//! a maintenance task settles a large store across ticks without holding
//! anything for the whole of it.

use kappa_types::error::StoreError;

/// Outcome of one bounded inventory step.
///
/// Every entry examined is counted under exactly one of `files`, `owned`,
/// `protected`, `unrecognized`, `absent` or `failed`, so the figures
/// distinguish measured reclamation from logical ownership, from
/// protection by readers and preparations, from residue the backend cannot
/// classify, and from removals that failed and remain owed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reclamation {
    /// Representations deleted.
    pub files: u64,
    /// Bytes those representations held.
    pub bytes: u64,
    /// Entries a committed row (or a published generation) owns.
    pub owned: u64,
    /// Entries protected by a reader, an in-flight preparation, or a
    /// concurrent reclamation claim.
    pub protected: u64,
    /// Entries the backend's layout does not explain; left in place and
    /// reported.
    pub unrecognized: u64,
    /// Entries whose storage was already gone when examined (another entry
    /// of a representation whose deletion, decided at its first entry,
    /// removed every entry; a file unlinked meanwhile).
    pub absent: u64,
    /// Removals attempted that failed. The representation stays owed, its
    /// bytes stay charged, and a later step retries it.
    pub failed: u64,
    /// The pass reached the end of the inventory; the next call starts
    /// over from the beginning.
    pub complete: bool,
}

impl Reclamation {
    /// Entries examined and left in place, for logs and summaries.
    #[must_use]
    pub const fn retained(&self) -> u64 {
        self.owned
            .saturating_add(self.protected)
            .saturating_add(self.unrecognized)
    }

    /// Add another step's figures to this one.
    pub const fn accumulate(&mut self, step: &Self) {
        self.files = self.files.saturating_add(step.files);
        self.bytes = self.bytes.saturating_add(step.bytes);
        self.owned = self.owned.saturating_add(step.owned);
        self.protected = self.protected.saturating_add(step.protected);
        self.unrecognized = self.unrecognized.saturating_add(step.unrecognized);
        self.absent = self.absent.saturating_add(step.absent);
        self.failed = self.failed.saturating_add(step.failed);
        self.complete = step.complete;
    }
}

/// Outcome of one index repair.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IndexRepair {
    /// The derived indexes disagreed with committed state and were
    /// rebuilt from it.
    pub diverged: bool,
    /// Entries the rebuilt indexes hold; zero when nothing was rebuilt.
    pub entries: u64,
}

/// Bounded, resumable reclamation of unowned representations, and repair
/// of the derived indexes that accelerate it.
pub trait MaintenanceStore: Send + Sync {
    /// Examine at most `limit` inventory entries from where the previous
    /// call stopped, reclaiming every representation no committed row
    /// owns and nothing protects. Ownership is decided per entry against
    /// committed state, never by index absence alone.
    fn reclaim_unowned(&self, limit: usize) -> Result<Reclamation, StoreError>;

    /// Rebuild the backend's derived reference indexes from committed
    /// state when they have diverged from it: a backend that recorded a
    /// divergence while writing rebuilds; one that keeps its indexes in
    /// memory recomputes and replaces them when they differ. Changes no
    /// epoch-committed state and publishes nothing.
    fn repair_indexes(&self) -> Result<IndexRepair, StoreError>;

    /// Settle at most `limit` published epochs into the backend's shared
    /// projections (catalog, ownership, directory), from where the
    /// previous call stopped. Publication never waits on this; a backend
    /// whose projections are updated with the publication settles nothing
    /// and returns zero. Returns the number of epochs settled.
    fn settle(&self, limit: u64) -> Result<u64, StoreError>;
}
