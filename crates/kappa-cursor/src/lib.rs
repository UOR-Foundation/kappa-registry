//! Ordered cursor trait and set-algebra combinators.
//!
//! This crate defines `KappaCursor` -- the streaming iteration
//! interface over sorted byte sequences -- and the combinators
//! that compose cursors into compound queries without materializing
//! intermediate result sets.
//!
//! Zero dependencies. Every index implementation (redb B+tree,
//! LOUDS trie, sorted Vec, roaring bitmap, distributed remote)
//! implements `KappaCursor`. Every query consumer (resolution,
//! GC, reconciliation, vector search filter) accepts
//! `Box<dyn KappaCursor>`.
//!
#![deny(clippy::disallowed_types)]

mod btree;
mod cursor;
mod difference;
mod empty;
mod fallible;
mod filtered;
mod intersection;
mod once;
mod slice;
mod union;

pub use btree::BTreeCursor;
pub use cursor::{BlockCursor, KappaCursor, SeekResult, TERMINATED};
pub use difference::Difference;
pub use empty::EmptyCursor;
pub use fallible::{FallibleCursor, InfallibleCursor};
pub use filtered::FilteredCursor;
pub use intersection::Intersection;
pub use once::OnceCursor;
pub use slice::{ArcSliceCursor, SliceCursor};
pub use union::Union;
