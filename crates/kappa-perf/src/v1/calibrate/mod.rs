//! Calibration framework: canonical measurement identifiers, dependency
//! gating, physics validation, baseline comparison, roofline grading and
//! dataset emission.
//!
//! Layers, each depending only on those above it:
//!
//! - Vocabulary: [`quantity`], [`operation`], [`condition`], [`substrate`],
//!   [`profile`] and the identifier [`grammar`].
//! - Provenance: [`platform`] (host, toolchain, storage).
//! - Distributions: [`histogram`] (`HdrHistogram` percentiles and encoding).
//! - Records: [`record`] (one JSONL line per measurement) and [`dataset`]
//!   (the merged per-session file).
//! - Analysis: [`dependency`], [`validate`], [`roofline`], [`reference`],
//!   [`baseline`].
//! - Harness: [`backfill`] (criterion results), [`session`], [`summary`]
//!   (what a finalized session reports), [`harness`] (criterion
//!   integration).

pub mod backfill;
pub mod baseline;
pub mod condition;
pub mod dataset;
pub mod dependency;
pub mod grammar;
pub mod harness;
pub mod histogram;
pub mod operation;
pub mod platform;
pub mod profile;
pub mod quantity;
pub mod record;
pub mod reference;
pub mod roofline;
pub mod session;
pub mod substrate;
pub mod summary;
pub mod validate;

pub use condition::Conditions;
pub use grammar::OscId;
pub use harness::{Bench, CalibratedGroup, calibrated_criterion, finalize};
pub use histogram::LatencyHistogram;
pub use profile::Profile;
pub use quantity::{Quantity, Work};
pub use session::CalibratedSession;
pub use summary::Summary;
