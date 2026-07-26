//! Reconciliation dispatch.
//!
//! Three reconciliation mechanisms for three different sets:
//! - RBSR (fingerprint.rs): blob-set XOR-monoid reconciliation
//! - MST (mst.rs): tag-name diff via Merkle search tree page ranges
//! - AKD (akd_adapter): assertion-level inclusion/absence proofs
//!
//! RBSR is NOT deleted. It reconciles a different set (blob kappas)
//! than the MST (tag names). Both are needed.

pub mod mst;
