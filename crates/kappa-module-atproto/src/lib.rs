#![forbid(unsafe_code)]
//! AT Protocol module for kappa-registry.
//!
//! Pure codec and data structures for the AT Protocol. No kappa-core
//! dependency. The server handler bridges to the substrate.
//!
//! - mst: Merkle Search Tree for repository state
//! - car: Content Addressable aRchive encode/decode
//! - tid: Timestamp ID generation
//! - commit: Repository commit signing and verification
//! - cid: Content Identifier computation

pub mod car;
pub mod cid;
pub mod commit;
pub mod mst;
pub mod session;
pub mod tid;
pub mod xrpc;

pub use xrpc::register;
