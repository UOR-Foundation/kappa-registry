#![forbid(unsafe_code)]
//! Nix binary cache protocol module for kappa-registry.
//!
//! Pure protocol codec library. Parses and generates the narinfo text
//! format, scans NAR byte streams for store path references, and
//! handles Nix key/signature format parsing. No HTTP types. No async.
//! No dependency on kappa-core. WASM-portable.
//!
//! Cryptographic operations (Ed25519 sign/verify) are performed by
//! kappa-core in the server handler layer. This crate provides the
//! format bridge: parse "name:base64" key strings, format
//! "name:base64sig" output strings.

pub mod narinfo;
pub mod refs;
pub mod sign;
