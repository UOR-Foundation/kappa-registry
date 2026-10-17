use dcbor::prelude::*;

use crate::kappa::Kappa;

/// Object versioning state for a namespace.
///
/// Controls whether mutations create version entries.
/// Stored as namespace metadata at key `_versions/state`.
/// Participates in epoch state root via `namespace_put_meta`.
///
/// CBOR discriminants (PERMANENT):
///   0: Disabled, 1: Enabled, 2: Suspended
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub enum VersioningState {
    #[cbor(n = 0)]
    Disabled,
    #[cbor(n = 1)]
    Enabled,
    #[cbor(n = 2)]
    Suspended,
}

/// A single version entry in an object version chain.
///
/// Stored as a tag under `_versions/{object_key}/{inverted_timestamp}`.
/// The tag value is the kappa of the version's content.
/// Delete markers use a well-known sentinel kappa (content address
/// of dCBOR `{"delete_marker": true}`).
///
/// CBOR key assignments (PERMANENT):
///   0: kappa, 1: `version_id`, 2: `is_delete_marker`, 3: `created_at_ms`
#[derive(Debug, Clone, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct VersionEntry {
    /// Content address of this version. For delete markers, this is
    /// the sentinel kappa (content address of `{"delete_marker": true}`).
    #[cbor(n = 0)]
    pub kappa: Kappa,
    #[cbor(n = 1)]
    pub version_id: String,
    #[cbor(n = 2)]
    pub is_delete_marker: bool,
    #[cbor(n = 3)]
    pub created_at_ms: i64,
}

/// Result of a version delete operation.
#[derive(Debug, Clone)]
pub struct DeleteResult {
    pub version_id: Option<String>,
    pub is_delete_marker: bool,
}
