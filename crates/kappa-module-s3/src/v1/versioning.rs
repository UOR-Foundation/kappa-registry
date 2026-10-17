use dcbor::prelude::*;

use kappa_store::kappa::Kappa;

/// S3 object versioning state for a bucket (namespace).
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

/// A single version entry in an S3 object version chain.
///
/// CBOR key assignments (PERMANENT):
///   0: kappa, 1: version_id, 2: is_delete_marker, 3: created_at_ms
#[derive(Debug, Clone, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct VersionEntry {
    #[cbor(n = 0)]
    pub kappa: Option<Kappa>,
    #[cbor(n = 1)]
    pub version_id: String,
    #[cbor(n = 2)]
    pub is_delete_marker: bool,
    #[cbor(n = 3)]
    pub created_at_ms: i64,
}

/// Result of an S3 version delete operation.
#[derive(Debug, Clone)]
pub struct DeleteResult {
    pub version_id: Option<String>,
    pub is_delete_marker: bool,
}
