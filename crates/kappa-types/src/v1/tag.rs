use dcbor::prelude::*;

use crate::kappa::Kappa;

/// A named mutable pointer to a kappa digest with a monotonic version.
///
/// CBOR key assignments (PERMANENT):
///   0: name, 1: kappa, 2: version, 3: `created_at_ms`,
///   4: `updated_at_ms`, 5: symref
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable, serde::Serialize, serde::Deserialize)]
pub struct TagEntry {
    #[cbor(n = 0)]
    pub name: String,
    #[cbor(n = 1)]
    pub kappa: Kappa,
    #[cbor(n = 2)]
    pub version: u64,
    #[cbor(n = 3)]
    pub created_at_ms: i64,
    #[cbor(n = 4)]
    pub updated_at_ms: i64,
    #[cbor(n = 5)]
    pub symref: Option<String>,
}

/// Conditional tag mutation.
#[derive(Debug, Clone)]
pub enum TagUpdate {
    /// Set unconditionally.
    Set { kappa: Kappa },

    /// Set only if the current version matches.
    CompareAndSwap { kappa: Kappa, expected_version: u64 },

    /// Set only if the tag does not exist.
    CreateIfAbsent { kappa: Kappa },

    /// Set as a symbolic reference to another tag name.
    SetSymref { target: String },
}
