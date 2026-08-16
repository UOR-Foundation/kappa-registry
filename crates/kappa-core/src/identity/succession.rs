//! Identity succession: key rotation without losing ownership.
//!
//! A succession declares "new_anchor replaces old_anchor." The old
//! anchor's bindings and assertions transfer to the new anchor.
//! Succession creates a watermark at effective_at to invalidate
//! pre-succession assertions from the old anchor.

use dcbor::prelude::*;

/// An identity succession links a new anchor to an old anchor.
///
/// CBOR key assignments (PERMANENT):
///   0: old_anchor (the anchor being replaced)
///   1: new_anchor (the anchor taking over)
///   2: reason (why the succession happened -- "rotation", "compromise", "upgrade")
///   3: effective_at_ms (when the succession takes effect)
///   4: old_signature (old anchor's signature approving the succession)
///   5: new_signature (new anchor's signature accepting the succession)
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct IdentitySuccession {
    #[cbor(n = 0)]
    pub old_anchor: String,
    #[cbor(n = 1)]
    pub new_anchor: String,
    #[cbor(n = 2)]
    pub reason: String,
    #[cbor(n = 3)]
    pub effective_at_ms: u64,
    #[cbor(n = 4)]
    pub old_signature: Vec<u8>,
    #[cbor(n = 5)]
    pub new_signature: Vec<u8>,
}
