//! The directory's committed records: map entries, log transitions and
//! the commitment an epoch names.
//!
//! Every record is canonical dCBOR; the map and log leaves are the
//! canonical bytes of an `Entry` and a `Transition`, and the commitment
//! is published as content whose identity the epoch's ledger names.

use dcbor::prelude::*;

use kappa_types::kappa::Kappa;

/// One label's current standing in the map.
/// CBOR key assignments (PERMANENT): 0-4
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct Entry {
    #[cbor(n = 0)]
    pub label: ByteString,
    /// The assertion the label currently names (the last one set).
    #[cbor(n = 1)]
    pub value: Kappa,
    /// How many times the label was set; 1 for its first publication.
    #[cbor(n = 2)]
    pub version: u64,
    /// The directory epoch that first published the label.
    #[cbor(n = 3)]
    pub first_epoch: u64,
    /// The directory epoch that retracted the label, while it is retracted.
    #[cbor(n = 4)]
    pub retracted_at: Option<u64>,
}

impl Entry {
    pub const fn is_active(&self) -> bool {
        self.retracted_at.is_none()
    }
}

/// One change to the map, in the order the log records it.
/// CBOR key assignments (PERMANENT): 0-3
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct Transition {
    #[cbor(n = 0)]
    pub label: ByteString,
    /// The value set, or `None` for a retraction.
    #[cbor(n = 1)]
    pub value: Option<Kappa>,
    /// The entry's version after this transition.
    #[cbor(n = 2)]
    pub version: u64,
    /// The directory epoch that published this transition.
    #[cbor(n = 3)]
    pub epoch: u64,
}

/// The commitment one directory epoch names: the roots and sizes of the
/// map and the log at that epoch, and the commitment it extends.
/// CBOR key assignments (PERMANENT): 0-5
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct Commitment {
    #[cbor(n = 0)]
    pub epoch: u64,
    #[cbor(n = 1)]
    pub map_root: ByteString,
    #[cbor(n = 2)]
    pub leaf_count: u64,
    #[cbor(n = 3)]
    pub log_root: ByteString,
    #[cbor(n = 4)]
    pub log_size: u64,
    /// Identity of the commitment of the previous directory epoch; absent
    /// for the first.
    #[cbor(n = 5)]
    pub previous: Option<Kappa>,
}

impl Commitment {
    pub fn map_root_bytes(&self) -> Result<[u8; 32], crate::DirectoryError> {
        root_bytes(&self.map_root, "map root")
    }

    pub fn log_root_bytes(&self) -> Result<[u8; 32], crate::DirectoryError> {
        root_bytes(&self.log_root, "log root")
    }
}

/// The map as published: every entry in label order.
/// CBOR key assignments (PERMANENT): 0
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct MapRecord {
    #[cbor(n = 0)]
    pub entries: Vec<Entry>,
}

/// The log as published: every transition in order.
/// CBOR key assignments (PERMANENT): 0
#[derive(Debug, Clone, PartialEq, Eq, CBORCodable)]
pub struct LogRecord {
    #[cbor(n = 0)]
    pub transitions: Vec<Transition>,
}

pub(crate) fn root_bytes(
    bytes: &ByteString,
    what: &str,
) -> Result<[u8; 32], crate::DirectoryError> {
    <[u8; 32]>::try_from(bytes.as_ref())
        .map_err(|_| crate::DirectoryError::Verification(format!("{what} is not 32 bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kappa_types::canonical::{canonical_bytes, from_canonical};

    #[test]
    fn records_round_trip_canonically() -> Result<(), crate::DirectoryError> {
        let entry = Entry {
            label: ByteString::from(b"label".as_slice()),
            value: Kappa::sha256(b"assertion"),
            version: 2,
            first_epoch: 3,
            retracted_at: Some(5),
        };
        let bytes = canonical_bytes(&entry);
        assert_eq!(from_canonical::<Entry>(&bytes)?, entry);
        let transition = Transition {
            label: ByteString::from(b"label".as_slice()),
            value: None,
            version: 2,
            epoch: 5,
        };
        let bytes = canonical_bytes(&transition);
        assert_eq!(from_canonical::<Transition>(&bytes)?, transition);
        let commitment = Commitment {
            epoch: 5,
            map_root: ByteString::from([1u8; 32]),
            leaf_count: 1,
            log_root: ByteString::from([2u8; 32]),
            log_size: 2,
            previous: None,
        };
        let bytes = canonical_bytes(&commitment);
        assert_eq!(from_canonical::<Commitment>(&bytes)?, commitment);
        assert_eq!(commitment.map_root_bytes()?, [1u8; 32]);
        assert!(
            Commitment {
                map_root: ByteString::from([1u8; 31]),
                ..commitment
            }
            .map_root_bytes()
            .is_err()
        );
        Ok(())
    }
}
