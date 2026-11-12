//! The identity of one namespace storage instance.
//!
//! A namespace identity is deterministic (`NamespaceRef::deterministic`)
//! and reusable: a creation that never committed releases its claim, and
//! the same identity can be created again. Storage created for it is a new
//! instance, distinguished by a random incarnation written once into the
//! instance's own database (`NAMESPACE_SELF` key `b"incarnation"`) when the
//! database is created. Every record that names storage it does not live
//! in names the instance, not only the namespace: settlement checkpoints,
//! retirement records, pending markers, catalog and epoch-root locators,
//! allocation owner records and unsettled registrations. A record of one
//! instance is never applied to, and never removes, another.
//!
//! Storage created before incarnations existed has none; its instance is
//! [`Incarnation::Unknown`]. Unknown is decoding compatibility, not
//! identity: two such instances are indistinguishable. How storage present
//! relates to an instance a record names is one [`Identification`], and
//! what each relation permits is decided once, by its methods: a relation
//! involving an unknown incarnation permits reading where reading is
//! otherwise valid, permits settlement only between a legacy record and
//! legacy storage, and never authorizes destructive work: deleting
//! storage or allocations, or releasing claims. A recorded retirement of a
//! missing unknown instance may discharge that instance's recovery
//! obligation (its marker, gap and closing charge), which removes nothing
//! that holds data.
//!
//! Encodings: an instance key is `[namespace:16]` for an unknown
//! incarnation and `[namespace:16][incarnation:16]` otherwise, so every
//! key written before incarnations existed decodes as unknown, and a key
//! of any other length is refused.

use kappa_store::StoreError;

/// Bytes of an incarnation.
pub const INCARNATION_LEN: usize = 16;

/// Longest instance key ([`StorageInstance::key`]): the namespace and a
/// known incarnation.
pub const MAX_INSTANCE_KEY_BYTES: usize = 16 + INCARNATION_LEN;

/// The incarnation of a storage instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Incarnation {
    /// Written at creation; unique per instance.
    Known([u8; INCARNATION_LEN]),
    /// Storage, or a record of it, from before incarnations existed.
    Unknown,
}

/// How storage present relates to the instance a record names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Identification {
    /// Same namespace and the same known incarnation.
    Exact,
    /// Same namespace and both incarnations unknown: legacy storage named
    /// by a legacy record, indistinguishable from any other legacy
    /// instance of the namespace.
    Legacy,
    /// Same namespace and exactly one incarnation unknown.
    Ambiguous,
    /// Another namespace, or another known incarnation of it.
    Other,
}

impl Identification {
    /// The storage may answer a read the record locates.
    pub const fn permits_read(self) -> bool {
        matches!(self, Self::Exact | Self::Legacy | Self::Ambiguous)
    }

    /// The storage may be settled, and the record's recovery obligation
    /// discharged by that settlement: the record may have been written for
    /// this storage.
    pub const fn permits_settlement(self) -> bool {
        matches!(self, Self::Exact | Self::Legacy)
    }

    /// The storage's committed state may release what the record holds,
    /// and the storage may be removed for the record.
    pub const fn permits_destruction(self) -> bool {
        matches!(self, Self::Exact)
    }
}

/// One namespace storage instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StorageInstance {
    namespace: [u8; 16],
    incarnation: Incarnation,
}

impl StorageInstance {
    pub const fn new(namespace: [u8; 16], incarnation: Incarnation) -> Self {
        Self {
            namespace,
            incarnation,
        }
    }

    /// A fresh instance of `namespace` with a random incarnation.
    pub fn generate(namespace: [u8; 16]) -> Result<Self, StoreError> {
        let mut incarnation = [0u8; INCARNATION_LEN];
        getrandom::fill(&mut incarnation)
            .map_err(|error| StoreError::Internal(format!("incarnation: {error}")))?;
        Ok(Self::new(namespace, Incarnation::Known(incarnation)))
    }

    pub const fn namespace(&self) -> &[u8; 16] {
        &self.namespace
    }

    pub const fn incarnation(&self) -> Incarnation {
        self.incarnation
    }

    /// The known incarnation of this instance, for `purpose`: what shared
    /// transitions, receipts and publications bind. Storage of unknown
    /// incarnation has none, and `purpose` is refused there.
    pub fn known_incarnation(&self, purpose: &str) -> Result<[u8; INCARNATION_LEN], StoreError> {
        match self.incarnation {
            Incarnation::Known(incarnation) => Ok(incarnation),
            Incarnation::Unknown => Err(StoreError::Rejected(format!(
                "{purpose} requires a known incarnation of {self}"
            ))),
        }
    }

    /// How storage of instance `self` relates to `named`, the instance a
    /// record names. Symmetric.
    pub fn identify(&self, named: &Self) -> Identification {
        if self.namespace != named.namespace {
            return Identification::Other;
        }
        match (self.incarnation, named.incarnation) {
            (Incarnation::Known(own), Incarnation::Known(theirs)) if own == theirs => {
                Identification::Exact
            }
            (Incarnation::Known(_), Incarnation::Known(_)) => Identification::Other,
            (Incarnation::Unknown, Incarnation::Unknown) => Identification::Legacy,
            (Incarnation::Known(_), Incarnation::Unknown)
            | (Incarnation::Unknown, Incarnation::Known(_)) => Identification::Ambiguous,
        }
    }

    /// The instance key: `[namespace:16]` or `[namespace:16][incarnation:16]`,
    /// allocated at exactly [`Self::key_len`] bytes.
    pub fn key(&self) -> Vec<u8> {
        let mut key = Vec::with_capacity(usize::from(self.key_len()));
        self.append_key(&mut key);
        key
    }

    /// Append the instance key to `out` without allocating anything else:
    /// the one encoding of an instance key, for every key that embeds it.
    pub fn append_key(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.namespace);
        if let Incarnation::Known(incarnation) = &self.incarnation {
            out.extend_from_slice(incarnation);
        }
    }

    /// Bytes of [`Self::key`], as the one length byte a projection key
    /// prefixes it with: 16 for an unknown incarnation, 32 otherwise.
    pub const fn key_len(&self) -> u8 {
        match self.incarnation {
            Incarnation::Unknown => 16,
            Incarnation::Known(_) => 32,
        }
    }

    /// Decode an instance key; any length but 16 or 32 is refused.
    pub fn from_key(bytes: &[u8]) -> Result<Self, StoreError> {
        let malformed = || {
            StoreError::Internal(format!(
                "storage instance key of {} bytes is neither 16 nor 32",
                bytes.len()
            ))
        };
        let namespace: [u8; 16] = bytes
            .get(..16)
            .and_then(|namespace| namespace.try_into().ok())
            .ok_or_else(malformed)?;
        let incarnation = match &bytes[16..] {
            [] => Incarnation::Unknown,
            rest => Incarnation::Known(rest.try_into().map_err(|_| malformed())?),
        };
        Ok(Self::new(namespace, incarnation))
    }

    /// The instance key in lowercase hex, the name of its pending marker.
    pub fn hex(&self) -> String {
        hex::encode(self.key())
    }

    /// Decode [`Self::hex`].
    pub fn from_hex(name: &str) -> Result<Self, StoreError> {
        let bytes = hex::decode(name).map_err(|error| {
            StoreError::Internal(format!("storage instance name {name}: {error}"))
        })?;
        Self::from_key(&bytes)
    }

    /// Decode the incarnation row of an instance's own database: absent
    /// is unknown; present must be exactly [`INCARNATION_LEN`] bytes.
    pub fn incarnation_from_row(row: Option<&[u8]>) -> Result<Incarnation, StoreError> {
        row.map_or(Ok(Incarnation::Unknown), |bytes| {
            bytes.try_into().map(Incarnation::Known).map_err(|_| {
                StoreError::Rejected(format!(
                    "namespace incarnation row of {} bytes is not {INCARNATION_LEN}",
                    bytes.len()
                ))
            })
        })
    }
}

impl std::fmt::Display for StorageInstance {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.incarnation {
            Incarnation::Known(incarnation) => write!(
                formatter,
                "{}/{}",
                hex::encode(self.namespace),
                hex::encode(incarnation)
            ),
            Incarnation::Unknown => write!(formatter, "{}/unknown", hex::encode(self.namespace)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_round_trip_and_legacy_keys_decode_as_unknown() -> Result<(), StoreError> {
        let known = StorageInstance::generate([1; 16])?;
        assert_eq!(known.key().len(), 32);
        assert_eq!(known.key().len(), usize::from(known.key_len()));
        assert_eq!(StorageInstance::from_key(&known.key())?, known);
        assert_eq!(StorageInstance::from_hex(&known.hex())?, known);
        let legacy = StorageInstance::from_key(&[1; 16])?;
        assert_eq!(legacy.incarnation(), Incarnation::Unknown);
        assert_eq!(legacy.key(), vec![1; 16]);
        assert_eq!(legacy.key().len(), usize::from(legacy.key_len()));
        for length in [0, 15, 17, 31, 33] {
            assert!(
                StorageInstance::from_key(&vec![1; length]).is_err(),
                "{length}"
            );
        }
        assert!(StorageInstance::incarnation_from_row(Some(&[0; 15])).is_err());
        assert_eq!(
            StorageInstance::incarnation_from_row(None)?,
            Incarnation::Unknown
        );
        Ok(())
    }

    #[test]
    fn identification_and_its_permissions() -> Result<(), StoreError> {
        let a = StorageInstance::generate([1; 16])?;
        let b = StorageInstance::generate([1; 16])?;
        let legacy = StorageInstance::new([1; 16], Incarnation::Unknown);
        let other = StorageInstance::generate([2; 16])?;
        assert_eq!(a.identify(&a), Identification::Exact);
        assert_eq!(a.identify(&b), Identification::Other);
        assert_eq!(a.identify(&other), Identification::Other);
        assert_eq!(a.identify(&legacy), Identification::Ambiguous);
        assert_eq!(legacy.identify(&a), Identification::Ambiguous);
        assert_eq!(legacy.identify(&legacy), Identification::Legacy);
        // One table: every caller reads, settles and destroys by it.
        let table = [
            (Identification::Exact, true, true, true),
            (Identification::Legacy, true, true, false),
            (Identification::Ambiguous, true, false, false),
            (Identification::Other, false, false, false),
        ];
        for (relation, read, settle, destroy) in table {
            assert_eq!(relation.permits_read(), read, "{relation:?}");
            assert_eq!(relation.permits_settlement(), settle, "{relation:?}");
            assert_eq!(relation.permits_destruction(), destroy, "{relation:?}");
        }
        Ok(())
    }
}
