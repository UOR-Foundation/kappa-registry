//! What one signed epoch commits about its namespace's state.
//!
//! Every epoch root names (key 11, `EpochRoot::state`) one canonical
//! [`NamespaceState`] record, derived from the same sealed execution state
//! as the epoch's ledger:
//!
//! - the exact namespace instance: namespace identity and incarnation,
//!   fixed at genesis and preserved by every successor;
//! - `authority`: the identity of the canonical [`AuthorityState`] record,
//!   who controls the namespace at this revision;
//! - `index_root`: the root of the authenticated current-state index
//!   (`state_index`), which holds the authority record under
//!   `state_key::authority_path()` with the same identity, so the direct
//!   reference is a fast path the index proves;
//! - `history_root` and `history_size`: the RFC 9162 log (`merkle`) of
//!   every canonical mutation the namespace has sealed, in order; each
//!   epoch's ledger is the contiguous range that ends at `history_size`.
//!
//! A retirement proves ownership at a revision with the signed root, this
//! record and the authority record: constant size, whatever the namespace
//! wrote since its ownership last changed.
//!
//! Decoding is strict: unknown versions or keys, identities that are not
//! 16 bytes, an unknown (all-zero) incarnation, and roots that are not 32
//! bytes are refused at the decode boundary.

use dcbor::prelude::*;

use crate::canonical::canonical_bytes;
use crate::error::StoreError;
use crate::kappa::Kappa;
use crate::namespace::ProtocolId;
use crate::wire_map::wire_map;

/// The only version of both records.
pub const NAMESPACE_STATE_VERSION: u64 = 1;

/// Longest namespace name an authority record carries.
pub const MAX_AUTHORITY_NAME_BYTES: usize = 1024;

fn id16(bytes: &[u8], what: &str) -> Result<[u8; 16], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Rejected(format!("{what} is not 16 bytes")))
}

fn root32(bytes: &[u8], what: &str) -> Result<[u8; 32], StoreError> {
    bytes
        .try_into()
        .map_err(|_| StoreError::Rejected(format!("{what} is not 32 bytes")))
}

fn known_incarnation(incarnation: &[u8; 16]) -> Result<(), StoreError> {
    if *incarnation == [0; 16] {
        return Err(StoreError::Rejected(
            "namespace state names an unknown incarnation".into(),
        ));
    }
    Ok(())
}

/// Who controls one namespace instance at one revision.
///
/// `owner` is the owning anchor, or `None` for a namespace governed by the
/// node's authority lineage. `name` and `protocol` are the scope a
/// delegation is interpreted against (`DelegationScope::permits_namespace`
/// matches the name). `tombstoned` is the lifecycle: a deleted namespace
/// keeps its controller until its storage is retired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityState {
    namespace: [u8; 16],
    incarnation: [u8; 16],
    owner: Option<Kappa>,
    name: String,
    protocol: Option<ProtocolId>,
    tombstoned: bool,
}

/// Wire shape. Keys (PERMANENT): 0 version, 1 namespace, 2 incarnation,
/// 3 owner, 4 name, 5 protocol, 6 tombstoned.
struct AuthorityStateWire {
    version: u64,
    namespace: Vec<u8>,
    incarnation: Vec<u8>,
    owner: Option<Kappa>,
    name: String,
    protocol: Option<ProtocolId>,
    tombstoned: bool,
}

wire_map!(AuthorityStateWire {
    version: value = 0,
    namespace: bytes = 1,
    incarnation: bytes = 2,
    owner: optional = 3,
    name: value = 4,
    protocol: optional = 5,
    tombstoned: value = 6,
});

impl AuthorityState {
    pub fn new(
        namespace: [u8; 16],
        incarnation: [u8; 16],
        owner: Option<Kappa>,
        name: String,
        protocol: Option<ProtocolId>,
        tombstoned: bool,
    ) -> Result<Self, StoreError> {
        known_incarnation(&incarnation)?;
        if name.is_empty() || name.len() > MAX_AUTHORITY_NAME_BYTES {
            return Err(StoreError::Rejected(format!(
                "authority record name must be 1 to {MAX_AUTHORITY_NAME_BYTES} bytes"
            )));
        }
        Ok(Self {
            namespace,
            incarnation,
            owner,
            name,
            protocol,
            tombstoned,
        })
    }

    pub const fn namespace(&self) -> &[u8; 16] {
        &self.namespace
    }
    pub const fn incarnation(&self) -> &[u8; 16] {
        &self.incarnation
    }
    pub const fn owner(&self) -> Option<&Kappa> {
        self.owner.as_ref()
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub const fn protocol(&self) -> Option<&ProtocolId> {
        self.protocol.as_ref()
    }
    pub const fn tombstoned(&self) -> bool {
        self.tombstoned
    }

    /// The record's identity: SHA-256 of its canonical bytes.
    pub fn identity(&self) -> Kappa {
        Kappa::sha256(&canonical_bytes(self))
    }
}

impl From<AuthorityState> for CBOR {
    fn from(value: AuthorityState) -> Self {
        AuthorityStateWire {
            version: NAMESPACE_STATE_VERSION,
            namespace: value.namespace.to_vec(),
            incarnation: value.incarnation.to_vec(),
            owner: value.owner,
            name: value.name,
            protocol: value.protocol,
            tombstoned: value.tombstoned,
        }
        .into()
    }
}

impl From<&AuthorityState> for CBOR {
    fn from(value: &AuthorityState) -> Self {
        value.clone().into()
    }
}

impl TryFrom<CBOR> for AuthorityState {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let wire = AuthorityStateWire::try_from(cbor)?;
        let decode = || -> Result<Self, StoreError> {
            if wire.version != NAMESPACE_STATE_VERSION {
                return Err(StoreError::Rejected(format!(
                    "unknown authority record version {}",
                    wire.version
                )));
            }
            Self::new(
                id16(&wire.namespace, "authority namespace")?,
                id16(&wire.incarnation, "authority incarnation")?,
                wire.owner,
                wire.name,
                wire.protocol,
                wire.tombstoned,
            )
        };
        decode().map_err(|error| dcbor::Error::msg(error.to_string()))
    }
}

/// What one epoch commits about its namespace (see the module
/// documentation).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceState {
    namespace: [u8; 16],
    incarnation: [u8; 16],
    authority: Kappa,
    index_root: [u8; 32],
    history_root: [u8; 32],
    history_size: u64,
}

/// Wire shape. Keys (PERMANENT): 0 version, 1 namespace, 2 incarnation,
/// 3 authority record, 4 index root, 5 history root, 6 history size.
struct NamespaceStateWire {
    version: u64,
    namespace: Vec<u8>,
    incarnation: Vec<u8>,
    authority: Kappa,
    index_root: Vec<u8>,
    history_root: Vec<u8>,
    history_size: u64,
}

wire_map!(NamespaceStateWire {
    version: value = 0,
    namespace: bytes = 1,
    incarnation: bytes = 2,
    authority: value = 3,
    index_root: bytes = 4,
    history_root: bytes = 5,
    history_size: value = 6,
});

impl NamespaceState {
    /// Seven-field map: head and keys (8), version (1), two 16-byte
    /// strings (34), longest Kappa text (137), two 32-byte strings (68),
    /// and the widest history-size integer (9).
    pub const MAX_ENCODED_LEN: u64 = 8 + 1 + 34 + 137 + 68 + 9;

    pub fn new(
        authority: &AuthorityState,
        index_root: [u8; 32],
        history_root: [u8; 32],
        history_size: u64,
    ) -> Self {
        Self {
            namespace: authority.namespace,
            incarnation: authority.incarnation,
            authority: authority.identity(),
            index_root,
            history_root,
            history_size,
        }
    }

    pub const fn namespace(&self) -> &[u8; 16] {
        &self.namespace
    }
    pub const fn incarnation(&self) -> &[u8; 16] {
        &self.incarnation
    }
    /// Identity of the authority record at this revision.
    pub const fn authority(&self) -> &Kappa {
        &self.authority
    }
    pub const fn index_root(&self) -> &[u8; 32] {
        &self.index_root
    }
    pub const fn history_root(&self) -> &[u8; 32] {
        &self.history_root
    }
    pub const fn history_size(&self) -> u64 {
        self.history_size
    }

    /// The record's identity, which the epoch root signs.
    pub fn identity(&self) -> Kappa {
        Kappa::sha256(&canonical_bytes(self))
    }

    /// Whether `authority` is the authority record this state names, of the
    /// same namespace instance.
    pub fn names(&self, authority: &AuthorityState) -> bool {
        authority.namespace == self.namespace
            && authority.incarnation == self.incarnation
            && authority.identity() == self.authority
    }
}

impl From<NamespaceState> for CBOR {
    fn from(value: NamespaceState) -> Self {
        NamespaceStateWire {
            version: NAMESPACE_STATE_VERSION,
            namespace: value.namespace.to_vec(),
            incarnation: value.incarnation.to_vec(),
            authority: value.authority,
            index_root: value.index_root.to_vec(),
            history_root: value.history_root.to_vec(),
            history_size: value.history_size,
        }
        .into()
    }
}

impl From<&NamespaceState> for CBOR {
    fn from(value: &NamespaceState) -> Self {
        value.clone().into()
    }
}

/// The same record constructed from a strictly decoded document, field by
/// field into its fixed arrays, with the same refusals as the symbolic
/// decoding: unknown version, unknown or repeated key, identities not 16
/// bytes, roots not 32 bytes, the unknown incarnation. The authority
/// identity is the one heap-free text parse (`Kappa`); nothing else is
/// allocated.
impl dcbor::bounded::decode::BoundedDecodable for NamespaceState {
    fn construct<A: dcbor::bounded::Allocator>(
        node: dcbor::bounded::decode::Node<'_, '_>,
        permits: &mut dcbor::bounded::Owned<A::Permit, A::Permit>,
        allocator: &mut A,
    ) -> dcbor::bounded::decode::ConstructResult<Self, A> {
        use dcbor::bounded::decode::DecodeError;

        use crate::canonical::{bounded_fixed_bytes, bounded_map_fields, bounded_required};

        let fields = bounded_map_fields::<A, 7>(node, allocator)?;
        let version = u64::construct(bounded_required(fields[0])?, permits, allocator)?;
        if version != NAMESPACE_STATE_VERSION {
            return Err(DecodeError::Invalid(dcbor::Error::msg(format!(
                "unknown namespace state version {version}"
            ))));
        }
        let namespace = bounded_fixed_bytes::<A, 16>(bounded_required(fields[1])?, allocator)?;
        let incarnation = bounded_fixed_bytes::<A, 16>(bounded_required(fields[2])?, allocator)?;
        known_incarnation(&incarnation)
            .map_err(|error| DecodeError::Invalid(dcbor::Error::msg(error.to_string())))?;
        let authority = Kappa::construct(bounded_required(fields[3])?, permits, allocator)?;
        let index_root = bounded_fixed_bytes::<A, 32>(bounded_required(fields[4])?, allocator)?;
        let history_root = bounded_fixed_bytes::<A, 32>(bounded_required(fields[5])?, allocator)?;
        let history_size = u64::construct(bounded_required(fields[6])?, permits, allocator)?;
        Ok(Self {
            namespace,
            incarnation,
            authority,
            index_root,
            history_root,
            history_size,
        })
    }
}

impl TryFrom<CBOR> for NamespaceState {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let wire = NamespaceStateWire::try_from(cbor)?;
        let decode = || -> Result<Self, StoreError> {
            if wire.version != NAMESPACE_STATE_VERSION {
                return Err(StoreError::Rejected(format!(
                    "unknown namespace state version {}",
                    wire.version
                )));
            }
            let incarnation = id16(&wire.incarnation, "state incarnation")?;
            known_incarnation(&incarnation)?;
            Ok(Self {
                namespace: id16(&wire.namespace, "state namespace")?,
                incarnation,
                authority: wire.authority,
                index_root: root32(&wire.index_root, "state index root")?,
                history_root: root32(&wire.history_root, "state history root")?,
                history_size: wire.history_size,
            })
        };
        decode().map_err(|error| dcbor::Error::msg(error.to_string()))
    }
}

impl crate::canonical::BoundedRecord for NamespaceState {
    const OPTIONS: dcbor::bounded::decode::Options = dcbor::bounded::decode::Options::quick_only(1);
    const AXIS: crate::axis::Axis = crate::axis::Axis::Sha256;
    const FIELDS: &'static [u8] = &[1, 4, 4, 8, 4, 4, 1];

    fn construction(input: u64) -> crate::canonical::ConstructionBound {
        crate::canonical::ConstructionBound {
            // Map plus up to eight keys, and seven scalar constructors.
            values: 16,
            bytes: input,
            allocated: 0,
            peak: 0,
            held: 0,
            permits: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::from_canonical;

    fn authority(owner: Option<Kappa>) -> Result<AuthorityState, StoreError> {
        AuthorityState::new([1; 16], [2; 16], owner, "team/repo".into(), None, false)
    }

    #[test]
    fn records_roundtrip_and_the_state_names_its_authority() -> Result<(), StoreError> {
        for owner in [None, Some(Kappa::sha256(b"owner"))] {
            let record = authority(owner)?;
            let decoded: AuthorityState = from_canonical(&canonical_bytes(&record))?;
            assert_eq!(decoded, record);
            let state = NamespaceState::new(&record, [3; 32], [4; 32], 7);
            let decoded: NamespaceState = from_canonical(&canonical_bytes(&state))?;
            assert_eq!(decoded, state);
            assert!(state.names(&record));
            assert_eq!(state.authority(), &record.identity());
        }
        let owned = authority(Some(Kappa::sha256(b"owner")))?;
        let state = NamespaceState::new(&authority(None)?, [3; 32], [4; 32], 7);
        assert!(!state.names(&owned), "another owner is another record");
        Ok(())
    }

    #[test]
    fn construction_and_decoding_refuse_unknown_instances() -> Result<(), StoreError> {
        assert!(AuthorityState::new([1; 16], [0; 16], None, "n".into(), None, false).is_err());
        assert!(AuthorityState::new([1; 16], [2; 16], None, String::new(), None, false).is_err());
        let state = NamespaceState::new(&authority(None)?, [3; 32], [4; 32], 7);
        let edit = |key: u64, value: CBOR| {
            let CBORCase::Map(mut map) = CBOR::from(&state).into_case() else {
                return Vec::new();
            };
            map.insert(key, value);
            CBOR::from(map).to_cbor_data()
        };
        let refused = |bytes: Vec<u8>| from_canonical::<NamespaceState>(&bytes).is_err();
        assert!(refused(edit(0, CBOR::from(2u64))), "unknown version");
        assert!(refused(edit(7, CBOR::from(1u64))), "unknown key");
        assert!(
            refused(edit(2, CBOR::from(ByteString::from(vec![0u8; 16])))),
            "unknown incarnation"
        );
        assert!(
            refused(edit(4, CBOR::from(ByteString::from(vec![0u8; 31])))),
            "short index root"
        );
        Ok(())
    }
}
