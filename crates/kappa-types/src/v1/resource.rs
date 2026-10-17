//! Staged resources: canonical immutable records for content assembled
//! across requests, expressed with registry primitives only.
//!
//! A resource is identified by its incarnation. Its anchor is the identity
//! `Kappa::sha256(canonical(ResourceAnchor))`, a stable non-content
//! identity that `Member` edges hang from. Its head is a [`ResourceHead`]
//! record, installed as content and named by the tag
//! `_resource/{incarnation hex}` in the owning namespace; every stage,
//! preparation, completion, or discard publishes a new head revision in an
//! epoch, so the resource's state is epoch-committed and a retried request
//! resolves the committed binding instead of repeating its effect.
//!
//! Completion is two epoch-committed transitions. Preparation freezes the
//! exact ordered selection into a [`ResourceSelection`] record, names it
//! from the head (`prepared`), and binds the completion request to it; the
//! bytes are then hashed outside any writer against that frozen record.
//! Completion validates that the head still names the same generation and
//! installs the composite, recording the committed outcome
//! ([`ResourceCompletion`]) with every identity and protocol receipt a
//! replay must return, so a retry needs no staging state.
//!
//! Protocols specialize [`MemberCoordinate`]: sequential uploads validate
//! offsets, numbered uploads validate slots, membership transactions
//! validate identities. Validation of a coordinate against the resource's
//! kind is the shared composition's job (`kappa_store::resource`);
//! protocol-specific rules (`ETag` formats, minimum part sizes) stay in the
//! protocol crates.

use dcbor::prelude::*;

use crate::error::StoreError;
use crate::kappa::Kappa;
use crate::wire_map::wire_map;

/// How members of a resource are addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
pub enum ResourceKind {
    /// Members are contiguous byte ranges in offset order.
    #[cbor(n = 0)]
    Sequential,
    /// Members occupy numbered, replaceable slots.
    #[cbor(n = 1)]
    Numbered,
    /// Members are content identities with no order.
    #[cbor(n = 2)]
    Membership,
}

/// Lifecycle phase of a resource head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, CBORCodable)]
pub enum ResourcePhase {
    /// Accepting members.
    #[cbor(n = 0)]
    Open,
    /// Completed: `completion` names the assembled identity.
    #[cbor(n = 1)]
    Completed,
    /// Discarded: members are no longer retained by this head.
    #[cbor(n = 2)]
    Discarded,
    /// Admission closed; `prepared` names the frozen selection awaiting
    /// completion.
    #[cbor(n = 3)]
    Prepared,
}

/// Where a member sits in its resource. The edge metadata of a `Member`
/// edge is the canonical encoding of this record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberCoordinate {
    /// Byte offset for sequential resources; slot number for numbered
    /// resources; zero for membership resources.
    pub position: u64,
    /// Logical length of the member.
    pub length: u64,
    /// Opaque protocol receipt (an S3 part `ETag` source, for instance).
    pub receipt: Option<Vec<u8>>,
}

wire_map!(MemberCoordinate {
    position: value = 0,
    length: value = 1,
    receipt: optional_bytes = 2,
});

/// The identity `Member` edges hang from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceAnchor {
    pub namespace_id: Vec<u8>,
    pub incarnation: Vec<u8>,
}

wire_map!(ResourceAnchor {
    namespace_id: bytes = 0,
    incarnation: bytes = 1,
});

impl ResourceAnchor {
    pub fn identity(&self) -> Kappa {
        Kappa::sha256(&crate::canonical::canonical_bytes(self))
    }
}

/// One selected member of a frozen generation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedMember {
    pub identity: Kappa,
    pub position: u64,
    pub length: u64,
}

wire_map!(SelectedMember {
    identity: value = 0,
    position: value = 1,
    length: value = 2,
});

/// The frozen, ordered selection a completion publishes. Installed as
/// content; the head names it while the resource is `Prepared`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceSelection {
    pub namespace_id: Vec<u8>,
    pub incarnation: Vec<u8>,
    /// Head revision the selection was taken at.
    pub revision: u64,
    /// The completion request bound to this generation.
    pub request: Kappa,
    pub members: Vec<SelectedMember>,
    pub total_bytes: u64,
}

impl From<ResourceSelection> for CBOR {
    fn from(value: ResourceSelection) -> Self {
        let members: Vec<Self> = value.members.into_iter().map(Self::from).collect();
        let mut map = Map::new();
        map.insert(0u64, ByteString::from(value.namespace_id));
        map.insert(1u64, ByteString::from(value.incarnation));
        map.insert(2u64, value.revision);
        map.insert(3u64, value.request);
        map.insert(4u64, Self::from(members));
        map.insert(5u64, value.total_bytes);
        map.into()
    }
}

impl From<&ResourceSelection> for CBOR {
    fn from(value: &ResourceSelection) -> Self {
        value.clone().into()
    }
}

/// A canonical map admitting exactly `keys`. Shared by every record whose
/// fields include arrays, which `wire_map!` does not express.
pub(crate) fn strict_map(cbor: CBOR, keys: &[u64]) -> Result<Map, dcbor::Error> {
    let CBORCase::Map(map) = cbor.into_case() else {
        return Err(dcbor::Error::WrongType);
    };
    for (key, _) in map.iter() {
        let key: u64 = key.clone().try_into()?;
        if !keys.contains(&key) {
            return Err(dcbor::Error::msg("unknown wire-map field"));
        }
    }
    Ok(map)
}

/// A canonical array whose every item decodes as `T`.
pub(crate) fn array_of<T: TryFrom<CBOR, Error = dcbor::Error>>(
    cbor: CBOR,
) -> Result<Vec<T>, dcbor::Error> {
    let CBORCase::Array(items) = cbor.into_case() else {
        return Err(dcbor::Error::WrongType);
    };
    items.into_iter().map(T::try_from).collect()
}

impl TryFrom<CBOR> for ResourceSelection {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = strict_map(cbor, &[0, 1, 2, 3, 4, 5])?;
        let namespace_id: ByteString = map.extract(0u64)?;
        let incarnation: ByteString = map.extract(1u64)?;
        Ok(Self {
            namespace_id: namespace_id.into(),
            incarnation: incarnation.into(),
            revision: map.extract(2u64)?,
            request: map.extract(3u64)?,
            members: array_of(map.extract(4u64)?)?,
            total_bytes: map.extract(5u64)?,
        })
    }
}

impl ResourceSelection {
    pub fn identity(&self) -> Kappa {
        Kappa::sha256(&crate::canonical::canonical_bytes(self))
    }

    /// Structural validity: members contribute their lengths exactly to
    /// `total_bytes`, and no member is empty.
    pub fn validate(&self, namespace_id: &[u8], incarnation: &[u8]) -> Result<(), StoreError> {
        if self.namespace_id != namespace_id || self.incarnation != incarnation {
            return Err(StoreError::Rejected(
                "resource selection belongs to another resource".into(),
            ));
        }
        if self.members.is_empty() {
            return Err(StoreError::Rejected("resource selection is empty".into()));
        }
        let mut total = 0u64;
        for member in &self.members {
            if member.length == 0 {
                return Err(StoreError::Rejected(
                    "resource selection has an empty member".into(),
                ));
            }
            total = total
                .checked_add(member.length)
                .ok_or_else(|| StoreError::CapacityExceeded("selection length overflows".into()))?;
        }
        if total != self.total_bytes {
            return Err(StoreError::Rejected(
                "resource selection total disagrees with its members".into(),
            ));
        }
        Ok(())
    }
}

/// Committed completion outcome: everything a replayed completion must
/// return, so a retry needs no staging state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceCompletion {
    /// The completion request that produced the outcome.
    pub request: Kappa,
    /// The generation that was published.
    pub generation: Kappa,
    /// The assembled identity.
    pub result: Kappa,
    /// Identities of the same bytes under the other mandatory axes.
    pub aliases: Vec<Kappa>,
    /// Protocol receipt of the outcome (an S3 composite `ETag`, for instance).
    pub receipt: Option<Vec<u8>>,
}

impl From<ResourceCompletion> for CBOR {
    fn from(value: ResourceCompletion) -> Self {
        let aliases: Vec<Self> = value.aliases.into_iter().map(Self::from).collect();
        let mut map = Map::new();
        map.insert(0u64, value.request);
        map.insert(1u64, value.generation);
        map.insert(2u64, value.result);
        map.insert(3u64, Self::from(aliases));
        if let Some(receipt) = value.receipt {
            map.insert(4u64, ByteString::from(receipt));
        }
        map.into()
    }
}

impl From<&ResourceCompletion> for CBOR {
    fn from(value: &ResourceCompletion) -> Self {
        value.clone().into()
    }
}

impl TryFrom<CBOR> for ResourceCompletion {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let map = strict_map(cbor, &[0, 1, 2, 3, 4])?;
        let receipt = if map.contains_key(4u64) {
            let bytes: ByteString = map.extract(4u64)?;
            Some(bytes.into())
        } else {
            None
        };
        Ok(Self {
            request: map.extract(0u64)?,
            generation: map.extract(1u64)?,
            result: map.extract(2u64)?,
            aliases: array_of(map.extract(3u64)?)?,
            receipt,
        })
    }
}

/// The epoch-committed state of a resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceHead {
    pub namespace_id: Vec<u8>,
    pub incarnation: Vec<u8>,
    pub kind: ResourceKind,
    pub revision: u64,
    pub phase: ResourcePhase,
    /// Sum of member lengths currently held.
    pub total_bytes: u64,
    /// Number of members currently held.
    pub member_count: u64,
    pub max_bytes: u64,
    pub created_at_ms: i64,
    pub expires_at_ms: i64,
    pub completion: Option<ResourceCompletion>,
    /// The frozen selection while `Prepared`; retained after completion as
    /// the generation the completion names.
    pub prepared: Option<Kappa>,
    /// Opaque protocol binding fixed at open (an S3 object key, for
    /// instance), committed with the head and gone with it, so a request
    /// addressing the resource is checked against the binding through
    /// every phase, including replay of a completed outcome.
    pub context: Option<Vec<u8>>,
}

wire_map!(ResourceHead {
    namespace_id: bytes = 0,
    incarnation: bytes = 1,
    kind: value = 2,
    revision: value = 3,
    phase: value = 4,
    total_bytes: value = 5,
    member_count: value = 6,
    max_bytes: value = 7,
    created_at_ms: value = 8,
    expires_at_ms: value = 9,
    completion: optional = 10,
    prepared: optional = 11,
    context: optional_bytes = 12,
});

impl ResourceHead {
    pub fn anchor(&self) -> ResourceAnchor {
        ResourceAnchor {
            namespace_id: self.namespace_id.clone(),
            incarnation: self.incarnation.clone(),
        }
    }

    /// Hex of the incarnation: the resource's protocol-visible id.
    pub fn id(&self) -> String {
        hex::encode(&self.incarnation)
    }

    /// Tag name under which the head is published.
    pub fn tag_name(id: &str) -> String {
        format!("_resource/{id}")
    }

    /// Namespace metadata key naming the committed member edge at
    /// `coordinate` (offset, slot, or identity string), so staging never
    /// enumerates the membership.
    pub fn member_key(id: &str, coordinate: &str) -> String {
        format!("_resource/{id}/m/{coordinate}")
    }

    /// Namespace metadata key naming the head's current `Owns` edge.
    pub fn owns_key(id: &str) -> String {
        format!("_resource/{id}/owns")
    }

    pub fn validate(&self, namespace_id: &[u8]) -> Result<(), StoreError> {
        if self.namespace_id != namespace_id {
            return Err(StoreError::Rejected(
                "resource head belongs to another namespace".into(),
            ));
        }
        if self.incarnation.len() != 16 {
            return Err(StoreError::Rejected(
                "resource incarnation is not 16 bytes".into(),
            ));
        }
        match self.phase {
            ResourcePhase::Completed if self.completion.is_none() => Err(StoreError::Rejected(
                "completed resource lacks its completion binding".into(),
            )),
            ResourcePhase::Prepared if self.prepared.is_none() => Err(StoreError::Rejected(
                "prepared resource lacks its generation".into(),
            )),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{canonical_bytes, from_canonical};

    #[test]
    fn head_coordinate_selection_and_completion_roundtrip() -> Result<(), StoreError> {
        let selection = ResourceSelection {
            namespace_id: vec![1; 16],
            incarnation: vec![2; 16],
            revision: 4,
            request: Kappa::sha256(b"request"),
            members: vec![SelectedMember {
                identity: Kappa::sha256(b"part"),
                position: 1,
                length: 10,
            }],
            total_bytes: 10,
        };
        selection.validate(&[1; 16], &[2; 16])?;
        assert!(selection.validate(&[9; 16], &[2; 16]).is_err());
        let decoded: ResourceSelection = from_canonical(&canonical_bytes(&selection))?;
        assert_eq!(decoded, selection);
        let head = ResourceHead {
            namespace_id: vec![1; 16],
            incarnation: vec![2; 16],
            kind: ResourceKind::Numbered,
            revision: 5,
            phase: ResourcePhase::Completed,
            total_bytes: 10,
            member_count: 1,
            max_bytes: 100,
            created_at_ms: 5,
            expires_at_ms: 6,
            completion: Some(ResourceCompletion {
                request: Kappa::sha256(b"request"),
                generation: selection.identity(),
                result: Kappa::sha256(b"result"),
                aliases: vec![Kappa::sha256(b"alias")],
                receipt: Some(b"\"etag-1\"".to_vec()),
            }),
            prepared: Some(selection.identity()),
            context: Some(b"bucket/key".to_vec()),
        };
        head.validate(&[1; 16])?;
        let decoded: ResourceHead = from_canonical(&canonical_bytes(&head))?;
        assert_eq!(decoded, head);
        let prepared = ResourceHead {
            phase: ResourcePhase::Prepared,
            prepared: None,
            ..head
        };
        assert!(prepared.validate(&[1; 16]).is_err());
        let coordinate = MemberCoordinate {
            position: 7,
            length: 3,
            receipt: Some(vec![4, 5]),
        };
        let decoded: MemberCoordinate = from_canonical(&canonical_bytes(&coordinate))?;
        assert_eq!(decoded, coordinate);
        Ok(())
    }
}
