use std::sync::Arc;

use dcbor::prelude::*;

use crate::axis::Axis;
use crate::canonical::{
    CanonicalError, DecodeCost, SharedRecord, bounded_record, canonical_bytes, decode_cost,
    from_canonical,
};
use crate::capacity::CapacityPool;
use crate::clock::ClockMs;
use crate::epoch::EpochMutation;
use crate::error::StoreError;
use crate::kappa::Kappa;
use crate::merkle;
use crate::namespace::NamespaceRef;
use crate::signed::SignedPayload;
use crate::verified::VerifiedContent;
use crate::work::{Dimension, Meter, Work};

mod encoding;

/// The format version every epoch root carries at key 12.
pub const EPOCH_FORMAT_STATE: u64 = 2;

/// A sealed epoch root with deterministic content-addressing.
///
/// CBOR key assignments (PERMANENT):
///   0: namespace UUID bytes, 1: `epoch_number`, 2: `prev_identifier`,
///   3: `state_digest`, 4: `mutations_root`, 5: timestamp,
///   6: signer, 7: `tag_count`, 8: `rotation_kappa`,
///   9: `cose_signature`, 10: `ledger_root`, 11: `state`,
///   12: format version
///
/// `state` (key 11) is the identity of the canonical
/// `namespace_state::NamespaceState` record the epoch commits: the
/// namespace instance, its authority record, its current-state index root
/// and its history log.
///
/// `format_version` (key 12) is [`EPOCH_FORMAT_STATE`]. Unknown versions
/// and unknown keys above 12 are rejected at decoding.
#[derive(Debug, Clone)]
pub struct EpochRootData {
    pub namespace_id: ByteString,
    pub epoch_number: u64,
    pub prev_identifier: Option<Kappa>,
    pub state_digest: ByteString,
    pub mutations_root: ByteString,
    pub timestamp_ms: i64,
    pub signer_anchor: Kappa,
    pub tag_count: u64,
    pub rotation_kappa: Option<Kappa>,
    pub cose_signature: SignedPayload,
    pub ledger_root: Kappa,
    pub state: Kappa,
    pub format_version: u64,
}

impl From<&EpochRootData> for CBOR {
    fn from(data: &EpochRootData) -> Self {
        let mut map = Map::new();
        map.insert(0u64, data.namespace_id.clone());
        map.insert(1u64, data.epoch_number);
        if let Some(prev) = &data.prev_identifier {
            map.insert(2u64, prev.clone());
        }
        map.insert(3u64, data.state_digest.clone());
        map.insert(4u64, data.mutations_root.clone());
        map.insert(5u64, data.timestamp_ms);
        map.insert(6u64, data.signer_anchor.clone());
        map.insert(7u64, data.tag_count);
        if let Some(rotation) = &data.rotation_kappa {
            map.insert(8u64, rotation.clone());
        }
        map.insert(9u64, data.cose_signature.clone());
        map.insert(10u64, data.ledger_root.clone());
        map.insert(11u64, data.state.clone());
        map.insert(12u64, data.format_version);
        map.into()
    }
}

impl From<EpochRootData> for CBOR {
    fn from(data: EpochRootData) -> Self {
        Self::from(&data)
    }
}

impl EpochRootData {
    /// The fixed lengths every root carries: a 16-byte namespace identity
    /// and 32-byte state digest and mutation root. Checked by both decoding
    /// paths after structural construction.
    fn validate_root_lengths(&self) -> Result<(), dcbor::Error> {
        if self.namespace_id.len() != 16
            || self.state_digest.len() != 32
            || self.mutations_root.len() != 32
        {
            return Err(dcbor::Error::msg(
                "epoch namespace UUID must contain 16 bytes; digest and mutation root must each contain 32 bytes",
            ));
        }
        Ok(())
    }
}

/// The same record constructed from a strictly decoded document, under the
/// same refusals as the symbolic decoding: an unknown format version, a key
/// above 12 or repeated, a required key absent, and the fixed lengths
/// ([`EpochRootData::validate_root_lengths`]). The byte strings and the
/// signature are copied once each into storage requested from the
/// allocator; the identities are heap-free text parses.
impl dcbor::bounded::decode::BoundedDecodable for EpochRootData {
    fn construct<A: dcbor::bounded::Allocator>(
        node: dcbor::bounded::decode::Node<'_, '_>,
        permits: &mut dcbor::bounded::Owned<A::Permit, A::Permit>,
        allocator: &mut A,
    ) -> dcbor::bounded::decode::ConstructResult<Self, A> {
        use dcbor::bounded::decode::DecodeError;

        use crate::canonical::{bounded_map_fields, bounded_required};

        let fields = bounded_map_fields::<A, 13>(node, allocator)?;
        let format_version = u64::construct(bounded_required(fields[12])?, permits, allocator)?;
        if format_version != EPOCH_FORMAT_STATE {
            return Err(DecodeError::Invalid(dcbor::Error::msg(format!(
                "unknown epoch format version {format_version}"
            ))));
        }
        let prev_identifier = match fields[2] {
            Some(node) => Some(Kappa::construct(node, permits, allocator)?),
            None => None,
        };
        let rotation_kappa = match fields[8] {
            Some(node) => Some(Kappa::construct(node, permits, allocator)?),
            None => None,
        };
        let data = Self {
            namespace_id: ByteString::construct(bounded_required(fields[0])?, permits, allocator)?,
            epoch_number: u64::construct(bounded_required(fields[1])?, permits, allocator)?,
            prev_identifier,
            state_digest: ByteString::construct(bounded_required(fields[3])?, permits, allocator)?,
            mutations_root: ByteString::construct(
                bounded_required(fields[4])?,
                permits,
                allocator,
            )?,
            timestamp_ms: i64::construct(bounded_required(fields[5])?, permits, allocator)?,
            signer_anchor: Kappa::construct(bounded_required(fields[6])?, permits, allocator)?,
            tag_count: u64::construct(bounded_required(fields[7])?, permits, allocator)?,
            rotation_kappa,
            cose_signature: SignedPayload::construct(
                bounded_required(fields[9])?,
                permits,
                allocator,
            )?,
            ledger_root: Kappa::construct(bounded_required(fields[10])?, permits, allocator)?,
            state: Kappa::construct(bounded_required(fields[11])?, permits, allocator)?,
            format_version,
        };
        data.validate_root_lengths().map_err(DecodeError::Invalid)?;
        Ok(data)
    }
}

impl crate::canonical::BoundedRecord for EpochRootData {
    // All fields are scalars. Every text is an ASCII Kappa label; the COSE
    // envelope is an opaque byte string at this boundary.
    const OPTIONS: dcbor::bounded::decode::Options = dcbor::bounded::decode::Options::quick_only(1);
    const AXIS: Axis = Axis::Sha256;
    const FIELDS: &'static [u8] = &[4, 1, 8, 4, 4, 3, 8, 1, 8, 4, 8, 8, 1];

    fn construction(input: u64) -> crate::canonical::ConstructionBound {
        crate::canonical::ConstructionBound {
            // Map plus at most fourteen keys (the last refused), and thirteen
            // field constructors. Payload regions are disjoint in the input.
            values: 28,
            bytes: input,
            allocated: input,
            peak: input,
            held: input,
            permits: 4,
        }
    }
}

impl TryFrom<CBOR> for EpochRootData {
    type Error = dcbor::Error;

    fn try_from(cbor: CBOR) -> Result<Self, Self::Error> {
        let CBORCase::Map(map) = cbor.into_case() else {
            return Err(dcbor::Error::WrongType);
        };
        let format_version: u64 = map.extract(12u64)?;
        if format_version != EPOCH_FORMAT_STATE {
            return Err(dcbor::Error::msg(format!(
                "unknown epoch format version {format_version}"
            )));
        }
        for (key, _) in map.iter() {
            let key: u64 = key.clone().try_into()?;
            if key > 12 {
                return Err(dcbor::Error::msg("unknown epoch root field"));
            }
        }
        Ok(Self {
            namespace_id: {
                let bs: ByteString = map.extract(0u64)?;
                bs
            },
            epoch_number: map.extract(1u64)?,
            prev_identifier: if map.contains_key(2u64) {
                Some(map.extract(2u64)?)
            } else {
                None
            },
            state_digest: {
                let bs: ByteString = map.extract(3u64)?;
                bs
            },
            mutations_root: {
                let bs: ByteString = map.extract(4u64)?;
                bs
            },
            timestamp_ms: map.extract(5u64)?,
            signer_anchor: map.extract(6u64)?,
            tag_count: map.extract(7u64)?,
            rotation_kappa: if map.contains_key(8u64) {
                Some(map.extract(8u64)?)
            } else {
                None
            },
            cose_signature: map.extract(9u64)?,
            ledger_root: map.extract(10u64)?,
            state: map.extract(11u64)?,
            format_version,
        })
    }
}

/// Signing payload: keys 0-8, 10, 11 and 12 (the COSE envelope at key 9
/// is excluded from its own payload).
#[derive(Clone)]
struct EpochRootSignable {
    namespace_id: ByteString,
    epoch_number: u64,
    prev_identifier: Option<Kappa>,
    state_digest: ByteString,
    mutations_root: ByteString,
    timestamp_ms: i64,
    signer_anchor: Kappa,
    tag_count: u64,
    rotation_kappa: Option<Kappa>,
    ledger_root: Kappa,
    state: Kappa,
    format_version: u64,
}

crate::wire_map::wire_map!(EpochRootSignable {
    namespace_id: value = 0,
    epoch_number: value = 1,
    prev_identifier: optional = 2,
    state_digest: value = 3,
    mutations_root: value = 4,
    timestamp_ms: value = 5,
    signer_anchor: value = 6,
    tag_count: value = 7,
    rotation_kappa: optional = 8,
    ledger_root: value = 10,
    state: value = 11,
    format_version: value = 12,
});

/// Input for constructing an epoch root from pre-computed roots.
#[derive(Debug, Clone, Copy)]
pub struct EpochRootInput<'a> {
    pub namespace: &'a NamespaceRef,
    pub epoch_number: u64,
    pub prev_identifier: Option<&'a Kappa>,
    pub state_digest: [u8; 32],
    pub mutations_root: [u8; 32],
    pub timestamp: ClockMs,
    pub signer_anchor: &'a Kappa,
    pub tag_count: u64,
    pub rotation_kappa: Option<&'a Kappa>,
    pub ledger_root: &'a Kappa,
    /// Identity of the committed `NamespaceState` record.
    pub state: &'a Kappa,
}

/// Input for constructing an epoch root with verified roots.
#[derive(Debug, Clone, Copy)]
pub struct EpochRootVerifiedInput<'a> {
    pub namespace: &'a NamespaceRef,
    pub epoch_number: u64,
    pub prev_identifier: Option<&'a Kappa>,
    pub sorted_tags: &'a [(&'a str, &'a Kappa)],
    pub mutations: &'a [EpochMutation],
    pub timestamp: ClockMs,
    pub signer_anchor: &'a Kappa,
    pub rotation_kappa: Option<&'a Kappa>,
    /// Identity of the committed `NamespaceState` record.
    pub state: &'a Kappa,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EpochRootError {
    #[error("canonical: {0}")]
    Canonical(#[from] CanonicalError),
}

/// How a root owns its data: built or symbolically decoded, owned outright;
/// or constructed under bounded decoding, owned together with the
/// reservations of every allocation it holds ([`crate::canonical::Record`]), shared by every
/// clone of the root and released when the last drops. No path moves the
/// data out of its reservations.
#[derive(Clone)]
enum RootData {
    Owned(EpochRootData),
    Decoded(SharedRecord<EpochRootData>),
}

impl RootData {
    fn get(&self) -> &EpochRootData {
        match self {
            Self::Owned(data) => data,
            Self::Decoded(decoded) => decoded.value(),
        }
    }
}

/// Wrapper that caches the content-address kappa.
#[derive(Clone)]
pub struct EpochRoot {
    data: RootData,
    cached_kappa: Kappa,
}

impl std::fmt::Debug for EpochRoot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EpochRoot")
            .field("data", self.data.get())
            .field("cached_kappa", &self.cached_kappa)
            .finish()
    }
}

impl EpochRoot {
    /// Complete verified construction, including the strong-only shared owner.
    /// The parser arena is released before the shared allocation is created.
    pub fn verified_cost(length: u64) -> Result<DecodeCost, StoreError> {
        let mut cost = decode_cost::<EpochRootData>(length)?;
        let shared = SharedRecord::<EpochRootData>::allocation_bytes();
        cost.work
            .checked_add_assign(&Work::default().with(Dimension::BytesAllocated, shared))
            .map_err(|_| StoreError::CapacityExceeded("shared root work overflows".into()))?;
        cost.held = cost
            .held
            .checked_add(shared)
            .ok_or_else(|| StoreError::CapacityExceeded("shared root capacity overflows".into()))?;
        cost.peak = cost.peak.max(cost.held);
        Ok(cost)
    }

    fn data(&self) -> &EpochRootData {
        self.data.get()
    }

    /// The root `evidence` holds, constructed under bounded decoding on
    /// `work` in storage reserved from `storage`
    /// ([`bounded_record`]): the bytes decoded and the identity
    /// cached are the one verified owner's, so the cached identity is the
    /// content address of exactly the bytes the data came from, established
    /// by `evidence`'s verification and not hashed again here. A root's
    /// identity is its SHA-256 (`build`), so evidence under another axis is
    /// refused before anything is decoded. The fallible shared allocation
    /// retains its own reservation until deallocation after the last owner.
    pub fn from_verified(
        evidence: &VerifiedContent,
        max_depth: usize,
        work: &mut dyn Meter,
        storage: &Arc<CapacityPool>,
    ) -> Result<Self, StoreError> {
        if evidence.axis() != Axis::Sha256 {
            return Err(StoreError::Rejected(format!(
                "epoch root identity {} is not a SHA-256 content address",
                evidence.kappa()
            )));
        }
        if max_depth == 0 {
            return Err(StoreError::CapacityExceeded(
                "epoch root requires one map nesting level".into(),
            ));
        }
        let cost = Self::verified_cost(evidence.len() as u64)?;
        let mut unit = work.admit(&cost.work.as_bound())?;
        let data = bounded_record::<EpochRootData>(evidence, &mut unit, storage)?;
        let data = SharedRecord::new(data, &mut unit, storage)?;
        Ok(Self {
            data: RootData::Decoded(data),
            cached_kappa: evidence.kappa().clone(),
        })
    }

    /// Canonical keys 0-8, 10, 11 and 12. The COSE envelope is excluded
    /// from its own payload.
    pub fn signable_bytes(&self) -> Vec<u8> {
        let data = self.data();
        canonical_bytes(&EpochRootSignable {
            namespace_id: data.namespace_id.clone(),
            epoch_number: data.epoch_number,
            prev_identifier: data.prev_identifier.clone(),
            state_digest: data.state_digest.clone(),
            mutations_root: data.mutations_root.clone(),
            timestamp_ms: data.timestamp_ms,
            signer_anchor: data.signer_anchor.clone(),
            tag_count: data.tag_count,
            rotation_kappa: data.rotation_kappa.clone(),
            ledger_root: data.ledger_root.clone(),
            state: data.state.clone(),
            format_version: data.format_version,
        })
    }

    pub fn build(input: EpochRootInput<'_>) -> Self {
        let data = EpochRootData {
            namespace_id: ByteString::from(*input.namespace.id()),
            epoch_number: input.epoch_number,
            prev_identifier: input.prev_identifier.cloned(),
            state_digest: ByteString::from(input.state_digest),
            mutations_root: ByteString::from(input.mutations_root),
            timestamp_ms: input.timestamp.as_i64(),
            signer_anchor: input.signer_anchor.clone(),
            tag_count: input.tag_count,
            rotation_kappa: input.rotation_kappa.cloned(),
            cose_signature: SignedPayload::empty(),
            ledger_root: input.ledger_root.clone(),
            state: input.state.clone(),
            format_version: EPOCH_FORMAT_STATE,
        };
        let cached_kappa = Kappa::sha256(&canonical_bytes(&data));
        Self {
            data: RootData::Owned(data),
            cached_kappa,
        }
    }

    pub fn build_verified(input: EpochRootVerifiedInput<'_>) -> Self {
        let mut digest = crate::StateDigest::default();
        for (name, kappa) in input.sorted_tags {
            digest.insert(name, kappa);
        }
        let state_root = digest.into_bytes();
        let mutations_root = mutations_merkle_root(input.mutations);
        let ledger_root = Kappa::sha256(&canonical_bytes(&input.mutations.to_vec()));
        let tag_count = input.sorted_tags.len() as u64;

        Self::build(EpochRootInput {
            namespace: input.namespace,
            epoch_number: input.epoch_number,
            prev_identifier: input.prev_identifier,
            state_digest: state_root,
            mutations_root,
            timestamp: input.timestamp,
            signer_anchor: input.signer_anchor,
            tag_count,
            rotation_kappa: input.rotation_kappa,
            ledger_root: &ledger_root,
            state: input.state,
        })
    }

    /// This root signed, its identity recomputed. A built root
    /// (`RootData::Owned`, the only root the sealing path signs) is moved
    /// and mutated, never copied. A root constructed from stored bytes
    /// (`RootData::Decoded`) is a committed epoch and is not signed again:
    /// its data is copied out of its retained ownership into an owned root,
    /// a copy the sealing path's allowance, not the decoder's permits,
    /// stands behind.
    #[must_use]
    pub fn with_signature(self, cose_signature: SignedPayload) -> Self {
        let mut data = match self.data {
            RootData::Owned(data) => data,
            RootData::Decoded(decoded) => decoded.value().clone(),
        };
        data.cose_signature = cose_signature;
        let cached_kappa = Kappa::sha256(&canonical_bytes(&data));
        Self {
            data: RootData::Owned(data),
            cached_kappa,
        }
    }

    pub const fn kappa(&self) -> &Kappa {
        &self.cached_kappa
    }

    /// The identity of this root without its signature: the identity the
    /// unsigned root it was signed from has (`build`), which names the
    /// publication candidate before and after signing.
    #[cfg(test)]
    fn unsigned_identity(&self) -> Kappa {
        let mut data = self.data().clone();
        data.cose_signature = SignedPayload::empty();
        Kappa::sha256(&canonical_bytes(&data))
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        canonical_bytes(self.data())
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CanonicalError> {
        let epoch_data: EpochRootData = from_canonical(data)?;
        epoch_data
            .validate_root_lengths()
            .map_err(CanonicalError::Conversion)?;
        let cached_kappa = Kappa::sha256(data);
        Ok(Self {
            data: RootData::Owned(epoch_data),
            cached_kappa,
        })
    }

    pub fn namespace_id(&self) -> &[u8] {
        &self.data().namespace_id
    }
    pub fn epoch_number(&self) -> u64 {
        self.data().epoch_number
    }
    pub fn prev_identifier(&self) -> Option<&Kappa> {
        self.data().prev_identifier.as_ref()
    }
    pub fn state_digest(&self) -> &[u8] {
        &self.data().state_digest
    }
    pub fn mutations_root(&self) -> &[u8] {
        &self.data().mutations_root
    }
    pub fn timestamp(&self) -> ClockMs {
        ClockMs::from_raw(self.data().timestamp_ms)
    }
    pub fn timestamp_ms(&self) -> i64 {
        self.data().timestamp_ms
    }
    pub fn signer_anchor(&self) -> &Kappa {
        &self.data().signer_anchor
    }
    pub fn tag_count(&self) -> u64 {
        self.data().tag_count
    }
    pub fn rotation_kappa(&self) -> Option<&Kappa> {
        self.data().rotation_kappa.as_ref()
    }
    pub fn cose_signature(&self) -> &SignedPayload {
        &self.data().cose_signature
    }

    pub fn ledger_root(&self) -> &Kappa {
        &self.data().ledger_root
    }

    /// Identity of the `NamespaceState` record this epoch commits.
    pub fn state(&self) -> &Kappa {
        &self.data().state
    }
}

/// Compute the state Merkle root from sorted (name, kappa) pairs.
///
/// An empty tag set produces `merkle::EMPTY_ROOT`.
pub fn state_merkle_root(sorted_tags: &[(&str, &Kappa)]) -> [u8; 32] {
    let leaf_bytes: Vec<Vec<u8>> = sorted_tags
        .iter()
        .map(|(name, kappa)| {
            let name_cbor: CBOR = CBOR::from(name.to_string());
            let kappa_cbor: CBOR = CBOR::from(*kappa);
            let pair: CBOR = vec![name_cbor, kappa_cbor].into();
            pair.to_cbor_data()
        })
        .collect();
    let refs: Vec<&[u8]> = leaf_bytes.iter().map(Vec::as_slice).collect();
    merkle::merkle_root(&refs)
}

/// Compute the mutations Merkle root from a list of mutations.
///
/// An empty mutation list produces `merkle::EMPTY_ROOT`.
pub fn mutations_merkle_root(mutations: &[EpochMutation]) -> [u8; 32] {
    let leaf_bytes: Vec<Vec<u8>> = mutations.iter().map(canonical_bytes).collect();
    let refs: Vec<&[u8]> = leaf_bytes.iter().map(Vec::as_slice).collect();
    merkle::merkle_root(&refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_clock(ms: i64) -> ClockMs {
        ClockMs::test_value(ms)
    }

    fn test_anchor() -> Kappa {
        Kappa::sha256(b"test-signer")
    }

    fn test_state() -> Kappa {
        Kappa::sha256(b"namespace-state")
    }

    fn unsigned_epoch(ns: &str, epoch: u64) -> EpochRoot {
        EpochRoot::build(EpochRootInput {
            namespace: &NamespaceRef::deterministic(ns),
            epoch_number: epoch,
            prev_identifier: None,
            state_digest: [0u8; 32],
            mutations_root: [0u8; 32],
            timestamp: test_clock(1000),
            signer_anchor: &test_anchor(),
            tag_count: 0,
            rotation_kappa: None,
            ledger_root: &Kappa::sha256(&canonical_bytes(&Vec::<EpochMutation>::new())),
            state: &test_state(),
        })
    }

    /// The state commitment is signed and required: another state
    /// produces a different signing payload and identity, and a root
    /// without key 11 does not decode.
    #[test]
    fn the_state_commitment_is_signed_and_required() -> Result<(), dcbor::Error> {
        let root = unsigned_epoch("ns", 1);
        assert_eq!(root.state(), &test_state());
        let other = EpochRoot::build(EpochRootInput {
            namespace: &NamespaceRef::deterministic("ns"),
            epoch_number: 1,
            prev_identifier: None,
            state_digest: [0u8; 32],
            mutations_root: [0u8; 32],
            timestamp: test_clock(1000),
            signer_anchor: &test_anchor(),
            tag_count: 0,
            rotation_kappa: None,
            ledger_root: &Kappa::sha256(&canonical_bytes(&Vec::<EpochMutation>::new())),
            state: &Kappa::sha256(b"other-state"),
        });
        assert_ne!(root.signable_bytes(), other.signable_bytes());
        assert_ne!(root.kappa(), other.kappa());
        let CBORCase::Map(map) = CBOR::try_from_data(root.signable_bytes())?.into_case() else {
            panic!("epoch signable form must be a map");
        };
        let signed: Kappa = map.extract(11u64)?;
        assert_eq!(&signed, root.state());
        let version: u64 = map.extract(12u64)?;
        assert_eq!(version, EPOCH_FORMAT_STATE);
        let CBORCase::Map(map) = CBOR::try_from_data(root.to_bytes())?.into_case() else {
            panic!("epoch must encode as a map");
        };
        let mut stateless = Map::new();
        for (key, value) in map.iter() {
            if key != &CBOR::from(11u64) {
                stateless.insert(key.clone(), value.clone());
            }
        }
        assert!(EpochRoot::from_bytes(&CBOR::from(stateless).to_cbor_data()).is_err());
        Ok(())
    }

    #[test]
    fn build_and_serialize_roundtrip() -> Result<(), CanonicalError> {
        let root = unsigned_epoch("test-ns", 1);
        let bytes = root.to_bytes();
        let recovered = EpochRoot::from_bytes(&bytes)?;
        assert_eq!(
            recovered.namespace_id(),
            NamespaceRef::deterministic("test-ns").id()
        );
        assert_eq!(recovered.epoch_number(), 1);
        assert!(recovered.prev_identifier().is_none());
        assert!(recovered.cose_signature().is_empty());
        assert!(recovered.rotation_kappa().is_none());
        assert_eq!(recovered.state(), &test_state());
        Ok(())
    }

    /// A root constructed from verified bytes carries the identity of
    /// exactly those bytes, hashes nothing again, and releases every
    /// reservation of its decoded data with the last root that shares it.
    #[test]
    fn bounded_root_identity_comes_from_its_verified_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let original =
            unsigned_epoch("ns", 1).with_signature(SignedPayload::from_cose_bytes(vec![7; 64]));
        let bytes = original.to_bytes();
        let evidence = VerifiedContent::verify_owned(original.kappa(), bytes)?;
        let pool = Arc::new(CapacityPool::new(
            "bounded root test",
            crate::canonical::DEFAULT_DECODED_STORAGE,
        ));
        let mut work = crate::work::WorkMeter::unbounded();
        let decoded = EpochRoot::from_verified(&evidence, 64, &mut work, &pool)?;
        assert_eq!(decoded.kappa(), original.kappa());
        assert_eq!(decoded.to_bytes(), evidence.content());
        assert_eq!(decoded.cose_signature(), original.cose_signature());
        assert_eq!(
            work.used().get(crate::work::Dimension::BytesHashed),
            0,
            "verified root construction must not hash its content again"
        );
        assert!(pool.used() > 0, "the decoded data holds its reservations");
        let shared = decoded.clone();
        drop(decoded);
        assert!(pool.used() > 0, "a surviving clone keeps them");
        drop(shared);
        assert_eq!(pool.used(), 0, "the last clone releases them");
        Ok(())
    }

    /// Verified content under another axis is not a root identity and is
    /// refused before anything is decoded or reserved.
    #[test]
    fn bounded_root_rejects_verified_content_under_another_axis()
    -> Result<(), Box<dyn std::error::Error>> {
        let original = unsigned_epoch("ns", 1);
        let evidence = VerifiedContent::compute_owned(Axis::Blake3, original.to_bytes())?;
        let pool = Arc::new(CapacityPool::new(
            "bounded root test",
            crate::canonical::DEFAULT_DECODED_STORAGE,
        ));
        let mut work = crate::work::WorkMeter::unbounded();
        assert!(matches!(
            EpochRoot::from_verified(&evidence, 64, &mut work, &pool),
            Err(StoreError::Rejected(_))
        ));
        assert_eq!(pool.used(), 0);
        assert_eq!(work.used().get(crate::work::Dimension::BytesDecoded), 0);
        Ok(())
    }

    /// Bounded construction refuses what the symbolic path refuses: an
    /// unknown key, an unknown format version, a missing required field and
    /// a wrong fixed length, each with nothing left reserved.
    #[test]
    fn bounded_root_construction_keeps_the_strict_contract() -> Result<(), dcbor::Error> {
        let pool = Arc::new(CapacityPool::new(
            "bounded root test",
            crate::canonical::DEFAULT_DECODED_STORAGE,
        ));
        let CBORCase::Map(map) =
            CBOR::try_from_data(unsigned_epoch("ns", 1).to_bytes())?.into_case()
        else {
            panic!("epoch must encode as a map");
        };
        let refused = |bytes: Vec<u8>| {
            let evidence = VerifiedContent::compute_owned(Axis::Sha256, bytes)
                .unwrap_or_else(|error| panic!("sha256 computes for every input: {error}"));
            let mut work = crate::work::WorkMeter::unbounded();
            let outcome = EpochRoot::from_verified(&evidence, 64, &mut work, &pool);
            assert_eq!(pool.used(), 0, "a refused construction reserves nothing");
            matches!(outcome, Err(StoreError::Rejected(_)))
        };
        let mut unknown = map.clone();
        unknown.insert(13u64, "extension");
        assert!(refused(CBOR::from(unknown).to_cbor_data()), "unknown key");
        let mut version = map.clone();
        version.insert(12u64, 99u64);
        assert!(
            refused(CBOR::from(version).to_cbor_data()),
            "unknown version"
        );
        let mut missing = Map::new();
        for (key, value) in map.iter() {
            if key != &CBOR::from(11u64) {
                missing.insert(key.clone(), value.clone());
            }
        }
        assert!(refused(CBOR::from(missing).to_cbor_data()), "missing state");
        for (key, length) in [(0u64, 15), (3, 31), (4, 31)] {
            let mut short = map.clone();
            short.insert(key, ByteString::from(vec![0; length]));
            assert!(
                refused(CBOR::from(short).to_cbor_data()),
                "key {key} of {length} bytes"
            );
        }
        Ok(())
    }

    #[test]
    fn kappa_is_deterministic() {
        let a = unsigned_epoch("ns", 1);
        let b = unsigned_epoch("ns", 1);
        assert_eq!(a.kappa(), b.kappa());
    }

    #[test]
    fn kappa_cached_matches_recomputed() {
        let root = unsigned_epoch("ns", 1);
        let recomputed = Kappa::sha256(&root.to_bytes());
        assert_eq!(*root.kappa(), recomputed);
    }

    #[test]
    fn signed_epoch_changes_kappa() {
        let unsigned = unsigned_epoch("ns", 1);
        let signed = unsigned_epoch("ns", 1)
            .with_signature(SignedPayload::from_cose_bytes(vec![1, 2, 3, 4]));
        assert_ne!(unsigned.kappa(), signed.kappa());
    }

    /// A signed root names the unsigned root it was signed from: its
    /// unsigned identity is that root's identity, whatever the signature,
    /// and survives encoding.
    #[test]
    fn a_signed_root_names_its_unsigned_root() -> Result<(), CanonicalError> {
        let unsigned = unsigned_epoch("ns", 1);
        assert_eq!(&unsigned.unsigned_identity(), unsigned.kappa());
        let signed = unsigned_epoch("ns", 1)
            .with_signature(SignedPayload::from_cose_bytes(vec![1, 2, 3, 4]));
        assert_ne!(signed.kappa(), unsigned.kappa());
        assert_eq!(&signed.unsigned_identity(), unsigned.kappa());
        let decoded = EpochRoot::from_bytes(&signed.to_bytes())?;
        assert_eq!(&decoded.unsigned_identity(), unsigned.kappa());
        assert_ne!(
            &unsigned_epoch("ns", 2).unsigned_identity(),
            unsigned.kappa()
        );
        Ok(())
    }

    #[test]
    fn signed_epoch_roundtrip() -> Result<(), CanonicalError> {
        let root = unsigned_epoch("ns", 1).with_signature(SignedPayload::from_cose_bytes(vec![99]));
        let bytes = root.to_bytes();
        let recovered = EpochRoot::from_bytes(&bytes)?;
        assert!(recovered.cose_signature().is_signed());
        assert_eq!(recovered.cose_signature().as_bytes(), &[99]);
        assert_eq!(recovered.kappa(), root.kappa());
        Ok(())
    }

    #[test]
    fn rotation_kappa_preserved() -> Result<(), CanonicalError> {
        let rotation = Kappa::sha256(b"succession-kappa");
        let root = EpochRoot::build(EpochRootInput {
            namespace: &NamespaceRef::deterministic("ns"),
            epoch_number: 5,
            prev_identifier: None,
            state_digest: [0u8; 32],
            mutations_root: [0u8; 32],
            timestamp: test_clock(5000),
            signer_anchor: &test_anchor(),
            tag_count: 0,
            rotation_kappa: Some(&rotation),
            ledger_root: &Kappa::sha256(&canonical_bytes(&Vec::<EpochMutation>::new())),
            state: &test_state(),
        });
        let bytes = root.to_bytes();
        let recovered = EpochRoot::from_bytes(&bytes)?;
        assert_eq!(recovered.rotation_kappa(), Some(&rotation));
        Ok(())
    }

    #[test]
    fn tag_count_reflected_in_kappa() {
        let state = test_state();
        let a = EpochRoot::build(EpochRootInput {
            namespace: &NamespaceRef::deterministic("ns"),
            epoch_number: 1,
            prev_identifier: None,
            state_digest: [0u8; 32],
            mutations_root: [0u8; 32],
            timestamp: test_clock(1000),
            signer_anchor: &test_anchor(),
            tag_count: 100,
            rotation_kappa: None,
            ledger_root: &Kappa::sha256(&canonical_bytes(&Vec::<EpochMutation>::new())),
            state: &state,
        });
        let b = EpochRoot::build(EpochRootInput {
            namespace: &NamespaceRef::deterministic("ns"),
            epoch_number: 1,
            prev_identifier: None,
            state_digest: [0u8; 32],
            mutations_root: [0u8; 32],
            timestamp: test_clock(1000),
            signer_anchor: &test_anchor(),
            tag_count: 200,
            rotation_kappa: None,
            ledger_root: &Kappa::sha256(&canonical_bytes(&Vec::<EpochMutation>::new())),
            state: &state,
        });
        assert_ne!(a.kappa(), b.kappa());
    }

    #[test]
    fn empty_roots_are_sha256_of_empty() {
        assert_eq!(state_merkle_root(&[]), merkle::EMPTY_ROOT);
        assert_eq!(mutations_merkle_root(&[]), merkle::EMPTY_ROOT);
    }

    #[test]
    fn epoch_digest_roots_and_signature_are_byte_strings() -> Result<(), dcbor::Error> {
        let root = unsigned_epoch("ns", 1);
        let cbor = CBOR::try_from_data(root.to_bytes())?;
        let CBORCase::Map(map) = cbor.into_case() else {
            panic!("epoch must be a map");
        };
        let mut expected = vec![0x58, 0x20];
        expected.extend_from_slice(&[0; 32]);
        for key in [3u64, 4] {
            let value: CBOR = map.extract(key)?;
            assert_eq!(value.to_cbor_data(), expected);
        }
        let signature: CBOR = map.extract(9u64)?;
        assert_eq!(signature.to_cbor_data(), [0x40]);
        Ok(())
    }

    #[test]
    fn namespace_rename_preserves_signed_identity_and_content_address() -> Result<(), dcbor::Error>
    {
        let before = NamespaceRef::resolved([7; 16], "before".into(), None);
        let after = NamespaceRef::resolved([7; 16], "after".into(), None);
        let other = NamespaceRef::resolved([8; 16], "before".into(), None);
        let anchor = test_anchor();
        let ledger = Kappa::sha256(b"ledger");
        let state = test_state();
        let build = |namespace| {
            EpochRoot::build(EpochRootInput {
                namespace,
                epoch_number: 1,
                prev_identifier: None,
                state_digest: [0; 32],
                mutations_root: [0; 32],
                timestamp: test_clock(1000),
                signer_anchor: &anchor,
                tag_count: 0,
                rotation_kappa: None,
                ledger_root: &ledger,
                state: &state,
            })
        };
        let initial = build(&before);
        let renamed = build(&after);
        assert_eq!(initial.signable_bytes(), renamed.signable_bytes());
        assert_eq!(initial.kappa(), renamed.kappa());
        assert_ne!(initial.kappa(), build(&other).kappa());
        let CBORCase::Map(map) = CBOR::try_from_data(initial.to_bytes())?.into_case() else {
            panic!("epoch must encode as a map");
        };
        let namespace: CBOR = map.extract(0u64)?;
        let mut expected = vec![0x50];
        expected.extend_from_slice(&[7; 16]);
        assert_eq!(namespace.to_cbor_data(), expected);
        Ok(())
    }

    #[test]
    fn signing_payload_commits_ledger_state_and_excludes_envelope() -> Result<(), dcbor::Error> {
        let root = unsigned_epoch("ns", 1);
        let payload = root.signable_bytes();
        let signed = root
            .clone()
            .with_signature(SignedPayload::from_cose_bytes(vec![1, 2]));
        assert_eq!(payload, signed.signable_bytes());
        let CBORCase::Map(map) = CBOR::try_from_data(payload)?.into_case() else {
            panic!("epoch signable form must be a map");
        };
        assert!(!map.contains_key(9u64));
        let ledger: Kappa = map.extract(10u64)?;
        assert_eq!(&ledger, root.ledger_root());
        let state: Kappa = map.extract(11u64)?;
        assert_eq!(&state, root.state());
        Ok(())
    }

    #[test]
    fn malformed_uuid_and_digest_lengths_are_rejected() -> Result<(), dcbor::Error> {
        for (key, length) in [(0u64, 15), (3, 31), (4, 31)] {
            let CBORCase::Map(mut map) =
                CBOR::try_from_data(unsigned_epoch("ns", 1).to_bytes())?.into_case()
            else {
                panic!("epoch must encode as a map");
            };
            map.insert(key, ByteString::from(vec![0; length]));
            assert!(EpochRoot::from_bytes(&CBOR::from(map).to_cbor_data()).is_err());
        }
        Ok(())
    }

    #[test]
    fn optional_links_are_omitted_and_malformed_present_links_are_rejected()
    -> Result<(), dcbor::Error> {
        let CBORCase::Map(map) =
            CBOR::try_from_data(unsigned_epoch("ns", 1).to_bytes())?.into_case()
        else {
            panic!("epoch must encode as a map");
        };
        assert!(!map.contains_key(2u64));
        assert!(!map.contains_key(8u64));
        for key in [2u64, 8] {
            for invalid in [CBOR::null(), CBOR::from(1u64), CBOR::from("invalid-kappa")] {
                let mut malformed = map.clone();
                malformed.insert(key, invalid);
                assert!(EpochRoot::from_bytes(&CBOR::from(malformed).to_cbor_data()).is_err());
            }
        }
        let mut unknown = map;
        unknown.insert(13u64, "unsigned extension");
        assert!(EpochRoot::from_bytes(&CBOR::from(unknown).to_cbor_data()).is_err());
        Ok(())
    }

    #[test]
    fn unknown_format_version_is_rejected() -> Result<(), dcbor::Error> {
        let CBORCase::Map(mut map) =
            CBOR::try_from_data(unsigned_epoch("ns", 1).to_bytes())?.into_case()
        else {
            panic!("epoch must encode as a map");
        };
        map.insert(12u64, 99u64);
        assert!(
            EpochRoot::from_bytes(&CBOR::from(map).to_cbor_data()).is_err(),
            "unknown format version must be rejected"
        );
        Ok(())
    }
}
