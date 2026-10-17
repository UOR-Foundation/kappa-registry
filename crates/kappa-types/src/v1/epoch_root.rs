use dcbor::prelude::*;

use crate::canonical::{CanonicalError, canonical_bytes, from_canonical};
use crate::clock::ClockMs;
use crate::epoch::EpochMutation;
use crate::kappa::Kappa;
use crate::merkle;
use crate::namespace::NamespaceRef;
use crate::signed::SignedPayload;

/// A sealed epoch root with deterministic content-addressing.
///
/// CBOR key assignments (PERMANENT):
///   0: namespace UUID bytes, 1: `epoch_number`, 2: `prev_identifier`,
///   3: `state_digest`, 4: `mutations_root`, 5: timestamp,
///   6: signer, 7: `tag_count`, 8: `rotation_kappa`,
///   9: `cose_signature`, 10: `ledger_root`
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
}

crate::wire_map::wire_map!(EpochRootData {
    namespace_id: value = 0,
    epoch_number: value = 1,
    prev_identifier: optional = 2,
    state_digest: value = 3,
    mutations_root: value = 4,
    timestamp_ms: value = 5,
    signer_anchor: value = 6,
    tag_count: value = 7,
    rotation_kappa: optional = 8,
    cose_signature: value = 9,
    ledger_root: value = 10,
});

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
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EpochRootError {
    #[error("canonical: {0}")]
    Canonical(#[from] CanonicalError),
}

/// Wrapper that caches the content-address kappa.
#[derive(Debug, Clone)]
pub struct EpochRoot {
    data: EpochRootData,
    cached_kappa: Kappa,
}

impl EpochRoot {
    /// Canonical keys 0-8 and 10. The COSE envelope is excluded from its own payload.
    pub fn signable_bytes(&self) -> Vec<u8> {
        canonical_bytes(&EpochRootSignable {
            namespace_id: self.data.namespace_id.clone(),
            epoch_number: self.data.epoch_number,
            prev_identifier: self.data.prev_identifier.clone(),
            state_digest: self.data.state_digest.clone(),
            mutations_root: self.data.mutations_root.clone(),
            timestamp_ms: self.data.timestamp_ms,
            signer_anchor: self.data.signer_anchor.clone(),
            tag_count: self.data.tag_count,
            rotation_kappa: self.data.rotation_kappa.clone(),
            ledger_root: self.data.ledger_root.clone(),
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
        };
        let cached_kappa = Kappa::sha256(&canonical_bytes(&data));
        Self { data, cached_kappa }
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
        })
    }

    #[must_use]
    pub fn with_signature(mut self, cose_signature: SignedPayload) -> Self {
        self.data.cose_signature = cose_signature;
        self.cached_kappa = Kappa::sha256(&canonical_bytes(&self.data));
        self
    }

    pub const fn kappa(&self) -> &Kappa {
        &self.cached_kappa
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        canonical_bytes(&self.data)
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self, CanonicalError> {
        let epoch_data: EpochRootData = from_canonical(data)?;
        if epoch_data.namespace_id.len() != 16
            || epoch_data.state_digest.len() != 32
            || epoch_data.mutations_root.len() != 32
        {
            return Err(CanonicalError::Conversion(dcbor::Error::msg(
                "epoch namespace UUID must contain 16 bytes; digest and mutation root must each contain 32 bytes",
            )));
        }
        let cached_kappa = Kappa::sha256(data);
        Ok(Self {
            data: epoch_data,
            cached_kappa,
        })
    }

    pub fn namespace_id(&self) -> &[u8] {
        &self.data.namespace_id
    }
    pub const fn epoch_number(&self) -> u64 {
        self.data.epoch_number
    }
    pub const fn prev_identifier(&self) -> Option<&Kappa> {
        self.data.prev_identifier.as_ref()
    }
    pub fn state_digest(&self) -> &[u8] {
        &self.data.state_digest
    }
    pub fn mutations_root(&self) -> &[u8] {
        &self.data.mutations_root
    }
    pub const fn timestamp(&self) -> ClockMs {
        ClockMs::from_raw(self.data.timestamp_ms)
    }
    pub const fn timestamp_ms(&self) -> i64 {
        self.data.timestamp_ms
    }
    pub const fn signer_anchor(&self) -> &Kappa {
        &self.data.signer_anchor
    }
    pub const fn tag_count(&self) -> u64 {
        self.data.tag_count
    }
    pub const fn rotation_kappa(&self) -> Option<&Kappa> {
        self.data.rotation_kappa.as_ref()
    }
    pub const fn cose_signature(&self) -> &SignedPayload {
        &self.data.cose_signature
    }

    pub const fn ledger_root(&self) -> &Kappa {
        &self.data.ledger_root
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
        })
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
        });
        let bytes = root.to_bytes();
        let recovered = EpochRoot::from_bytes(&bytes)?;
        assert_eq!(recovered.rotation_kappa(), Some(&rotation));
        Ok(())
    }

    #[test]
    fn tag_count_reflected_in_kappa() {
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
    fn signing_payload_commits_ledger_and_excludes_envelope() -> Result<(), dcbor::Error> {
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
        unknown.insert(11u64, "unsigned extension");
        assert!(EpochRoot::from_bytes(&CBOR::from(unknown).to_cbor_data()).is_err());
        Ok(())
    }
}
