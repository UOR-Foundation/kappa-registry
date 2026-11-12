use super::*;
use crate::canonical::canonical_bytes;
use crate::epoch_root::{EPOCH_FORMAT_STATE, EpochRootData};
use crate::namespace_state::NamespaceState;
use crate::signed::SignedPayload;
use crate::work::{WorkLimit, WorkMeter};
use dcbor::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn meter(cost: &DecodeCost) -> WorkMeter {
    let mut limit = WorkLimit::unbounded();
    for dimension in Dimension::ALL {
        limit = limit.with(dimension, cost.work.get(dimension));
    }
    WorkMeter::new(limit)
}

fn root(axis: Axis, signature: usize) -> Result<EpochRootData, StoreError> {
    let identity = Kappa::compute(axis, b"identity")?;
    Ok(EpochRootData {
        namespace_id: ByteString::from([1; 16]),
        epoch_number: u64::MAX,
        prev_identifier: Some(identity.clone()),
        state_digest: ByteString::from([2; 32]),
        mutations_root: ByteString::from([3; 32]),
        timestamp_ms: i64::MIN,
        signer_anchor: identity.clone(),
        tag_count: u64::MAX,
        rotation_kappa: Some(identity.clone()),
        cose_signature: SignedPayload::from_cose_bytes(vec![7; signature]),
        ledger_root: identity.clone(),
        state: identity,
        format_version: EPOCH_FORMAT_STATE,
    })
}

#[test]
fn all_label_axes_and_signature_growth_boundaries_fit() -> TestResult {
    for axis in [
        Axis::Sha256,
        Axis::Sha512,
        Axis::Blake3,
        Axis::Sha1,
        Axis::Sha3_256,
        Axis::Keccak256,
    ] {
        for signature in [0, 23, 24, 255, 256, 3309, 65536] {
            let original = root(axis, signature)?;
            let bytes = canonical_bytes(&original);
            let evidence = VerifiedContent::compute_owned(Axis::Sha256, bytes)?;
            let cost = decode_cost::<EpochRootData>(evidence.len() as u64)?;
            let pool = Arc::new(CapacityPool::new("record bound", cost.peak));
            let mut work = meter(&cost);
            let decoded = bounded_record::<EpochRootData>(&evidence, &mut work, &pool)?;
            assert_eq!(decoded.identity(), evidence.kappa());
            assert_eq!(canonical_bytes(decoded.value()), evidence.content());
            assert_eq!(work.used().get(Dimension::BytesHashed), 0);
            assert!(pool.used() <= cost.held);
            let consumed = *work.used();
            drop(decoded);
            assert_eq!(pool.used(), 0);
            assert_eq!(*work.used(), consumed);
        }
    }
    Ok(())
}

#[test]
fn admission_refusal_keeps_evidence_and_consumes_nothing() -> TestResult {
    let evidence =
        VerifiedContent::compute_owned(Axis::Sha256, canonical_bytes(&root(Axis::Sha256, 64)?))?;
    let cost = decode_cost::<EpochRootData>(evidence.len() as u64)?;
    let pool = Arc::new(CapacityPool::new("record bound", cost.peak));
    for dimension in Dimension::ALL {
        let bound = cost.work.get(dimension);
        if bound == 0 {
            continue;
        }
        let mut limited = WorkMeter::new(meter(&cost).limit().with(dimension, bound - 1));
        assert!(matches!(
            bounded_record::<EpochRootData>(&evidence, &mut limited, &pool),
            Err(StoreError::WorkRefused(_))
        ));
        assert_eq!(*limited.used(), Work::default());
        assert_eq!(pool.used(), 0);
    }
    let decoded = bounded_record::<EpochRootData>(&evidence, &mut meter(&cost), &pool)?;
    assert_eq!(decoded.identity(), evidence.kappa());
    Ok(())
}

#[test]
fn every_proper_prefix_refuses_within_its_own_bound() -> TestResult {
    let bytes = canonical_bytes(&root(Axis::Sha512, 256)?);
    for end in 0..bytes.len() {
        let evidence = VerifiedContent::compute(Axis::Sha256, &bytes[..end])?;
        let cost = decode_cost::<EpochRootData>(end as u64)?;
        let pool = Arc::new(CapacityPool::new("prefix bound", cost.peak));
        assert!(matches!(
            bounded_record::<EpochRootData>(&evidence, &mut meter(&cost), &pool),
            Err(StoreError::Rejected(_))
        ));
        assert_eq!(pool.used(), 0);
    }
    Ok(())
}

#[test]
fn maximal_state_is_257_bytes_and_has_no_retained_heap() -> TestResult {
    let mut map = Map::new();
    map.insert(0u64, 1u64);
    map.insert(1u64, ByteString::from([1; 16]));
    map.insert(2u64, ByteString::from([2; 16]));
    map.insert(3u64, Kappa::compute(Axis::Sha512, b"authority")?);
    map.insert(4u64, ByteString::from([3; 32]));
    map.insert(5u64, ByteString::from([4; 32]));
    map.insert(6u64, u64::MAX);
    let bytes = CBOR::from(map).to_cbor_data();
    assert_eq!(bytes.len() as u64, NamespaceState::MAX_ENCODED_LEN);
    let evidence = VerifiedContent::compute_owned(Axis::Sha256, bytes)?;
    let cost = decode_cost::<NamespaceState>(evidence.len() as u64)?;
    let pool = Arc::new(CapacityPool::new("state bound", cost.peak));
    let decoded = bounded_record::<NamespaceState>(&evidence, &mut meter(&cost), &pool)?;
    assert_eq!(decoded.value().history_size(), u64::MAX);
    assert_eq!(pool.used(), 0);
    assert_eq!(cost.held, 0);
    Ok(())
}

#[test]
fn wrong_axis_refuses_before_work_or_storage() -> TestResult {
    let evidence =
        VerifiedContent::compute_owned(Axis::Blake3, canonical_bytes(&root(Axis::Sha256, 64)?))?;
    let pool = Arc::new(CapacityPool::new("wrong axis", 0));
    let mut work = WorkMeter::new(WorkLimit::unbounded().with(Dimension::Entries, 0));
    assert!(matches!(
        bounded_record::<EpochRootData>(&evidence, &mut work, &pool),
        Err(StoreError::Rejected(_))
    ));
    assert_eq!(*work.used(), Work::default());
    assert_eq!(pool.used(), 0);
    Ok(())
}

#[test]
fn capacity_refusal_releases_storage_but_keeps_consumption() -> TestResult {
    let evidence =
        VerifiedContent::compute_owned(Axis::Sha256, canonical_bytes(&root(Axis::Sha256, 64)?))?;
    let cost = decode_cost::<EpochRootData>(evidence.len() as u64)?;
    let pool = Arc::new(CapacityPool::new("no arena capacity", 0));
    let mut work = meter(&cost);
    assert!(matches!(
        bounded_record::<EpochRootData>(&evidence, &mut work, &pool),
        Err(StoreError::CapacityExceeded(_))
    ));
    assert_eq!(pool.used(), 0);
    assert_eq!(
        work.used().get(Dimension::BytesDecoded),
        evidence.len() as u64
    );
    assert!(work.used().get(Dimension::BytesAllocated) > 0);
    Ok(())
}

#[test]
fn understated_construction_is_a_defect_not_a_retry() -> TestResult {
    struct Understated;
    impl BoundedDecodable for Understated {
        fn construct<A: Allocator>(
            _: dcbor::bounded::decode::Node<'_, '_>,
            _: &mut dcbor::bounded::Owned<A::Permit, A::Permit>,
            allocator: &mut A,
        ) -> dcbor::bounded::decode::ConstructResult<Self, A> {
            allocator
                .traverse(u64::MAX, 0)
                .map_err(dcbor::bounded::BoundedError::Refused)?;
            Ok(Self)
        }
    }
    impl BoundedRecord for Understated {
        const OPTIONS: Options = Options::quick_only(1);
        const AXIS: Axis = Axis::Sha256;
        const FIELDS: &'static [u8] = &[];
        fn construction(_: u64) -> ConstructionBound {
            ConstructionBound {
                values: 0,
                bytes: 0,
                allocated: 0,
                peak: 0,
                held: 0,
                permits: 0,
            }
        }
    }
    let evidence = VerifiedContent::compute(Axis::Sha256, &[0xa0])?;
    let cost = decode_cost::<Understated>(1)?;
    let pool = Arc::new(CapacityPool::new("understated constructor", cost.peak));
    assert!(matches!(
        bounded_record::<Understated>(&evidence, &mut meter(&cost), &pool),
        Err(StoreError::Internal(_))
    ));
    assert_eq!(pool.used(), 0);
    Ok(())
}
