use super::*;
use crate::work::{WorkLimit, WorkMeter};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn borrowed_encodings_preserve_wire_bytes_and_release_capacity() -> TestResult {
    let namespace = NamespaceRef::deterministic("bounded-transformations");
    let anchor = Kappa::sha256(b"anchor");
    let ledger = Kappa::sha256(b"ledger");
    let state = Kappa::sha256(b"state");
    let pool = Arc::new(CapacityPool::new("root transformations", 1 << 20));
    for previous in [None, Some(&ledger)] {
        for rotation in [None, Some(&anchor)] {
            for signature in [0, 23, 24, 255, 256, 3309] {
                let unsigned = EpochRoot::build(EpochRootInput {
                    namespace: &namespace,
                    epoch_number: 2,
                    prev_identifier: previous,
                    state_digest: [1; 32],
                    mutations_root: [2; 32],
                    timestamp: ClockMs::test_value(1000),
                    signer_anchor: &anchor,
                    tag_count: u64::MAX,
                    rotation_kappa: rotation,
                    ledger_root: &ledger,
                    state: &state,
                });
                let expected_unsigned = unsigned.kappa().clone();
                let root =
                    unsigned.with_signature(SignedPayload::from_cose_bytes(vec![7; signature]));
                let mut work = WorkMeter::new(WorkLimit::unbounded());
                let full = root.bounded_bytes(&mut work, &pool)?;
                assert_eq!(full.as_ref(), root.to_bytes());
                let signing = root.bounded_signable_bytes(&mut work, &pool)?;
                assert_eq!(signing.as_ref(), root.signable_bytes());
                assert_eq!(
                    pool.used(),
                    (full.as_ref().len() + signing.as_ref().len()) as u64
                );
                assert_eq!(
                    root.bounded_unsigned_identity(&mut work, &pool)?,
                    expected_unsigned
                );
                let consumed = *work.used();
                drop(full);
                drop(signing);
                assert_eq!(pool.used(), 0);
                assert_eq!(*work.used(), consumed);
            }
        }
    }
    Ok(())
}
