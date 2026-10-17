use super::*;

fn proposal(generation: u64) -> Proposal {
    Proposal {
        namespace: [1; 16],
        plane: ControlPlaneId::LOCAL,
        predecessor: None,
        epoch_number: 1,
        root: Kappa::sha256(b"root"),
        generation,
        assignment_generation: 0,
        dependencies: Vec::new(),
        timestamp_ms: 1,
    }
}

fn local_assignment() -> AssignmentRecord {
    AssignmentRecord {
        namespace_id: vec![1; 16],
        plane: ControlPlaneId::LOCAL.0.to_vec(),
        generation: 0,
        requires: Guarantees::NONE.with(Guarantee::TotalOrder),
    }
}

#[test]
fn an_unassigned_namespace_is_refused_every_plane() {
    let planes = ControlPlanes::new(NodeId("node".into()));
    assert!(matches!(
        planes.plane_for(None),
        Err(StoreError::Rejected(_))
    ));
}

#[test]
fn the_local_plane_decides_in_writer_order_and_fences_stale_generations() -> Result<(), StoreError>
{
    let planes = ControlPlanes::new(NodeId("node".into()));
    let plane = planes.plane_for(Some(&local_assignment()))?;
    assert_eq!(
        plane.decide(&proposal(0)),
        Decision::Decided {
            position: 1,
            generation: 0
        }
    );
    plane.reconfigure(Membership {
        generation: 3,
        nodes: vec![NodeId("node".into())],
    })?;
    assert!(matches!(plane.decide(&proposal(0)), Decision::Rejected(_)));
    assert!(
        plane
            .reconfigure(Membership::single(NodeId("node".into())))
            .is_err()
    );
    Ok(())
}

/// The local plane declares the fencing its `decide` enforces, so an
/// assignment requiring it is admitted; replication it cannot provide is
/// still refused.
#[test]
fn the_local_plane_declares_the_fencing_it_enforces() -> Result<(), StoreError> {
    let planes = ControlPlanes::new(NodeId("node".into()));
    let fenced = AssignmentRecord {
        requires: Guarantees::NONE
            .with(Guarantee::TotalOrder)
            .with(Guarantee::Fenced)
            .with(Guarantee::LinearizableReads),
        ..local_assignment()
    };
    let plane = planes.plane_for(Some(&fenced))?;
    assert!(plane.agreement.guarantees().provides(Guarantee::Fenced));
    plane.reconfigure(Membership {
        generation: 1,
        nodes: vec![NodeId("node".into())],
    })?;
    assert!(
        matches!(plane.decide(&proposal(0)), Decision::Rejected(_)),
        "control: a proposal of the previous generation is fenced"
    );
    Ok(())
}

#[test]
fn an_assignment_requiring_replication_is_refused_by_the_local_plane() {
    let planes = ControlPlanes::new(NodeId("node".into()));
    let assignment = AssignmentRecord {
        namespace_id: vec![1; 16],
        plane: vec![0; 16],
        generation: 1,
        requires: Guarantees::NONE
            .with(Guarantee::TotalOrder)
            .with(Guarantee::Replicated),
    };
    assert!(matches!(
        planes.plane_for(Some(&assignment)),
        Err(StoreError::Rejected(_))
    ));
    let unknown = AssignmentRecord {
        plane: vec![9; 16],
        requires: Guarantees::NONE.with(Guarantee::TotalOrder),
        ..assignment
    };
    assert!(matches!(
        planes.plane_for(Some(&unknown)),
        Err(StoreError::NotSupported(_))
    ));
}

#[test]
fn a_lease_plane_decides_only_for_the_lease_holder() {
    let node = NodeId("holder".into());
    let plane = ControlPlane::new(
        ControlPlaneId([3; 16]),
        Membership::single(node.clone()),
        Arc::new(LeaseAgreement::new(
            Arc::new(kappa_types::coordinator::SingleNodeCoordinator),
            node,
            true,
        )),
        Arc::new(NoConflicts),
        ProtocolBinding::Named("test".into()),
    );
    let mut candidate = proposal(0);
    candidate.plane = plane.id;
    assert_eq!(
        plane.decide(&candidate),
        Decision::Decided {
            position: 1,
            generation: 0
        }
    );
    let outsider = ControlPlane::new(
        ControlPlaneId([4; 16]),
        Membership::single(NodeId("other".into())),
        Arc::new(LeaseAgreement::new(
            Arc::new(kappa_types::coordinator::SingleNodeCoordinator),
            NodeId("holder".into()),
            true,
        )),
        Arc::new(NoConflicts),
        ProtocolBinding::Named("test".into()),
    );
    assert!(matches!(outsider.decide(&candidate), Decision::Rejected(_)));
}

#[test]
fn latest_writer_wins_is_deterministic_across_members() {
    let mut a = proposal(0);
    a.timestamp_ms = 5;
    a.root = Kappa::sha256(b"a");
    let mut b = proposal(0);
    b.timestamp_ms = 5;
    b.root = Kappa::sha256(b"b");
    let conflict = Conflict {
        namespace: [1; 16],
        predecessor: None,
        candidates: vec![a.clone(), b.clone()],
    };
    let reversed = Conflict {
        candidates: vec![b, a],
        ..conflict.clone()
    };
    let first = LatestWriterWins.resolve(&conflict);
    let second = LatestWriterWins.resolve(&reversed);
    let Resolution::Accept(i) = first else {
        panic!("no winner");
    };
    let Resolution::Accept(j) = second else {
        panic!("no winner");
    };
    assert_eq!(conflict.candidates[i].root, reversed.candidates[j].root);
    assert!(matches!(
        NoConflicts.resolve(&conflict),
        Resolution::RejectAll(_)
    ));
}

/// A guarantee set roundtrips through its canonical encoding inside the
/// record, and a record naming a bit no guarantee defines is refused
/// rather than read as requiring less.
#[test]
fn assignment_records_roundtrip_and_refuse_undefined_guarantees() -> Result<(), StoreError> {
    let record = AssignmentRecord {
        namespace_id: vec![1; 16],
        plane: vec![0; 16],
        generation: 2,
        requires: Guarantees::NONE
            .with(Guarantee::Fenced)
            .with(Guarantee::LinearizableReads),
    };
    let bytes = kappa_store::canonical::canonical_bytes(&record);
    let decoded: AssignmentRecord = kappa_store::canonical::from_canonical(&bytes)?;
    assert_eq!(decoded, record);
    assert!(decoded.requires.provides(Guarantee::Fenced));
    assert!(!decoded.requires.provides(Guarantee::TotalOrder));
    let mut map = dcbor::Map::new();
    map.insert(0u64, dcbor::ByteString::from(vec![1u8; 16]));
    map.insert(1u64, dcbor::ByteString::from(vec![0u8; 16]));
    map.insert(2u64, 2u64);
    map.insert(3u64, 0b1_0000u64);
    let undefined = kappa_store::canonical::canonical_bytes(&dcbor::CBOR::from(map));
    assert!(kappa_store::canonical::from_canonical::<AssignmentRecord>(&undefined).is_err());
    assert_eq!(Guarantees::from_bits(0b1_0000), None);
    assert!(
        Guarantees::NONE
            .with(Guarantee::TotalOrder)
            .satisfies(Guarantees::NONE)
    );
    assert!(!Guarantees::NONE.satisfies(Guarantees::NONE.with(Guarantee::Replicated)));
    Ok(())
}

#[test]
fn assignment_entries_roundtrip() -> Result<(), StoreError> {
    let encoded = encode_assignment(ControlPlaneId([7; 16]), 42);
    assert_eq!(decode_assignment(&encoded)?, (ControlPlaneId([7; 16]), 42));
    assert!(decode_assignment(&encoded[..23]).is_err());
    Ok(())
}
