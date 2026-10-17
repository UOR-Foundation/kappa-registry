//! Shared epoch publication policy. Backends supply a locked, coherent view
//! and persist the resulting publication without reimplementing its rules.

use kappa_crypto::epoch_verification::{check_successor, succession_path_identity};
use kappa_types::{
    Kappa, NamespaceRef, StoreError, VerifiedContent,
    axis::Axis,
    canonical::{canonical_bytes, from_canonical},
    clock::ClockMs,
    edge::{BuiltinRelation, EdgeInput, EdgeRelation},
    epoch::EpochMutation,
    epoch_root::{EpochRoot, EpochRootInput, mutations_merkle_root},
};

use crate::epoch_authority::{EpochAuthority, PathEvidence};

#[derive(Clone, Copy)]
pub struct EpochPublicationInput<'a> {
    pub namespace: &'a NamespaceRef,
    pub predecessor: Option<&'a EpochRoot>,
    pub state_root: [u8; 32],
    pub tag_count: u64,
    pub mutations: &'a Vec<EpochMutation>,
    pub now: ClockMs,
    /// Anchor the caller requires the epoch to be signed under. Publication
    /// fails unless it is the store's current authority.
    pub signer_override: Option<&'a Kappa>,
}

/// Complete authenticated publication; fields are private so a backend cannot
/// substitute a ledger, edge, root or rotation evidence after shared
/// validation.
pub struct EpochPublication {
    root: EpochRoot,
    ledger: VerifiedContent,
    root_blob: VerifiedContent,
    edge: EdgeInput,
    edge_blob: VerifiedContent,
    rotation_record: Option<VerifiedContent>,
    retained_links: Vec<(EdgeInput, VerifiedContent)>,
}

impl EpochPublication {
    /// Prepare the next epoch of `input.namespace`, signed by the current
    /// authority of `authority`.
    ///
    /// A predecessor signed by an earlier authority of this store is
    /// followed by an epoch carrying the succession path from that
    /// authority to the current one, however many rotations the namespace
    /// was idle across. The signed root is checked against the same
    /// successor rule replay admits history with before it is returned.
    pub fn prepare(
        input: EpochPublicationInput<'_>,
        authority: &EpochAuthority,
    ) -> Result<Self, StoreError> {
        let signer = authority.current().signer();
        let anchor = authority.anchor();
        if input
            .signer_override
            .is_some_and(|required| required != anchor)
        {
            return Err(StoreError::Conflict(
                "epoch signing key does not match authority".into(),
            ));
        }
        let (epoch_number, evidence) = match input.predecessor {
            Some(previous) => {
                if previous.namespace_id() != input.namespace.id() {
                    return Err(StoreError::Internal(
                        "epoch predecessor crosses namespace identity".into(),
                    ));
                }
                if input.now.as_i64() < previous.timestamp_ms() {
                    return Err(StoreError::Rejected("epoch timestamp regressed".into()));
                }
                verify_epoch_authority(previous, authority)?;
                let path = authority
                    .path_from(previous.signer_anchor())
                    .ok_or_else(|| {
                        StoreError::Conflict(
                            "predecessor signer has no succession path to the current authority"
                                .into(),
                        )
                    })?;
                let number = previous
                    .epoch_number()
                    .checked_add(1)
                    .ok_or_else(|| StoreError::CapacityExceeded("epoch number exhausted".into()))?;
                (number, (!path.is_empty()).then(|| PathEvidence::new(path)))
            }
            None => (1, None),
        };
        let rotation = evidence.as_ref().map(PathEvidence::content);
        let rotation_kappa = rotation.as_deref().map(Kappa::sha256);
        let ledger = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(input.mutations))?;
        let root = EpochRoot::build(EpochRootInput {
            namespace: input.namespace,
            epoch_number,
            prev_identifier: input.predecessor.map(EpochRoot::kappa),
            state_digest: input.state_root,
            mutations_root: mutations_merkle_root(input.mutations),
            timestamp: input.now,
            signer_anchor: anchor,
            tag_count: input.tag_count,
            rotation_kappa: rotation_kappa.as_ref(),
            ledger_root: ledger.kappa(),
        });
        let root = kappa_crypto::signed_types::sign_epoch(root, signer)
            .map_err(|error| StoreError::Internal(format!("epoch signing: {error}")))?;
        match input.predecessor {
            Some(previous) => check_successor(
                previous,
                &root,
                signer.public_key(),
                evidence.as_ref().map(PathEvidence::path),
            )
            .map_err(|error| StoreError::Conflict(format!("epoch succession: {error}")))?,
            None => kappa_crypto::signed_types::verify_epoch(&root, signer.public_key()).map_err(
                |error| StoreError::Internal(format!("epoch signature verification: {error}")),
            )?,
        }
        let rotation_record = rotation
            .map(|content| VerifiedContent::compute(Axis::Sha256, &content))
            .transpose()?;
        let root_blob = VerifiedContent::verify(root.kappa(), &root.to_bytes())?;
        let edge = EdgeInput {
            source: root.kappa().clone(),
            target: ledger.kappa().clone(),
            relation: EdgeRelation::Builtin(BuiltinRelation::EpochRoot),
            asserter: anchor.clone(),
            created_at_ms: input.now.as_i64(),
            metadata: None,
        };
        let edge_blob = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(&edge))?;
        let retained_links = build_retained_links(
            &root,
            anchor,
            input.now,
            input.predecessor,
            rotation_record.as_ref(),
            input.mutations,
        )?;
        Ok(Self {
            root,
            ledger,
            root_blob,
            edge,
            edge_blob,
            rotation_record,
            retained_links,
        })
    }

    pub const fn root(&self) -> &EpochRoot {
        &self.root
    }
    pub const fn ledger(&self) -> &VerifiedContent {
        &self.ledger
    }
    pub const fn root_blob(&self) -> &VerifiedContent {
        &self.root_blob
    }
    pub const fn edge(&self) -> &EdgeInput {
        &self.edge
    }
    pub const fn edge_blob(&self) -> &VerifiedContent {
        &self.edge_blob
    }
    /// The succession path content `root().rotation_kappa()` names. A
    /// backend publishes it with the root so replay can retrieve it.
    pub const fn rotation_record(&self) -> Option<&VerifiedContent> {
        self.rotation_record.as_ref()
    }
    pub fn into_root(self) -> EpochRoot {
        self.root
    }

    pub fn retained_links(&self) -> &[(EdgeInput, VerifiedContent)] {
        &self.retained_links
    }
}

/// Build the set of edges from the epoch root to each retained target: the
/// predecessor, any rotation evidence, and each mutation whose record
/// replay derives state from (operations, namespace updates, sequences,
/// metadata, edges, content commitments, aliases and compositions).
/// History retains the evidence it names: a content commitment
/// authenticates range reads of its content for as long as the epoch that
/// published it exists, and a composition the binding its components are
/// retained under. A published record (`RecordPublish`) is content, not
/// evidence replay reads: it is retained by what names it (a tag, the
/// head, a retaining edge) and is otherwise retirable.
fn build_retained_links(
    root: &EpochRoot,
    anchor: &Kappa,
    now: ClockMs,
    predecessor: Option<&EpochRoot>,
    rotation_record: Option<&VerifiedContent>,
    mutations: &[EpochMutation],
) -> Result<Vec<(EdgeInput, VerifiedContent)>, StoreError> {
    let mut links = Vec::new();
    for target in predecessor
        .map(EpochRoot::kappa)
        .into_iter()
        .chain(rotation_record.map(VerifiedContent::kappa))
        .chain(
            mutations
                .iter()
                .filter(|mutation| {
                    matches!(
                        mutation.op,
                        kappa_types::MutationOp::OperationPublish
                            | kappa_types::MutationOp::NamespaceUpdate
                            | kappa_types::MutationOp::SequenceUpdate
                            | kappa_types::MutationOp::MetadataUpdate
                            | kappa_types::MutationOp::EdgePut
                            | kappa_types::MutationOp::EdgeDelete
                            | kappa_types::MutationOp::ContentPublish
                            | kappa_types::MutationOp::ContentAlias
                            | kappa_types::MutationOp::ContentCompose
                    )
                    // A retirement names content the epoch must not retain.
                })
                .map(|mutation| &mutation.kappa),
        )
    {
        let edge = EdgeInput {
            source: root.kappa().clone(),
            target: target.clone(),
            relation: EdgeRelation::Builtin(BuiltinRelation::EpochRoot),
            asserter: anchor.clone(),
            created_at_ms: now.as_i64(),
            metadata: None,
        };
        let content = VerifiedContent::compute(Axis::Sha256, &canonical_bytes(&edge))?;
        links.push((edge, content));
    }
    Ok(links)
}

/// Admit persisted epoch evidence before it can drive recovery or publication.
///
/// A content-addressed root alone does not establish authority or correspondence
/// between the signed mutation commitment and the persisted ledger.
pub fn verify_persisted_epoch(
    root: &EpochRoot,
    authority: &EpochAuthority,
    ledger_bytes: &[u8],
) -> Result<(), StoreError> {
    verify_epoch_authority(root, authority)?;
    VerifiedContent::verify(root.ledger_root(), ledger_bytes)?;
    let mutations: Vec<EpochMutation> = from_canonical(ledger_bytes)?;
    if mutations_merkle_root(&mutations).as_slice() != root.mutations_root() {
        return Err(StoreError::Rejected(
            "epoch mutation commitment does not match persisted ledger".into(),
        ));
    }
    Ok(())
}

/// Correspondence of a persisted root to ledger digests its caller computed:
/// `ledger` must equal the root's ledger identity and `mutations_root` its
/// signed mutation commitment.
///
/// This compares the supplied values with the root's and nothing else. It
/// does not establish that they were computed from the persisted ledger,
/// and it does not admit the root's authority. A caller reading a ledger
/// incrementally owns the remaining checks, each separately required:
/// every persisted ledger byte, in order, hashed on the axis of
/// `root.ledger_root()` into `ledger`; every element decoded as a canonical
/// `EpochMutation`, with nothing after the last; the `canonical_bytes` of
/// each decoded mutation folded, in ledger order, into the `merkle_root`
/// tree that yields `mutations_root`; and `verify_epoch_authority` on the
/// root. `verify_persisted_epoch` performs all of it over complete ledger
/// bytes.
pub fn check_ledger_digests(
    root: &EpochRoot,
    ledger: &Kappa,
    mutations_root: &[u8; 32],
) -> Result<(), StoreError> {
    if ledger != root.ledger_root() {
        return Err(StoreError::Rejected(format!(
            "persisted ledger hashes to {ledger}, the epoch commits {}",
            root.ledger_root()
        )));
    }
    if mutations_root.as_slice() != root.mutations_root() {
        return Err(StoreError::Rejected(
            "epoch mutation commitment does not match persisted ledger".into(),
        ));
    }
    Ok(())
}

/// Admission of one persisted root against the store's authority history.
///
/// Its signer must be an authority of this store whose window contains the
/// root's timestamp, any rotation evidence it names must be a path of this
/// store's own transitions ending at that signer, and its signature must
/// verify under that authority's key. It says nothing about the root's
/// ledger (`check_ledger_digests`, `verify_persisted_epoch`).
///
/// Position in a namespace's chain (which predecessor, which path) is
/// enforced when an epoch is published and re-established by authenticated
/// replay; both apply `check_successor`.
pub fn verify_epoch_authority(
    root: &EpochRoot,
    authority: &EpochAuthority,
) -> Result<(), StoreError> {
    if root.epoch_number() == 0 || (root.epoch_number() == 1) != root.prev_identifier().is_none() {
        return Err(StoreError::Rejected(
            "invalid epoch predecessor structure".into(),
        ));
    }
    let key = authority
        .verification_key(root.signer_anchor(), root.timestamp_ms())
        .ok_or_else(|| {
            StoreError::Rejected(
                "persisted epoch signer is not an authority of this store at its timestamp".into(),
            )
        })?;
    if let Some(reference) = root.rotation_kappa() {
        let transitions = authority.transitions();
        let end = transitions
            .iter()
            .position(|transition| transition.incoming().anchor() == root.signer_anchor())
            .ok_or_else(|| {
                StoreError::Rejected("rotation evidence names no transition of this store".into())
            })?;
        let named = (0..=end).any(|start| {
            let links: Vec<_> = transitions[start..=end]
                .iter()
                .map(|transition| transition.succession().clone())
                .collect();
            &succession_path_identity(&links) == reference
        });
        if !named {
            return Err(StoreError::Rejected(
                "rotation evidence is not a path of this store's transitions".into(),
            ));
        }
    }
    kappa_crypto::signed_types::verify_epoch(root, key.public_key())
        .map_err(|error| StoreError::Rejected(format!("persisted epoch signature: {error}")))
}
