use std::collections::{BTreeMap, BTreeSet};

use kappa_types::canonical::from_canonical;
use kappa_types::epoch::{EpochMutation, MutationOp};
use kappa_types::epoch_root::mutations_merkle_root;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::namespace::NamespaceRef;
use kappa_types::verified::VerifiedContent;

use crate::identity_ops::AnchorKeyResolver;
use crate::traits::blob::BlobStore;
use crate::traits::epoch::EpochStore;

/// Reconstructed namespace state from epoch chain replay.
///
/// Tags keyed by name. The `BTreeMap` provides sorted iteration
/// for comparison against live state.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamespaceState {
    pub tags: BTreeMap<String, Kappa>,
    pub namespace_record: Option<Kappa>,
    pub sequences: BTreeMap<String, u64>,
    /// Namespace metadata reconstructed from `MetadataUpdate` evidence.
    pub metadata: BTreeMap<String, Vec<u8>>,
    pub edges: BTreeSet<Kappa>,
    pub operations: BTreeMap<[u8; 32], Kappa>,
    /// Chunk framing committed for content identities, keyed by the
    /// content identity. One commitment per identity: the framing is a
    /// function of the bytes, so a second differing commitment is evidence
    /// of inconsistency and a second equal one of a duplicate publication.
    pub commitments: BTreeMap<Kappa, kappa_types::ContentCommitment>,
    /// Digest aliases bound in this namespace's history: alias identity to
    /// (target identity, common length). Content shared across namespaces
    /// is installed again by each namespace that publishes it, so an equal
    /// binding may recur; a differing one is evidence of inconsistency.
    pub aliases: BTreeMap<Kappa, (Kappa, u64)>,
    /// Compositions installed in this namespace's history: composite
    /// identity to every component list recorded for it. Two chunkings of
    /// the same bytes are both true of them, so distinct lists accumulate;
    /// an equal one recurring is a reinstallation and changes nothing.
    pub compositions: BTreeMap<Kappa, BTreeSet<Vec<(Kappa, u64)>>>,
    /// Identities admitted as records (`RecordPublish`, and every other
    /// record-naming mutation whose evidence was accepted) rather than
    /// through a content commitment: retirement of such an identity is
    /// admitted when a record-naming mutation preceded it.
    pub retired_inline: BTreeSet<Kappa>,
}

impl NamespaceState {
    /// Apply a single mutation to the reconstructed state.
    ///
    /// TagSet/TagDelete use the context field as the tag name.
    /// Missing tag identity is rejected rather than inventing a different key.
    pub fn apply(&mut self, mutation: &EpochMutation) -> Result<(), StoreError> {
        match mutation.op {
            MutationOp::TagSet => {
                let name = mutation
                    .context
                    .as_deref()
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| StoreError::Rejected("TagSet lacks tag identity".into()))?;
                self.tags.insert(name.to_string(), mutation.kappa.clone());
            }
            MutationOp::TagDelete => {
                let name = mutation
                    .context
                    .as_deref()
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| StoreError::Rejected("TagDelete lacks tag identity".into()))?;
                if self.tags.get(name) != Some(&mutation.kappa) {
                    return Err(StoreError::Rejected(
                        "TagDelete does not match reconstructed state".into(),
                    ));
                }
                self.tags.remove(name);
            }
            MutationOp::AssertionPublish
            | MutationOp::RevocationPublish
            | MutationOp::AnchorOrigin => {
                // Non-tag mutations do not affect the tag state.
                // They are recorded for audit trail completeness.
            }
            MutationOp::RecordPublish => {
                // The record is content the namespace admitted, named by
                // its identity; no state derives from its bytes, which a
                // later retirement may have released. The signed ledger is
                // the evidence of the admission.
                if mutation.context.is_some() {
                    return Err(StoreError::Rejected(
                        "record publication carries a context".into(),
                    ));
                }
                self.retired_inline.insert(mutation.kappa.clone());
            }
            MutationOp::ContentRetire => {
                if mutation.context.is_some() {
                    return Err(StoreError::Rejected(
                        "content retirement carries a context".into(),
                    ));
                }
                // The namespace no longer selects a representation for the
                // identity: its commitment, alias binding and compositions
                // are no longer live. A retirement of an identity this
                // history never admitted is evidence of inconsistency.
                let committed = self.commitments.remove(&mutation.kappa).is_some();
                let aliased = self.aliases.remove(&mutation.kappa).is_some();
                let composed = self.compositions.remove(&mutation.kappa).is_some();
                if !(committed
                    || aliased
                    || composed
                    || self.retired_inline.remove(&mutation.kappa))
                {
                    return Err(StoreError::Rejected(format!(
                        "content {} retired without a preceding admission",
                        mutation.kappa
                    )));
                }
            }
            _ => return Err(StoreError::Rejected("unsupported replay mutation".into())),
        }
        Ok(())
    }

    /// Admit content-addressed record evidence before changing reconstructed state.
    pub fn apply_record(
        &mut self,
        ns: &NamespaceRef,
        mutation: &EpochMutation,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        VerifiedContent::verify(&mutation.kappa, bytes)?;
        self.apply_evidence(ns, mutation, bytes)?;
        // Every admitted record-naming mutation admits the record's
        // identity as content of the namespace, which a later retirement
        // may name. Rejected evidence admits nothing.
        self.retired_inline.insert(mutation.kappa.clone());
        Ok(())
    }

    /// The state change the verified record `bytes` of `mutation` makes.
    fn apply_evidence(
        &mut self,
        ns: &NamespaceRef,
        mutation: &EpochMutation,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        match mutation.op {
            MutationOp::EdgePut | MutationOp::EdgeDelete => self.apply_edge(mutation, bytes),
            MutationOp::OperationPublish => self.apply_operation(ns, mutation, bytes),
            MutationOp::ContentPublish => self.apply_commitment(mutation, bytes),
            MutationOp::ContentAlias => self.apply_alias(mutation, bytes),
            MutationOp::ContentCompose => self.apply_composition(mutation, bytes),
            MutationOp::NamespaceUpdate => {
                let record: crate::NamespaceInfo = from_canonical(bytes)?;
                if record.ns.id() != ns.id() || mutation.context.is_some() {
                    return Err(StoreError::Rejected(
                        "invalid namespace mutation evidence".into(),
                    ));
                }
                self.namespace_record = Some(mutation.kappa.clone());
                Ok(())
            }
            MutationOp::SequenceUpdate => self.apply_sequence(ns, mutation, bytes),
            MutationOp::MetadataUpdate => self.apply_metadata(ns, mutation, bytes),
            _ => Err(StoreError::Rejected("unsupported record mutation".into())),
        }
    }

    fn apply_edge(&mut self, mutation: &EpochMutation, bytes: &[u8]) -> Result<(), StoreError> {
        let record: kappa_types::EdgeInput = from_canonical(bytes)?;
        if mutation.context.as_deref() != Some(record.relation.to_string().as_str()) {
            return Err(StoreError::Rejected(
                "edge mutation relation mismatch".into(),
            ));
        }
        if mutation.op == MutationOp::EdgePut {
            if !self.edges.insert(mutation.kappa.clone()) {
                return Err(StoreError::Rejected("duplicate edge publication".into()));
            }
        } else if !self.edges.remove(&mutation.kappa) {
            return Err(StoreError::Rejected(
                "edge deletion lacks preceding publication".into(),
            ));
        }
        Ok(())
    }

    fn apply_operation(
        &mut self,
        ns: &NamespaceRef,
        mutation: &EpochMutation,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let receipt: kappa_types::OperationReceipt = from_canonical(bytes)?;
        receipt.validate()?;
        if receipt.namespace_id() != ns.id().as_slice() || mutation.context.is_some() {
            return Err(StoreError::Rejected(
                "invalid replay operation receipt".into(),
            ));
        }
        let identity = receipt.operation_id()?;
        if self.operations.contains_key(identity) {
            return Err(StoreError::Rejected(
                "operation published more than once".into(),
            ));
        }
        self.operations.insert(*identity, mutation.kappa.clone());
        Ok(())
    }

    fn apply_commitment(
        &mut self,
        mutation: &EpochMutation,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        // Decoding is strict: a malformed commitment never decodes.
        let record: kappa_types::ContentCommitment = from_canonical(bytes)?;
        if mutation.context.is_some() {
            return Err(StoreError::Rejected(
                "content commitment carries a context".into(),
            ));
        }
        if self.commitments.contains_key(record.identity()) {
            return Err(StoreError::Rejected(format!(
                "content {} committed more than once",
                record.identity()
            )));
        }
        self.commitments.insert(record.identity().clone(), record);
        Ok(())
    }

    fn apply_alias(&mut self, mutation: &EpochMutation, bytes: &[u8]) -> Result<(), StoreError> {
        // Decoding is strict: an alias on its own axis never decodes.
        let record: kappa_types::content::ContentAlias = from_canonical(bytes)?;
        if mutation.context.is_some() {
            return Err(StoreError::Rejected(
                "content alias carries a context".into(),
            ));
        }
        let binding = (record.target().clone(), record.length());
        match self.aliases.get(record.alias()) {
            Some(existing) if existing != &binding => Err(StoreError::Rejected(format!(
                "content alias {} rebound to another target",
                record.alias()
            ))),
            Some(_) => Ok(()),
            None => {
                self.aliases.insert(record.alias().clone(), binding);
                Ok(())
            }
        }
    }

    fn apply_composition(
        &mut self,
        mutation: &EpochMutation,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        // Decoding is strict: an empty, self-naming or mis-summed
        // composition never decodes.
        let record: kappa_types::content::ContentComposition = from_canonical(bytes)?;
        if mutation.context.is_some() {
            return Err(StoreError::Rejected(
                "content composition carries a context".into(),
            ));
        }
        let components = record
            .components()
            .iter()
            .map(|component| (component.identity.clone(), component.length))
            .collect();
        self.compositions
            .entry(record.identity().clone())
            .or_default()
            .insert(components);
        Ok(())
    }

    fn apply_sequence(
        &mut self,
        ns: &NamespaceRef,
        mutation: &EpochMutation,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let record: kappa_types::epoch::SequenceRecord = from_canonical(bytes)?;
        let previous = self.sequences.get(&record.name).copied().unwrap_or(0);
        if record.namespace_id != ns.id().as_slice()
            || record.name.is_empty()
            || mutation.context.as_deref() != Some(record.name.as_str())
            || previous.checked_add(1) != Some(record.value)
        {
            return Err(StoreError::Rejected(
                "invalid sequence mutation evidence".into(),
            ));
        }
        self.sequences.insert(record.name, record.value);
        Ok(())
    }

    fn apply_metadata(
        &mut self,
        ns: &NamespaceRef,
        mutation: &EpochMutation,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let record: kappa_types::epoch::MetadataRecord = from_canonical(bytes)?;
        if record.namespace_id != ns.id().as_slice()
            || record.key.is_empty()
            || mutation.context.as_deref() != Some(record.key.as_str())
        {
            return Err(StoreError::Rejected(
                "invalid metadata mutation evidence".into(),
            ));
        }
        match record.value {
            Some(value) => {
                self.metadata.insert(record.key, value);
            }
            None => {
                self.metadata.remove(&record.key);
            }
        }
        Ok(())
    }
}

/// Replay the epoch chain, reconstructing namespace state.
///
/// Walks numbered history from genesis to the captured head and reconstructs state through
/// `target_epoch`. Epoch zero denotes the empty state before genesis.
/// Verifies content identities, ledger commitments, chain continuity, mutation
/// roots, and reconstructed state commitments. This structural verification
/// does not establish signer authority; authenticated admission is separate.
///
/// Aborts on: corrupt mutation blob, `mutations_root` mismatch,
/// missing history, discontinuous linkage, or reconstructed state mismatch.
pub fn replay_to<S>(
    store: &S,
    ns: &NamespaceRef,
    target_epoch: u64,
) -> Result<NamespaceState, StoreError>
where
    S: EpochStore + BlobStore + ?Sized,
{
    replay_with_admission(store, ns, target_epoch, |_| Ok(()))
}

/// Reconstruct history admitted from an externally pinned genesis authority.
///
/// Anchors are digests of `(algorithm, public key)`, so they do not carry
/// key material. `key_resolver` supplies the key for each signer anchor the
/// walk meets: the pinned genesis, every epoch signer, and the outgoing
/// anchor of every link of every succession path. A supplied key is bound
/// to its anchor before use, so a resolver can withhold authority but never
/// substitute it. A signer change is admitted only through the succession
/// path its epoch references, retrieved by that signed content identity
/// and checked link by link through `VerifiedEpoch`; a historical key is
/// accepted only at the positions this walk proves it authorized.
pub fn replay_authenticated<S>(
    store: &S,
    ns: &NamespaceRef,
    target_epoch: u64,
    trusted_genesis: &Kappa,
    key_resolver: &AnchorKeyResolver<'_>,
) -> Result<NamespaceState, StoreError>
where
    S: EpochStore + BlobStore + ?Sized,
{
    let bound_key = |anchor: &Kappa| -> Result<(String, Vec<u8>), StoreError> {
        let (algorithm, key) = key_resolver(anchor).ok_or_else(|| {
            StoreError::Rejected(format!(
                "epoch admission: no key material for signer {anchor}"
            ))
        })?;
        if Kappa::from_key(&algorithm, &key)? != *anchor {
            return Err(StoreError::Rejected(format!(
                "epoch admission: key material does not match signer {anchor}"
            )));
        }
        Ok((algorithm, key))
    };
    let public_key = |anchor: &Kappa| bound_key(anchor).map(|(_, key)| key);
    let mut predecessor: Option<kappa_crypto::epoch_verification::VerifiedEpoch> = None;
    replay_with_admission(store, ns, target_epoch, |root| {
        let admitted = match predecessor.as_ref() {
            None => {
                let genesis_key = public_key(trusted_genesis)?;
                kappa_crypto::epoch_verification::VerifiedEpoch::admit_genesis(
                    root.clone(),
                    ns,
                    trusted_genesis,
                    &genesis_key,
                )
            }
            Some(previous) => {
                let links = root
                    .rotation_kappa()
                    .map(|identity| {
                        let bytes = store.blob_get_in(ns, identity)?;
                        VerifiedContent::verify(identity, &bytes)?;
                        from_canonical::<Vec<kappa_types::Succession>>(&bytes).map_err(|error| {
                            StoreError::Rejected(format!("succession path decode: {error}"))
                        })
                    })
                    .transpose()?;
                let signer_key = public_key(root.signer_anchor())?;
                let outgoing_keys = links
                    .iter()
                    .flatten()
                    .map(|link| bound_key(&link.old_anchor))
                    .collect::<Result<Vec<_>, _>>()?;
                let outgoing: Vec<(&str, &[u8])> = outgoing_keys
                    .iter()
                    .map(|(algorithm, key)| (algorithm.as_str(), key.as_slice()))
                    .collect();
                previous.admit_successor(
                    root.clone(),
                    &signer_key,
                    links.as_deref().map(|links| {
                        kappa_crypto::epoch_verification::SuccessionPath {
                            links,
                            outgoing: &outgoing,
                        }
                    }),
                )
            }
        }
        .map_err(|error| StoreError::Rejected(format!("epoch admission: {error}")))?;
        predecessor = Some(admitted);
        Ok(())
    })
}

fn replay_with_admission<S>(
    store: &S,
    ns: &NamespaceRef,
    target_epoch: u64,
    mut admit: impl FnMut(&kappa_types::EpochRoot) -> Result<(), StoreError>,
) -> Result<NamespaceState, StoreError>
where
    S: EpochStore + BlobStore + ?Sized,
{
    let (current_num, current_kappa) = store.epoch_current(ns)?;

    if target_epoch > current_num {
        return Err(StoreError::NotFound(format!(
            "target epoch {target_epoch} > current epoch {current_num}",
        )));
    }

    if current_num == 0 {
        return Ok(NamespaceState::default());
    }

    // Admit one ledger at a time. Historical mutation populations must not
    // accumulate in memory alongside the reconstructed state.
    let mut state = NamespaceState::default();
    let mut predecessor = None;
    let mut predecessor_timestamp = None;
    for expected_number in 1..=current_num {
        let walk_kappa = store.epoch_get_by_number(ns, expected_number)?;
        let root = store.epoch_get(&walk_kappa)?;
        if root.epoch_number() != expected_number || root.prev_identifier() != predecessor.as_ref()
        {
            return Err(StoreError::Rejected(
                "discontinuous replay epoch chain".into(),
            ));
        }
        if predecessor_timestamp.is_some_and(|timestamp| root.timestamp_ms() < timestamp) {
            return Err(StoreError::Rejected(
                "replay epoch timestamp regressed".into(),
            ));
        }
        predecessor_timestamp = Some(root.timestamp_ms());

        // Adjacency is not evidence of ledger identity. The epoch's signed
        // commitment names the exact bytes to retrieve and verify.
        if root.namespace_id() != ns.id() || root.kappa() != &walk_kappa {
            return Err(StoreError::Rejected(
                "replay epoch identity mismatch".into(),
            ));
        }
        if expected_number == current_num && walk_kappa != current_kappa {
            return Err(StoreError::Rejected(
                "replay history differs from captured head".into(),
            ));
        }
        // Every record of the history is the namespace's own: read from
        // it, current with its commit, never through a projection.
        let mutation_blob = store.blob_get_in(ns, root.ledger_root())?;
        VerifiedContent::verify(root.ledger_root(), &mutation_blob)?;
        let mutations: Vec<EpochMutation> = from_canonical(&mutation_blob).map_err(|e| {
            StoreError::Internal(format!(
                "epoch {} mutation blob decode: {e}",
                root.epoch_number(),
            ))
        })?;

        // Verify mutations_root. Abort on mismatch. Never skip.
        let computed_root = mutations_merkle_root(&mutations);
        let stored_root = root.mutations_root();
        if computed_root != stored_root {
            return Err(StoreError::Rejected(format!(
                "epoch {} mutations_root mismatch",
                root.epoch_number(),
            )));
        }

        admit(&root)?;
        predecessor = Some(walk_kappa);
        if root.epoch_number() > target_epoch {
            continue;
        }
        for mutation in &mutations {
            if matches!(
                mutation.op,
                MutationOp::NamespaceUpdate
                    | MutationOp::SequenceUpdate
                    | MutationOp::MetadataUpdate
                    | MutationOp::EdgePut
                    | MutationOp::EdgeDelete
                    | MutationOp::OperationPublish
                    | MutationOp::ContentPublish
                    | MutationOp::ContentAlias
                    | MutationOp::ContentCompose
            ) {
                let bytes = store.blob_get_in(ns, &mutation.kappa)?;
                state.apply_record(ns, mutation, &bytes)?;
                continue;
            }
            state.apply(mutation)?;
        }
        let mut digest = kappa_types::StateDigest::default();
        for (name, identity) in &state.tags {
            digest.insert(name, identity);
        }
        if digest.into_bytes().as_slice() != root.state_digest()
            || state.tags.len() as u64 != root.tag_count()
        {
            return Err(StoreError::Rejected(
                "reconstructed epoch state commitment mismatch".into(),
            ));
        }
    }

    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mutation(op: MutationOp, name: Option<&str>, content: &[u8]) -> EpochMutation {
        EpochMutation {
            op,
            kappa: Kappa::sha256(content),
            timestamp_ms: 1,
            context: name.map(str::to_owned),
        }
    }

    #[test]
    fn edge_replay_requires_evidence_and_a_preceding_publication() -> Result<(), StoreError> {
        let ns = NamespaceRef::deterministic("replayed-edges");
        let input = kappa_types::EdgeInput {
            source: Kappa::sha256(b"source"),
            target: Kappa::sha256(b"target"),
            relation: kappa_types::EdgeRelation::Builtin(kappa_types::BuiltinRelation::Owns),
            asserter: Kappa::sha256(b"authority"),
            created_at_ms: 1,
            metadata: None,
        };
        let bytes = kappa_types::canonical::canonical_bytes(&input);
        let relation = input.relation.to_string();
        let put = mutation(MutationOp::EdgePut, Some(&relation), &bytes);
        let delete = mutation(MutationOp::EdgeDelete, Some(&relation), &bytes);
        let mut state = NamespaceState::default();
        assert!(state.apply(&put).is_err());
        assert!(state.apply_record(&ns, &delete, &bytes).is_err());
        assert!(state.edges.is_empty());
        state.apply_record(&ns, &put, &bytes)?;
        let before = state.clone();
        assert!(state.apply_record(&ns, &put, &bytes).is_err());
        assert_eq!(state, before);
        let mut malformed = delete.clone();
        malformed.context = Some("different-relation".into());
        assert!(state.apply_record(&ns, &malformed, &bytes).is_err());
        assert_eq!(state, before);
        state.apply_record(&ns, &delete, &bytes)?;
        assert!(state.edges.is_empty());
        Ok(())
    }

    #[test]
    fn operation_replay_rejects_duplicate_publication() -> Result<(), StoreError> {
        let ns = NamespaceRef::deterministic("replayed-operation");
        let receipt = kappa_types::OperationReceipt::new(
            &ns,
            &[23; 32],
            Kappa::sha256(b"request"),
            b"result".to_vec(),
        )?;
        let bytes = kappa_types::canonical::canonical_bytes(&receipt);
        let publication = mutation(MutationOp::OperationPublish, None, &bytes);
        let mut state = NamespaceState::default();
        state.apply_record(&ns, &publication, &bytes)?;
        let before = state.clone();
        assert!(state.apply_record(&ns, &publication, &bytes).is_err());
        assert_eq!(state, before);
        assert_eq!(state.operations.get(&[23; 32]), Some(&publication.kappa));
        Ok(())
    }

    #[test]
    fn content_commitment_is_admitted_once_without_context() -> Result<(), StoreError> {
        let ns = NamespaceRef::deterministic("replayed-content");
        let identity = Kappa::sha256(b"large content");
        let commitment = kappa_types::ContentCommitment::new(identity.clone(), 65536, [3; 32])?;
        let bytes = kappa_types::canonical::canonical_bytes(&commitment);
        let publication = mutation(MutationOp::ContentPublish, None, &bytes);
        let mut state = NamespaceState::default();
        state.apply_record(&ns, &publication, &bytes)?;
        assert_eq!(state.commitments.get(&identity), Some(&commitment));
        let before = state.clone();
        assert!(state.apply_record(&ns, &publication, &bytes).is_err());
        let with_context = mutation(MutationOp::ContentPublish, Some("x"), &bytes);
        assert!(state.apply_record(&ns, &with_context, &bytes).is_err());
        assert_eq!(state, before);
        Ok(())
    }

    #[test]
    fn content_alias_recurs_equal_and_rejects_rebinding() -> Result<(), StoreError> {
        let ns = NamespaceRef::deterministic("replayed-aliases");
        let target = Kappa::sha256(b"aliased content");
        let alias = Kappa::compute(kappa_types::Axis::Sha512, b"aliased content")?;
        let binding = kappa_types::content::ContentAlias::new(alias.clone(), target.clone(), 15)?;
        let bytes = kappa_types::canonical::canonical_bytes(&binding);
        let publication = mutation(MutationOp::ContentAlias, None, &bytes);
        let mut state = NamespaceState::default();
        state.apply_record(&ns, &publication, &bytes)?;
        assert_eq!(state.aliases.get(&alias), Some(&(target, 15)));
        // The same binding published again (shared content installed by a
        // later publication) is accepted and changes nothing.
        let before = state.clone();
        state.apply_record(&ns, &publication, &bytes)?;
        assert_eq!(state, before);
        // The alias bound to another target is evidence of inconsistency.
        let other =
            kappa_types::content::ContentAlias::new(alias, Kappa::sha256(b"other content"), 15)?;
        let other_bytes = kappa_types::canonical::canonical_bytes(&other);
        let rebinding = mutation(MutationOp::ContentAlias, None, &other_bytes);
        assert!(state.apply_record(&ns, &rebinding, &other_bytes).is_err());
        let with_context = mutation(MutationOp::ContentAlias, Some("x"), &bytes);
        assert!(state.apply_record(&ns, &with_context, &bytes).is_err());
        // Alias evidence is not commitment evidence: it never decodes as one.
        let as_commitment = mutation(MutationOp::ContentPublish, None, &bytes);
        assert!(state.apply_record(&ns, &as_commitment, &bytes).is_err());
        assert_eq!(state, before);
        Ok(())
    }

    #[test]
    fn content_compositions_accumulate_and_reject_context() -> Result<(), StoreError> {
        use kappa_types::content::{ContentComponent, ContentComposition};
        let ns = NamespaceRef::deterministic("replayed-compositions");
        let whole = Kappa::sha256(b"hello world");
        let part = |bytes: &[u8]| ContentComponent {
            identity: Kappa::sha256(bytes),
            length: bytes.len() as u64,
        };
        let two =
            ContentComposition::new(whole.clone(), vec![part(b"hello "), part(b"world")], 11)?;
        let bytes = kappa_types::canonical::canonical_bytes(&two);
        let publication = mutation(MutationOp::ContentCompose, None, &bytes);
        let mut state = NamespaceState::default();
        state.apply_record(&ns, &publication, &bytes)?;
        let expected = vec![(Kappa::sha256(b"hello "), 6), (Kappa::sha256(b"world"), 5)];
        assert_eq!(
            state.compositions.get(&whole),
            Some(&BTreeSet::from([expected]))
        );
        // The same composition installed again changes nothing.
        let before = state.clone();
        state.apply_record(&ns, &publication, &bytes)?;
        assert_eq!(state, before);
        // Another chunking of the same bytes is also true of them.
        let three = ContentComposition::new(
            whole.clone(),
            vec![part(b"hel"), part(b"lo "), part(b"world")],
            11,
        )?;
        let three_bytes = kappa_types::canonical::canonical_bytes(&three);
        state.apply_record(
            &ns,
            &mutation(MutationOp::ContentCompose, None, &three_bytes),
            &three_bytes,
        )?;
        assert_eq!(state.compositions.get(&whole).map(BTreeSet::len), Some(2));
        let accumulated = state.clone();
        let with_context = mutation(MutationOp::ContentCompose, Some("x"), &bytes);
        assert!(state.apply_record(&ns, &with_context, &bytes).is_err());
        // Composition evidence is neither commitment nor alias evidence.
        for op in [MutationOp::ContentPublish, MutationOp::ContentAlias] {
            assert!(
                state
                    .apply_record(&ns, &mutation(op, None, &bytes), &bytes)
                    .is_err()
            );
        }
        assert_eq!(state, accumulated);
        Ok(())
    }

    #[test]
    fn sequence_evidence_rejects_gaps_and_cross_namespace_records() -> Result<(), StoreError> {
        let ns = NamespaceRef::deterministic("replayed-sequences");
        let mut state = NamespaceState::default();
        for (namespace_id, value, accepted) in [
            (ns.id().to_vec(), 1, true),
            (ns.id().to_vec(), 3, false),
            (NamespaceRef::deterministic("other").id().to_vec(), 2, false),
            (ns.id().to_vec(), 2, true),
        ] {
            let bytes =
                kappa_types::canonical::canonical_bytes(&kappa_types::epoch::SequenceRecord {
                    namespace_id,
                    name: "revision".into(),
                    value,
                });
            let mutation = mutation(MutationOp::SequenceUpdate, Some("revision"), &bytes);
            let before = state.clone();
            let result = state.apply_record(&ns, &mutation, &bytes);
            if accepted {
                result?;
                assert_eq!(state.sequences.get("revision"), Some(&value));
            } else {
                assert!(result.is_err());
                assert_eq!(state, before);
            }
        }
        Ok(())
    }

    #[test]
    fn metadata_evidence_sets_deletes_and_rejects_foreign_records() -> Result<(), StoreError> {
        let ns = NamespaceRef::deterministic("replayed-metadata");
        let record = |namespace: &NamespaceRef, value: Option<&[u8]>| {
            kappa_types::canonical::canonical_bytes(&kappa_types::epoch::MetadataRecord {
                namespace_id: namespace.id().to_vec(),
                key: "versioning".into(),
                value: value.map(<[u8]>::to_vec),
            })
        };
        let mut state = NamespaceState::default();
        let set = record(&ns, Some(b"enabled"));
        state.apply_record(
            &ns,
            &mutation(MutationOp::MetadataUpdate, Some("versioning"), &set),
            &set,
        )?;
        assert_eq!(
            state.metadata.get("versioning").map(Vec::as_slice),
            Some(&b"enabled"[..])
        );

        let before = state.clone();
        let foreign = record(&NamespaceRef::deterministic("other"), None);
        let wrong_key = mutation(MutationOp::MetadataUpdate, Some("other-key"), &set);
        assert!(
            state
                .apply_record(
                    &ns,
                    &mutation(MutationOp::MetadataUpdate, Some("versioning"), &foreign),
                    &foreign,
                )
                .is_err()
        );
        assert!(state.apply_record(&ns, &wrong_key, &set).is_err());
        assert_eq!(state, before);

        let delete = record(&ns, None);
        state.apply_record(
            &ns,
            &mutation(MutationOp::MetadataUpdate, Some("versioning"), &delete),
            &delete,
        )?;
        assert!(state.metadata.is_empty());
        Ok(())
    }

    #[test]
    fn missing_tag_identity_does_not_invent_a_key() {
        for name in [None, Some("")] {
            let mut state = NamespaceState::default();
            assert!(
                state
                    .apply(&mutation(MutationOp::TagSet, name, b"value"))
                    .is_err()
            );
            assert!(state.tags.is_empty());
        }
    }

    #[test]
    fn deletion_cannot_remove_a_different_content_identity() -> Result<(), StoreError> {
        let mut state = NamespaceState::default();
        state.apply(&mutation(MutationOp::TagSet, Some("head"), b"current"))?;
        let before = state.clone();
        assert!(
            state
                .apply(&mutation(MutationOp::TagDelete, Some("head"), b"old"))
                .is_err()
        );
        assert_eq!(state, before);
        state.apply(&mutation(MutationOp::TagDelete, Some("head"), b"current"))?;
        assert!(state.tags.is_empty());
        Ok(())
    }
}
