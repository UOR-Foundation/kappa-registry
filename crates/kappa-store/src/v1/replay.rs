//! Replay of a namespace's signed history into its reconstructed state.
//!
//! Every ledger mutation names its canonical transition evidence; replay
//! fetches that evidence from the namespace, verifies its identity and
//! interprets it through the shared transition boundary
//! (`PreparedTransition::decode`), so the operation, scope and index effect
//! a writer derived are the ones replay derives. Each interpreted
//! transition is then applied to the reconstructed state with its own
//! correspondence checks: a removal names what is held, a retirement the
//! exact admission it removes, a sequence advances by one.
//!
//! Each epoch is checked against everything it signs: its chain position,
//! its ledger and mutation root, the tag-state digest, and the namespace
//! state it commits: the authority record (of the instance replay began
//! with), the current-state index root rebuilt from the replayed index
//! effects and that authority record, and the history log extended by
//! exactly its ledger.

use std::collections::{BTreeMap, BTreeSet};

use kappa_types::canonical::{canonical_bytes, from_canonical};
use kappa_types::content::{ContentAdmissionEvidence, ContentAdmissionRecord, MetadataSubject};
use kappa_types::epoch::EpochMutation;
use kappa_types::epoch_root::mutations_merkle_root;
use kappa_types::error::StoreError;
use kappa_types::kappa::Kappa;
use kappa_types::merkle::StreamingTree;
use kappa_types::namespace::{LogicalIncarnation, NamespaceRef};
use kappa_types::state_index::{self, Change, Node, NodeSource, Path, Value};
use kappa_types::tag::TagEntry;
use kappa_types::verified::VerifiedContent;
use kappa_types::work::WorkMeter;
use kappa_types::{AuthorityState, EpochRoot, NamespaceState, state_key};

use crate::identity_ops::AnchorKeyResolver;
use crate::namespace_commitment::seal_index;
use crate::traits::blob::BlobStore;
use crate::traits::epoch::EpochStore;
use crate::transition::{PreparedTransition, RecordTransition, TransitionDomain};

/// Reconstructed namespace state from epoch chain replay.
///
/// The verifier's model, derived by applying committed transitions; not
/// the signed commitment record an epoch names (`NamespaceState`), which
/// replay checks it against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayedNamespaceState {
    /// Tag name to the identity it targets: what the tag-state digest
    /// commits.
    pub tags: BTreeMap<String, Kappa>,
    /// Tag name to its complete current entry.
    pub tag_entries: BTreeMap<String, TagEntry>,
    /// Evidence identity of the current namespace record.
    pub namespace_record: Option<Kappa>,
    pub sequences: BTreeMap<String, u64>,
    /// Namespace metadata.
    pub metadata: BTreeMap<String, Vec<u8>>,
    /// Blob metadata by content identity and key.
    pub blob_metadata: BTreeMap<(Kappa, String), Vec<u8>>,
    /// Identities of the edges the namespace currently holds.
    pub edges: BTreeSet<Kappa>,
    /// Operation identity to its receipt's identity.
    pub operations: BTreeMap<[u8; 32], Kappa>,
    /// Content identity to its current logical admission.
    pub admissions: BTreeMap<Kappa, ContentAdmissionRecord>,
    /// Every component list recorded for a composite identity: two
    /// chunkings of the same bytes are both true of them.
    pub compositions: BTreeMap<Kappa, BTreeSet<Vec<(Kappa, u64)>>>,
    pub assertions: BTreeSet<Kappa>,
    pub revocations: BTreeSet<Kappa>,
    pub watermarks: BTreeSet<Kappa>,
    /// Old anchor to the evidence of its succession.
    pub successions: BTreeMap<Kappa, Kappa>,
    /// Authorization scope (index path) to its latest governed transition.
    pub authorization: BTreeMap<Path, Kappa>,
    /// Identity member (index path) to the evidence of its current record.
    pub members: BTreeMap<Path, Kappa>,
    /// The authority record the last replayed epoch commits.
    pub authority: Option<AuthorityState>,
    /// The namespace-state record the last replayed epoch commits.
    pub committed: Option<NamespaceState>,
    /// The history log of every replayed mutation.
    pub history: StreamingTree,
    /// The current-state index entries the replayed transitions derive,
    /// with the committed authority entry.
    pub index: BTreeMap<Path, Value>,
}

fn rejected(message: impl Into<String>) -> StoreError {
    StoreError::Rejected(message.into())
}

impl ReplayedNamespaceState {
    /// Interpret `mutation` against the `evidence` bytes it names, in the
    /// namespace instance `domain`, and apply it. Returns the index effect
    /// the transition derives. A refusal changes nothing.
    pub fn apply(
        &mut self,
        domain: TransitionDomain,
        mutation: &EpochMutation,
        evidence: &[u8],
    ) -> Result<Change, StoreError> {
        let evidence = VerifiedContent::verify(&mutation.kappa, evidence)?;
        let transition = PreparedTransition::decode(domain, mutation, evidence)?;
        let change = transition.index_change();
        self.apply_record(transition.record(), &mutation.kappa, change)?;
        match change.1 {
            Some(value) => self.index.insert(change.0, value),
            None => self.index.remove(&change.0),
        };
        Ok(change)
    }

    /// The state change of one interpreted transition, whose evidence is
    /// `id`, checked before anything changes.
    fn apply_record(
        &mut self,
        record: &RecordTransition,
        id: &Kappa,
        change: Change,
    ) -> Result<(), StoreError> {
        match record {
            RecordTransition::TagSet(entry) => {
                self.tags.insert(entry.name.clone(), entry.kappa.clone());
                self.tag_entries.insert(entry.name.clone(), entry.clone());
            }
            RecordTransition::TagDelete(entry) => {
                if self.tag_entries.get(&entry.name) != Some(entry) {
                    return Err(rejected(format!(
                        "tag {} removal names an entry the namespace does not hold",
                        entry.name
                    )));
                }
                self.tags.remove(&entry.name);
                self.tag_entries.remove(&entry.name);
            }
            RecordTransition::EdgePut(_) => {
                if !self.edges.insert(id.clone()) {
                    return Err(rejected("duplicate edge publication"));
                }
            }
            RecordTransition::EdgeDelete(_) => {
                if !self.edges.remove(id) {
                    return Err(rejected("edge deletion lacks preceding publication"));
                }
            }
            RecordTransition::Assertion(_) => {
                self.assertions.insert(id.clone());
            }
            RecordTransition::Revocation(_) => {
                self.revocations.insert(id.clone());
            }
            RecordTransition::Watermark(_) => {
                self.watermarks.insert(id.clone());
            }
            RecordTransition::Succession(succession) => {
                self.successions
                    .insert(succession.old_anchor.clone(), id.clone());
            }
            RecordTransition::Session(_)
            | RecordTransition::Credential(_)
            | RecordTransition::Trust(_) => {
                self.authorization.insert(change.0, id.clone());
            }
            RecordTransition::Member(_) => match change.1 {
                Some(_) => {
                    self.members.insert(change.0, id.clone());
                }
                None => {
                    if self.members.remove(&change.0).is_none() {
                        return Err(rejected("member removal names no current member"));
                    }
                }
            },
            RecordTransition::Metadata(meta) => self.apply_metadata(meta)?,
            RecordTransition::Sequence(sequence) => {
                let previous = self.sequences.get(&sequence.name).copied().unwrap_or(0);
                if sequence.name.is_empty() || previous.checked_add(1) != Some(sequence.value) {
                    return Err(rejected("invalid sequence mutation evidence"));
                }
                self.sequences.insert(sequence.name.clone(), sequence.value);
            }
            RecordTransition::NamespaceUpdate(_) => {
                self.namespace_record = Some(id.clone());
            }
            RecordTransition::ContentPublish(admission)
            | RecordTransition::ContentAlias(admission)
            | RecordTransition::ContentCompose(admission)
            | RecordTransition::RecordPublish(admission) => self.admit(admission)?,
            RecordTransition::ContentRetire(retirement) => {
                self.retire(retirement.removed())?;
            }
            RecordTransition::OperationPublish(receipt) => {
                let operation = receipt.operation_id()?;
                if self.operations.contains_key(operation) {
                    return Err(rejected("operation published more than once"));
                }
                self.operations.insert(*operation, id.clone());
            }
        }
        Ok(())
    }

    fn apply_metadata(
        &mut self,
        meta: &kappa_types::content::MetadataTransition,
    ) -> Result<(), StoreError> {
        match (meta.subject(), meta.value()) {
            (MetadataSubject::Namespace, Some(value)) => {
                self.metadata.insert(meta.key().to_owned(), value.to_vec());
            }
            (MetadataSubject::Namespace, None) => {
                if self.metadata.remove(meta.key()).is_none() {
                    return Err(rejected("metadata deletion names no current key"));
                }
            }
            (MetadataSubject::Blob(identity), Some(value)) => {
                self.blob_metadata
                    .insert((identity.clone(), meta.key().to_owned()), value.to_vec());
            }
            (MetadataSubject::Blob(identity), None) => {
                if self
                    .blob_metadata
                    .remove(&(identity.clone(), meta.key().to_owned()))
                    .is_none()
                {
                    return Err(rejected("blob metadata deletion names no current key"));
                }
            }
        }
        Ok(())
    }

    /// Admit one logical admission: an identity is admitted at most once
    /// until retired; an alias needs its target admitted, a composition
    /// each of its components.
    fn admit(&mut self, record: &ContentAdmissionRecord) -> Result<(), StoreError> {
        let identity = record.admission().identity();
        if self.admissions.contains_key(identity) {
            return Err(rejected(format!("content {identity} admitted twice")));
        }
        match record.evidence() {
            ContentAdmissionEvidence::Alias(alias) => {
                if !self.admissions.contains_key(alias.target()) {
                    return Err(rejected(format!(
                        "alias {identity} names {}, which the namespace does not admit",
                        alias.target()
                    )));
                }
            }
            ContentAdmissionEvidence::Composition(composition) => {
                if let Some(missing) = composition
                    .components()
                    .iter()
                    .find(|component| !self.admissions.contains_key(&component.identity))
                {
                    return Err(rejected(format!(
                        "composite {identity} names {}, which the namespace does not admit",
                        missing.identity
                    )));
                }
                self.compositions
                    .entry(identity.clone())
                    .or_default()
                    .insert(
                        composition
                            .components()
                            .iter()
                            .map(|component| (component.identity.clone(), component.length))
                            .collect(),
                    );
            }
            ContentAdmissionEvidence::VerifiedBytes | ContentAdmissionEvidence::Chunked(_) => {}
        }
        self.admissions.insert(identity.clone(), record.clone());
        Ok(())
    }

    /// Retire exactly the admission `removed`: it must be the one held, no
    /// remaining alias or composite may select it, and its blob metadata
    /// must already have been removed by its own transitions.
    fn retire(
        &mut self,
        removed: &kappa_types::content::ContentAdmission,
    ) -> Result<(), StoreError> {
        let identity = removed.identity();
        match self.admissions.get(identity) {
            Some(held) if held.admission() == removed => {}
            Some(_) => {
                return Err(rejected(format!(
                    "retirement of {identity} names another admission than the one held"
                )));
            }
            None => {
                return Err(rejected(format!(
                    "content {identity} retired without a preceding admission"
                )));
            }
        }
        let selected =
            self.admissions
                .values()
                .any(|other| match other.evidence() {
                    ContentAdmissionEvidence::Alias(alias) => alias.target() == identity,
                    ContentAdmissionEvidence::Composition(composition) => composition
                        .components()
                        .iter()
                        .any(|component| component.identity == *identity),
                    ContentAdmissionEvidence::VerifiedBytes
                    | ContentAdmissionEvidence::Chunked(_) => false,
                });
        if selected {
            return Err(rejected(format!(
                "content {identity} retired while another admission selects it"
            )));
        }
        if self
            .blob_metadata
            .range((identity.clone(), String::new())..)
            .next()
            .is_some_and(|((owner, _), _)| owner == identity)
        {
            return Err(rejected(format!(
                "content {identity} retired with its blob metadata still held"
            )));
        }
        self.admissions.remove(identity);
        Ok(())
    }
}

/// Replay the epoch chain, reconstructing namespace state.
///
/// Walks numbered history from genesis to the captured head and reconstructs state through
/// `target_epoch`. Epoch zero denotes the empty state before genesis.
/// Verifies content identities, ledger commitments, chain continuity, mutation
/// roots, the tag-state digest and the namespace-state commitment of every
/// replayed epoch. This structural verification does not establish signer
/// authority; authenticated admission is separate.
pub fn replay_to<S>(
    store: &S,
    ns: &NamespaceRef,
    target_epoch: u64,
) -> Result<ReplayedNamespaceState, StoreError>
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
) -> Result<ReplayedNamespaceState, StoreError>
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

/// The index nodes replay rebuilds, read back through `NodeSource`.
#[derive(Default)]
struct ReplayNodes(BTreeMap<[u8; 32], Node>);

impl NodeSource for ReplayNodes {
    fn node(&self, hash: &[u8; 32]) -> Result<Node, StoreError> {
        self.0
            .get(hash)
            .copied()
            .ok_or_else(|| StoreError::Internal("replayed index node missing".into()))
    }
}

/// The namespace state `root` commits and the authority record it names,
/// each verified against its identity and against the other.
fn committed_state<S>(
    store: &S,
    ns: &NamespaceRef,
    root: &EpochRoot,
) -> Result<(NamespaceState, AuthorityState), StoreError>
where
    S: BlobStore + ?Sized,
{
    let state_bytes = store.blob_get_in(ns, root.state())?;
    VerifiedContent::verify(root.state(), &state_bytes)?;
    let state: NamespaceState = from_canonical(&state_bytes)?;
    if state.namespace() != ns.id() {
        return Err(rejected("epoch commits another namespace's state"));
    }
    let authority_bytes = store.blob_get_in(ns, state.authority())?;
    VerifiedContent::verify(state.authority(), &authority_bytes)?;
    let authority: AuthorityState = from_canonical(&authority_bytes)?;
    if !state.names(&authority) {
        return Err(rejected(
            "committed state does not name its authority record",
        ));
    }
    Ok((state, authority))
}

/// The ledger `root` signs, read from the namespace (current with its
/// commit, never through a projection), verified against the root's ledger
/// identity and decoded, with its Merkle root checked against the root's
/// mutation commitment.
fn signed_ledger<S>(
    store: &S,
    ns: &NamespaceRef,
    root: &EpochRoot,
) -> Result<Vec<EpochMutation>, StoreError>
where
    S: BlobStore + ?Sized,
{
    let mutation_blob = store.blob_get_in(ns, root.ledger_root())?;
    VerifiedContent::verify(root.ledger_root(), &mutation_blob)?;
    let mutations: Vec<EpochMutation> = from_canonical(&mutation_blob).map_err(|e| {
        StoreError::Internal(format!(
            "epoch {} mutation blob decode: {e}",
            root.epoch_number(),
        ))
    })?;
    if mutations_merkle_root(&mutations) != root.mutations_root() {
        return Err(rejected(format!(
            "epoch {} mutations_root mismatch",
            root.epoch_number(),
        )));
    }
    Ok(mutations)
}

/// The state replay rebuilds across epochs: the reconstructed namespace,
/// the index nodes and root its transitions derive, and the instance the
/// genesis epoch commits.
#[derive(Default)]
struct Rebuild {
    state: ReplayedNamespaceState,
    nodes: ReplayNodes,
    index_root: [u8; 32],
    domain: Option<TransitionDomain>,
}

impl Rebuild {
    fn new() -> Self {
        Self {
            index_root: state_index::EMPTY,
            ..Self::default()
        }
    }

    /// Apply the admitted epoch `root` with its verified `mutations` and
    /// check everything it commits: its instance, the index root its
    /// transitions and authority record derive, the history its ledger
    /// extends, and the tag-state digest and count.
    fn apply_epoch<S>(
        &mut self,
        store: &S,
        ns: &NamespaceRef,
        root: &EpochRoot,
        mutations: &[EpochMutation],
    ) -> Result<(), StoreError>
    where
        S: BlobStore + ?Sized,
    {
        // The instance genesis commits governs every later epoch.
        let (committed, authority) = committed_state(store, ns, root)?;
        let instance = TransitionDomain::new(
            *ns.id(),
            LogicalIncarnation::from_bytes(*committed.incarnation()),
        );
        if *self.domain.get_or_insert(instance) != instance {
            return Err(rejected("epoch commits another namespace incarnation"));
        }
        let state = &mut self.state;
        let mut changes = Vec::with_capacity(mutations.len() + 1);
        for mutation in mutations {
            let bytes = store.blob_get_in(ns, &mutation.kappa)?;
            changes.push(state.apply(instance, mutation, &bytes)?);
            // The push cannot fail, so the history taken here is always
            // restored below.
            let appended = std::mem::take(&mut state.history)
                .push(&canonical_bytes(mutation), |_, _| {
                    Ok::<_, std::convert::Infallible>(())
                });
            state.history = match appended {
                Ok(history) => history,
                Err(never) => match never {},
            };
        }
        let authority_entry = state_key::authority_entry(&canonical_bytes(&authority));
        state.index.insert(authority_entry.0, authority_entry.1);
        let update = seal_index(
            &self.nodes,
            self.index_root,
            changes,
            &authority,
            &mut WorkMeter::unbounded(),
        )?;
        for node in update.created {
            self.nodes.0.insert(node.hash(), node);
        }
        self.index_root = update.root;

        if self.index_root != *committed.index_root() {
            return Err(rejected(format!(
                "epoch {} commits an index root its transitions do not derive",
                root.epoch_number()
            )));
        }
        if state.history.leaves() != committed.history_size()
            || state.history.root() != *committed.history_root()
        {
            return Err(rejected(format!(
                "epoch {} commits a history its ledgers do not extend",
                root.epoch_number()
            )));
        }
        let mut digest = kappa_types::StateDigest::default();
        for (name, identity) in &state.tags {
            digest.insert(name, identity);
        }
        if digest.into_bytes().as_slice() != root.state_digest()
            || state.tags.len() as u64 != root.tag_count()
        {
            return Err(rejected("reconstructed epoch state commitment mismatch"));
        }
        state.authority = Some(authority);
        state.committed = Some(committed);
        Ok(())
    }
}

fn replay_with_admission<S>(
    store: &S,
    ns: &NamespaceRef,
    target_epoch: u64,
    mut admit: impl FnMut(&EpochRoot) -> Result<(), StoreError>,
) -> Result<ReplayedNamespaceState, StoreError>
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
        return Ok(ReplayedNamespaceState::default());
    }

    // Admit one ledger at a time. Historical mutation populations must not
    // accumulate in memory alongside the reconstructed state.
    let mut rebuild = Rebuild::new();
    let mut predecessor = None;
    let mut predecessor_timestamp = None;
    for expected_number in 1..=current_num {
        let walk_kappa = store.epoch_get_by_number(ns, expected_number)?;
        let root = store.epoch_get(&walk_kappa)?;
        if root.epoch_number() != expected_number || root.prev_identifier() != predecessor.as_ref()
        {
            return Err(rejected("discontinuous replay epoch chain"));
        }
        if predecessor_timestamp.is_some_and(|timestamp| root.timestamp_ms() < timestamp) {
            return Err(rejected("replay epoch timestamp regressed"));
        }
        predecessor_timestamp = Some(root.timestamp_ms());

        // Adjacency is not evidence of ledger identity. The epoch's signed
        // commitment names the exact bytes to retrieve and verify.
        if root.namespace_id() != ns.id() || root.kappa() != &walk_kappa {
            return Err(rejected("replay epoch identity mismatch"));
        }
        if expected_number == current_num && walk_kappa != current_kappa {
            return Err(rejected("replay history differs from captured head"));
        }
        let mutations = signed_ledger(store, ns, &root)?;

        admit(&root)?;
        predecessor = Some(walk_kappa);
        if root.epoch_number() > target_epoch {
            continue;
        }
        rebuild.apply_epoch(store, ns, &root, &mutations)?;
    }

    Ok(rebuild.state)
}

#[cfg(test)]
#[path = "replay_tests.rs"]
mod tests;
