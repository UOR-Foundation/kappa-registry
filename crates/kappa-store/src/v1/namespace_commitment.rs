//! The namespace-state commitment of one epoch, prepared once for both
//! backends (`kappa_types::namespace_state`).
//!
//! A backend supplies, from the same sealed candidate state as the ledger:
//! the authority record, the current-state index root with read access to
//! its nodes, the predecessor's committed state record, and the history
//! log builder it retained. [`commit`] enforces every correspondence the
//! signed commitment asserts:
//!
//! - the authority record is of this namespace, and of the predecessor's
//!   instance: genesis fixes the incarnation, successors preserve it;
//! - the index holds the authority record under its canonical path with
//!   the same identity, so the direct reference and the index cannot
//!   disagree;
//! - the history builder is the predecessor's committed log (genesis: the
//!   empty log), and the new log is that log extended by exactly this
//!   epoch's ledger, in order.
//!
//! It returns the records to publish with the epoch and the history nodes
//! the append emitted, for the backend to keep for audit proofs.

use kappa_types::canonical::canonical_bytes;
use kappa_types::epoch::EpochMutation;
use kappa_types::merkle::{NODE_HASH_INPUT, StreamingTree, node_count};
use kappa_types::state_index::{self, NodeSource};
use kappa_types::state_key;
use kappa_types::work::{Dimension, WorkMeter};
use kappa_types::{
    AuthorityState, Axis, EpochRoot, NamespaceRef, NamespaceState, StoreError, VerifiedContent,
};

/// What the backend supplies for one epoch's state commitment.
#[derive(Clone, Copy)]
pub struct StateInput<'a> {
    /// Who controls the namespace instance after this epoch's mutations.
    pub authority: &'a AuthorityState,
    /// The current-state index root after this epoch's mutations.
    pub index_root: [u8; 32],
    /// The nodes of the tree at `index_root`.
    pub index: &'a dyn NodeSource,
    /// The predecessor's committed state record; `None` at genesis.
    pub predecessor: Option<&'a NamespaceState>,
    /// The history log builder as of the predecessor (empty at genesis).
    pub history: &'a StreamingTree,
}

/// One history log node an append emitted: its position and hash.
pub type HistoryNode = (u64, [u8; 32]);

/// One epoch's committed state, ready to publish.
pub struct CommittedState {
    state: NamespaceState,
    state_record: VerifiedContent,
    authority_record: VerifiedContent,
    history: StreamingTree,
    history_nodes: Vec<HistoryNode>,
}

impl CommittedState {
    pub const fn state(&self) -> &NamespaceState {
        &self.state
    }
    /// The canonical state record the epoch root names.
    pub const fn state_record(&self) -> &VerifiedContent {
        &self.state_record
    }
    /// The canonical authority record the state names.
    pub const fn authority_record(&self) -> &VerifiedContent {
        &self.authority_record
    }
    /// The history builder after this epoch: what the next epoch extends.
    pub const fn history(&self) -> &StreamingTree {
        &self.history
    }
    /// The history log nodes this epoch's append emitted, by position.
    pub fn history_nodes(&self) -> &[HistoryNode] {
        &self.history_nodes
    }
}

fn refused(what: &str) -> StoreError {
    StoreError::Internal(format!("namespace state commitment: {what}"))
}

/// Bytes one emitted history node occupies: its position and hash.
pub const HISTORY_NODE_BYTES: u64 = 40;

/// The predecessor correspondence `commit` requires: genesis extends the
/// empty log; a successor's predecessor state is the one its epoch signs,
/// of the same namespace and incarnation, and the history builder is that
/// state's committed log.
fn check_continuity(
    input: &StateInput<'_>,
    namespace: &NamespaceRef,
    predecessor: Option<&EpochRoot>,
) -> Result<(), StoreError> {
    match (predecessor, input.predecessor) {
        (None, None) if input.history.leaves() == 0 => Ok(()),
        (None, None) => Err(refused("a genesis epoch extends a non-empty history")),
        (Some(root), Some(previous)) => {
            if previous.identity() != *root.state() {
                return Err(refused(
                    "the predecessor state is not the one its epoch commits",
                ));
            }
            if previous.namespace() != namespace.id() {
                return Err(refused("the predecessor state is another namespace's"));
            }
            if previous.incarnation() != input.authority.incarnation() {
                return Err(refused(
                    "the authority record is of another incarnation than its predecessor",
                ));
            }
            if input.history.leaves() != previous.history_size()
                || input.history.root() != *previous.history_root()
            {
                return Err(refused(
                    "the history builder is not the predecessor's committed log",
                ));
            }
            Ok(())
        }
        _ => Err(refused(
            "the predecessor state does not correspond to the predecessor epoch",
        )),
    }
}

/// `history` extended by `mutations`, with the nodes the append emits.
/// The emitted nodes are known exactly from the counts and are charged,
/// with their hashing, before any is computed; each mutation's encoding is
/// charged before the next is produced.
fn append_history(
    history: &StreamingTree,
    mutations: &[EpochMutation],
    meter: &mut WorkMeter,
) -> Result<(StreamingTree, Vec<HistoryNode>), StoreError> {
    let appended_leaves = u64::try_from(mutations.len())
        .map_err(|_| StoreError::CapacityExceeded("ledger length exceeds u64".into()))?;
    let final_leaves = history
        .leaves()
        .checked_add(appended_leaves)
        .ok_or_else(|| StoreError::CapacityExceeded("history log length exhausted".into()))?;
    let emitted = node_count(final_leaves) - node_count(history.leaves());
    let emitted_bytes = emitted
        .checked_mul(HISTORY_NODE_BYTES)
        .ok_or_else(|| StoreError::CapacityExceeded("history nodes exceed u64".into()))?;
    let emitted_hashed = emitted
        .checked_mul(NODE_HASH_INPUT)
        .ok_or_else(|| StoreError::CapacityExceeded("history hashing exceeds u64".into()))?;
    meter.charge_all(&[
        (Dimension::BytesAllocated, emitted_bytes),
        (Dimension::BytesHashed, emitted_hashed),
    ])?;
    let capacity = usize::try_from(emitted).map_err(|_| {
        StoreError::CapacityExceeded("history nodes exceed the address space".into())
    })?;
    let mut nodes = Vec::with_capacity(capacity);
    let mut history = history.clone();
    for mutation in mutations {
        let leaf = canonical_bytes(mutation);
        meter.charge_all(&[
            (Dimension::BytesAllocated, leaf.len() as u64),
            (Dimension::BytesHashed, leaf.len() as u64),
        ])?;
        let appended = history.push(&leaf, |position, node| {
            nodes.push((position, *node));
            Ok::<_, std::convert::Infallible>(())
        });
        history = match appended {
            Ok(history) => history,
            Err(never) => match never {},
        };
    }
    Ok((history, nodes))
}

/// The most bytes `state`'s canonical record encodes to: its fixed fields
/// and framing, the owner's text, and the name and protocol.
pub fn authority_record_bound(state: &AuthorityState) -> u64 {
    const FRAMING: u64 = 96;
    const KAPPA_TEXT: u64 = 140;
    FRAMING
        + KAPPA_TEXT
        + state.name().len() as u64
        + state
            .protocol()
            .map_or(0, |protocol| protocol.as_str().len() as u64)
}

/// The current-state index one epoch commits: the index effects of its
/// transitions, `changes` in execution order, followed by the entry of its
/// final `authority` record (last, so no earlier effect replaces it),
/// reduced to the final effect per path and applied to the tree at `root`,
/// whose nodes `source` reads. The authority record's encoding is admitted
/// at its bound before it is produced and consumed as measured. Every
/// backend's seal and replay derive the root through this one rule.
pub fn seal_index(
    source: &dyn NodeSource,
    root: [u8; 32],
    mut changes: Vec<state_index::Change>,
    authority: &AuthorityState,
    meter: &mut WorkMeter,
) -> Result<state_index::Update, StoreError> {
    let bound = authority_record_bound(authority);
    meter.admits(&[
        (Dimension::BytesAllocated, bound),
        (Dimension::BytesHashed, bound),
    ])?;
    let authority_bytes = canonical_bytes(authority);
    let encoded = authority_bytes.len() as u64;
    meter.consume(Dimension::BytesAllocated, encoded)?;
    meter.consume(Dimension::BytesHashed, encoded)?;
    let (path, value) = state_key::authority_entry(&authority_bytes);
    meter.charge(
        Dimension::BytesAllocated,
        size_of::<state_index::Change>() as u64,
    )?;
    changes.push((path, Some(value)));
    state_index::apply(source, root, &state_index::final_changes(changes), meter)
}

/// Prepare the state commitment of one epoch (see the module
/// documentation).
///
/// The epoch is of `namespace`, follows `predecessor` and seals
/// `mutations`; every byte encoded, hashed and allocated is charged to
/// `meter` before it is produced.
pub fn commit(
    input: StateInput<'_>,
    namespace: &NamespaceRef,
    predecessor: Option<&EpochRoot>,
    mutations: &[EpochMutation],
    meter: &mut WorkMeter,
) -> Result<CommittedState, StoreError> {
    let authority = input.authority;
    if authority.namespace() != namespace.id() {
        return Err(refused("the authority record is another namespace's"));
    }
    check_continuity(&input, namespace, predecessor)?;
    let authority_bytes = canonical_bytes(authority);
    meter.charge_all(&[
        (Dimension::BytesAllocated, authority_bytes.len() as u64),
        (Dimension::BytesHashed, 2 * authority_bytes.len() as u64),
    ])?;
    let (indexed, _) = state_index::lookup(
        input.index,
        input.index_root,
        &state_key::authority_path(),
        meter,
    )?;
    if indexed != Some(state_key::value(&authority_bytes)) {
        return Err(refused(
            "the current-state index does not hold the authority record",
        ));
    }
    let (history, history_nodes) = append_history(input.history, mutations, meter)?;
    let state = NamespaceState::new(
        authority,
        input.index_root,
        history.root(),
        history.leaves(),
    );
    let state_bytes = canonical_bytes(&state);
    meter.charge_all(&[
        (Dimension::BytesAllocated, state_bytes.len() as u64),
        (Dimension::BytesHashed, 2 * state_bytes.len() as u64),
    ])?;
    let state_record = VerifiedContent::compute(Axis::Sha256, &state_bytes)?;
    let authority_record = VerifiedContent::compute(Axis::Sha256, &authority_bytes)?;
    if state_record.kappa() != &state.identity() || authority_record.kappa() != state.authority() {
        return Err(refused("record identities disagree with the state"));
    }
    Ok(CommittedState {
        state,
        state_record,
        authority_record,
        history,
        history_nodes,
    })
}
